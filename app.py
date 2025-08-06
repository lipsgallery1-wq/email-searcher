from flask import Flask, render_template, request, jsonify
import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import threading
import signal
import os

app = Flask(__name__)

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# TIMEOUT MANAGEMENT pour Render - ULTRA AGRESSIF pour éviter worker timeout
SEARCH_TIMEOUT = 12  # 12 secondes MAXIMUM pour éviter le timeout Render de 26s
search_start_time = None

# Configuration des extensions ignorées (remplace config.py)
IGNORED_EXTENSIONS = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.zip', '.rar', '.tar', '.gz', '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.css', '.js', '.ico', '.xml', '.rss']

class TimeoutError(Exception):
    pass

class EmailSearcher:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        
    def extract_emails_from_text(self, text):
        """Extraire tous les emails d'un texte avec recherche améliorée par domaines"""
        emails = set()
        
        # Décoder les emails encodés
        text = self.decode_encoded_emails(text)
        
        # Pattern principal pour les emails
        matches = self.email_pattern.findall(text)
        for match in matches:
            # Nettoyer l'email (enlever les caractères de ponctuation en fin)
            email = match.strip('.,;:!?()[]{}"\' \t\n\r')
            if self.is_valid_email(email):
                emails.add(email.lower())
        
        # NOUVEAU: Recherche spécifique par domaines courants identifiés
        # Domaines extraits de la liste fournie par l'utilisateur
        common_domains = [
            '@hotmail.com', '@hotmail.fr', '@orange.fr', '@gmail.com', '@gmail.fr',
            '@wanadoo.fr', '@outlook.fr', '@aol.com', '@yahoo.fr', '@neuf.fr', 
            '@free.fr', '@sfr.fr', '@laposte.net', '@reworldmedia.com',
            '@bluewin.ch', '@acs.ch', '@porsche-montpellier.fr', '@porsche-avignon.fr',
            '@porsche-sierre.ch', '@mclaren.com', '@alpinecars.com', '@williamsf1.com',
            '@libertymedia.com', '@curbstone.net', '@proton.me', '@verbaereauto.com'
        ]
        
        # Recherche spécifique pour chaque domaine
        for domain in common_domains:
            # Pattern pour capturer l'email complet avec ce domaine
            domain_pattern = re.compile(
                r'\b[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?' + re.escape(domain) + r'\b',
                re.IGNORECASE
            )
            domain_matches = domain_pattern.findall(text)
            
            for match in domain_matches:
                email = match.strip('.,;:!?()[]{}"\' \t\n\r').lower()
                if self.is_valid_email(email):
                    emails.add(email)
        
        # Pattern alternatif pour emails avec des caractères spéciaux ou espacés
        alt_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+\s*@\s*[A-Za-z0-9.-]+\s*\.\s*[A-Z|a-z]{2,}\b')
        alt_matches = alt_pattern.findall(text)
        for match in alt_matches:
            # Supprimer les espaces
            email = re.sub(r'\s+', '', match)
            if self.is_valid_email(email):
                emails.add(email.lower())
        
        # Pattern pour emails obfusqués (avec [at], [dot], etc.)
        obfuscated_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+\s*(?:\[at\]|@|\(at\))\s*[A-Za-z0-9.-]+\s*(?:\[dot\]|\.|\(dot\))\s*[A-Z|a-z]{2,}\b', re.IGNORECASE)
        obfuscated_matches = obfuscated_pattern.findall(text)
        for match in obfuscated_matches:
            # Remplacer les obfuscations
            email = re.sub(r'\s*(?:\[at\]|\(at\))\s*', '@', match, flags=re.IGNORECASE)
            email = re.sub(r'\s*(?:\[dot\]|\(dot\))\s*', '.', email, flags=re.IGNORECASE)
            email = re.sub(r'\s+', '', email)
            if self.is_valid_email(email):
                emails.add(email.lower())
        
        return emails
    
    def extract_emails_by_domain_search(self, text):
        """Recherche spécialisée d'emails par domaine courant"""
        emails = set()
        
        # Liste exhaustive des domaines identifiés dans les emails racing
        racing_domains = [
            'hotmail.com', 'hotmail.fr', 'gmail.com', 'gmail.fr', 'orange.fr',
            'wanadoo.fr', 'outlook.fr', 'outlook.com', 'yahoo.fr', 'yahoo.com',
            'neuf.fr', 'free.fr', 'sfr.fr', 'laposte.net', 'aol.com',
            'bluewin.ch', 'acs.ch', 'proton.me', 'live.fr',
            # Domaines spécialisés racing/auto
            'porsche-montpellier.fr', 'porsche-avignon.fr', 'porsche-sierre.ch',
            'mclaren.com', 'alpinecars.com', 'williamsf1.com', 'libertymedia.com',
            'verbaereauto.com', 'reworldmedia.com', 'curbstone.net',
            # Extensions courantes
            '.com', '.fr', '.ch', '.be', '.de', '.it', '.lu', '.net', '.org'
        ]
        
        # Pour chaque domaine, rechercher les emails
        for domain in racing_domains:
            # Pattern flexible pour capturer emails avec ce domaine
            pattern = re.compile(
                r'[A-Za-z0-9](?:[A-Za-z0-9._+-]*[A-Za-z0-9])?@[A-Za-z0-9.-]*' + 
                re.escape(domain.lstrip('@.')) + r'(?!\w)',
                re.IGNORECASE
            )
            
            matches = pattern.findall(text)
            for match in matches:
                email = match.strip('.,;:!?()[]{}"\' \t\n\r').lower()
                if self.is_valid_email(email) and '@' in email:
                    emails.add(email)
        
        return emails
    
    def is_valid_email(self, email):
        """Valider le format de l'email"""
        if len(email) > 254:
            return False
        if email.count('@') != 1:
            return False
        local, domain = email.split('@')
        if len(local) > 64 or len(domain) > 253:
            return False
        return True
    
    def extract_emails_from_attributes(self, soup):
        """Extraire emails des attributs HTML (data-*, title, alt, etc.)"""
        emails = set()
        
        # Chercher dans tous les attributs
        for element in soup.find_all():
            if element.attrs:
                for attr_name, attr_value in element.attrs.items():
                    if isinstance(attr_value, str):
                        found_emails = self.extract_emails_from_text(attr_value)
                        emails.update(found_emails)
                    elif isinstance(attr_value, list):
                        for val in attr_value:
                            if isinstance(val, str):
                                found_emails = self.extract_emails_from_text(val)
                                emails.update(found_emails)
        
        return emails
    
    def extract_emails_from_scripts(self, soup):
        """Extraire emails du contenu JavaScript"""
        emails = set()
        
        # Chercher dans tous les scripts
        for script in soup.find_all('script'):
            if script.string:
                found_emails = self.extract_emails_from_text(script.string)
                emails.update(found_emails)
        
        return emails
    
    def extract_emails_from_comments(self, soup):
        """Extraire emails des commentaires HTML"""
        emails = set()
        
        # Chercher dans les commentaires HTML
        from bs4 import Comment
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        
        for comment in comments:
            found_emails = self.extract_emails_from_text(str(comment))
            emails.update(found_emails)
        
        return emails
    
    def extract_mailto_links(self, soup):
        """Extraire emails des liens mailto"""
        emails = set()
        
        # Chercher tous les liens mailto
        for link in soup.find_all('a', href=True):
            href = link['href']
            if href.startswith('mailto:'):
                # Nettoyer l'email (enlever les paramètres)
                email = href[7:].split('?')[0].split('&')[0]
                if self.is_valid_email(email):
                    emails.add(email.lower())
        
        return emails
    
    def decode_encoded_emails(self, text):
        """Décoder les emails encodés (HTML entities, URL encoding, etc.)"""
        import html
        import urllib.parse
        
        # Décoder les entités HTML
        text = html.unescape(text)
        
        # Décoder l'URL encoding
        try:
            text = urllib.parse.unquote(text)
        except:
            pass
        
        return text
    
    def extract_emails_from_json_data(self, soup):
        """Extraire emails des données JSON intégrées"""
        emails = set()
        
        # Chercher dans les scripts JSON-LD
        for script in soup.find_all('script', type='application/ld+json'):
            if script.string:
                found_emails = self.extract_emails_from_text(script.string)
                emails.update(found_emails)
        
        # Chercher dans les attributs data-* qui peuvent contenir du JSON
        for element in soup.find_all():
            if element.attrs:
                for attr_name, attr_value in element.attrs.items():
                    if attr_name.startswith('data-') and isinstance(attr_value, str):
                        try:
                            # Essayer de parser comme JSON
                            import json
                            if attr_value.strip().startswith(('{', '[')):
                                json_data = json.loads(attr_value)
                                json_str = json.dumps(json_data)
                                found_emails = self.extract_emails_from_text(json_str)
                                emails.update(found_emails)
                        except:
                            # Si ce n'est pas du JSON, chercher quand même
                            found_emails = self.extract_emails_from_text(attr_value)
                            emails.update(found_emails)
        
        return emails
    
    def extract_emails_from_css(self, soup):
        """Extraire emails du CSS inline"""
        emails = set()
        
        # Chercher dans les styles inline
        for element in soup.find_all(style=True):
            style_content = element.get('style', '')
            found_emails = self.extract_emails_from_text(style_content)
            emails.update(found_emails)
        
        # Chercher dans les balises <style>
        for style_tag in soup.find_all('style'):
            if style_tag.string:
                found_emails = self.extract_emails_from_text(style_tag.string)
                emails.update(found_emails)
        
        return emails
    
    def get_page_content(self, url, timeout=10):
        """Récupérer le contenu d'une page web"""
        try:
            response = self.session.get(url, timeout=timeout)
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            logger.error(f"Erreur lors de la récupération de {url}: {e}")
            return None
    
    def extract_links(self, html_content, base_url, keyword='informations'):
        """Extraire tous les liens dont le texte ou l'URL contient le mot-clé spécifié (robuste)"""
        import unicodedata
        soup = BeautifulSoup(html_content, 'html.parser')
        links = set()
        all_found = []

        def normalize(txt):
            if not isinstance(txt, str):
                return ''
            txt = txt.lower().strip()
            txt = unicodedata.normalize('NFKD', txt)
            txt = ''.join([c for c in txt if not unicodedata.combining(c)])
            return txt.replace('\xa0', ' ').replace(' ', ' ')

        for link in soup.find_all('a', href=True):
            href = link['href']
            link_text = link.get_text().strip()
            norm_text = normalize(link_text)
            norm_href = normalize(href)
            
            # Si pas de mot-clé spécifié, accepter tous les liens
            if not keyword:
                full_url = urljoin(base_url, href)
                parsed = urlparse(full_url)
                if parsed.scheme in ['http', 'https'] and parsed.netloc:
                    if not any(href.lower().endswith(ext) for ext in IGNORED_EXTENSIONS):
                        links.add(full_url)
                        all_found.append(f"{full_url} (texte: '{link_text}')")
                continue
            
            # Normaliser le mot-clé
            norm_keyword = normalize(keyword)
            
            # On accepte si le mot-clé est dans le texte ou l'URL (robuste)
            if norm_keyword in norm_text or norm_keyword in norm_href:
                full_url = urljoin(base_url, href)
                parsed = urlparse(full_url)
                if parsed.scheme in ['http', 'https'] and parsed.netloc:
                    if not any(href.lower().endswith(ext) for ext in IGNORED_EXTENSIONS):
                        links.add(full_url)
                        all_found.append(f"{full_url} (texte: '{link_text}')")
        
        keyword_info = f"'{keyword}'" if keyword else "TOUS LES LIENS"
        logger.info(f"🔎 {len(links)} liens avec mot-clé {keyword_info} trouvés: {all_found[:5]}...")
        return links
    
    def _extract_urls_from_json(self, data, base_url, links):
        """Extraire récursivement les URLs d'une structure JSON"""
        if isinstance(data, dict):
            for value in data.values():
                self._extract_urls_from_json(value, base_url, links)
        elif isinstance(data, list):
            for item in data:
                self._extract_urls_from_json(item, base_url, links)
        elif isinstance(data, str) and ('http' in data):
            full_url = urljoin(base_url, data)
            parsed = urlparse(full_url)
            if parsed.scheme in ['http', 'https'] and parsed.netloc:
                if not any(data.lower().endswith(ext) for ext in IGNORED_EXTENSIONS):
                    links.add(full_url)
    
    def search_emails_on_page(self, url, keyword='informations'):
        """Rechercher les emails sur une page spécifique"""
        logger.info(f"Analyse de la page: {url}")
        html_content = self.get_page_content(url)
        
        if not html_content:
            return set(), [], False
        
        # Vérifier si la page contient le mot "Email" pour priorisation
        has_email_keyword = 'Email' in html_content or 'email' in html_content or 'E-mail' in html_content
        
        emails = set()
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # MÉTHODE 1: Recherche dans le HTML brut (plus profonde)
        raw_emails = self.extract_emails_from_text(html_content)
        emails.update(raw_emails)
        logger.info(f"Emails trouvés dans HTML brut: {len(raw_emails)}")
        if raw_emails:
            logger.info(f"Emails HTML brut: {list(raw_emails)}")
        
        # MÉTHODE 2: Recherche dans le texte visible
        text_copy = soup.get_text()
        visible_emails = self.extract_emails_from_text(text_copy)
        emails.update(visible_emails)
        logger.info(f"Emails trouvés dans texte visible: {len(visible_emails)}")
        if visible_emails:
            logger.info(f"Emails texte visible: {list(visible_emails)}")
        
        # MÉTHODE 3: Recherche dans les attributs HTML
        attribute_emails = self.extract_emails_from_attributes(soup)
        emails.update(attribute_emails)
        logger.info(f"Emails trouvés dans attributs: {len(attribute_emails)}")
        
        # MÉTHODE 4: Recherche dans les scripts JavaScript
        script_emails = self.extract_emails_from_scripts(soup)
        emails.update(script_emails)
        logger.info(f"Emails trouvés dans scripts: {len(script_emails)}")
        
        # MÉTHODE 5: Recherche dans les commentaires HTML
        comment_emails = self.extract_emails_from_comments(soup)
        emails.update(comment_emails)
        logger.info(f"Emails trouvés dans commentaires: {len(comment_emails)}")
        
        # MÉTHODE 6: Liens mailto
        mailto_emails = self.extract_mailto_links(soup)
        emails.update(mailto_emails)
        logger.info(f"Emails trouvés via mailto: {len(mailto_emails)}")
        
        # MÉTHODE 7: Recherche dans les données JSON/structurées
        try:
            json_emails = self.extract_emails_from_json_data(soup)
            emails.update(json_emails)
            logger.info(f"Emails trouvés dans données JSON: {len(json_emails)}")
        except Exception as e:
            logger.error(f"Erreur lors de l'extraction JSON: {e}")
        
        # MÉTHODE 8: Recherche dans les styles CSS inline
        try:
            css_emails = self.extract_emails_from_css(soup)
            emails.update(css_emails)
            logger.info(f"Emails trouvés dans CSS: {len(css_emails)}")
        except Exception as e:
            logger.error(f"Erreur lors de l'extraction CSS: {e}")
        
        # MÉTHODE 9: NOUVELLE - Recherche spécialisée par domaines racing
        try:
            domain_emails = self.extract_emails_by_domain_search(html_content)
            emails.update(domain_emails)
            logger.info(f"Emails trouvés par recherche domaines: {len(domain_emails)}")
            if domain_emails:
                logger.info(f"Emails domaines: {list(domain_emails)}")
        except Exception as e:
            logger.error(f"Erreur lors de l'extraction par domaines: {e}")
        
        # Extraire les liens pour un scan plus profond
        try:
            links = self.extract_links(html_content, url, keyword)
            logger.info(f"Liens extraits: {len(links)}")
            if links:
                logger.info(f"Exemples de liens trouvés: {list(links)[:5]}")
        except Exception as e:
            logger.error(f"Erreur lors de l'extraction des liens: {e}")
            import traceback
            logger.error(f"Traceback extraction liens: {traceback.format_exc()}")
            links = []
        
        logger.info(f"Total emails uniques trouvés: {len(emails)}")
        if emails:
            logger.info(f"Liste des emails trouvés: {list(emails)}")
        
        # Debug avant le retour
        logger.info(f"AVANT RETOUR - emails: {emails}, type: {type(emails)}")
        logger.info(f"AVANT RETOUR - links: {len(list(links))}")
        logger.info(f"Page contient mot 'Email': {has_email_keyword}")
        
        return emails, list(links), has_email_keyword
    
    def quick_scan_for_email_pages(self, url, max_check=1000, excluded_links=None, keyword='informations'):
        """Scan rapide pour identifier les pages contenant des emails (amélioré)"""
        logger.info(f"🔍 Scan rapide pour identifier les pages avec emails (mot-clé: '{keyword if keyword else 'TOUS'}')")
        
        if excluded_links is None:
            excluded_links = set()
        
        html_content = self.get_page_content(url)
        if not html_content:
            return []
        
        try:
            links = self.extract_links(html_content, url, keyword)
            
            # Filtrer les liens exclus
            filtered_links = [link for link in links if link not in excluded_links]
            
            keyword_info = f"'{keyword}'" if keyword else "TOUS"
            logger.info(f"🔍 Vérification rapide de {min(len(filtered_links), min(max_check, 50))} liens avec mot-clé {keyword_info} (après filtrage)")
            
            email_pages = []
            # Vérifier rapidement les liens - LIMITÉ POUR RENDER
            for i, link in enumerate(filtered_links[:min(max_check, 50)]):  # MAX 50 liens pour éviter timeout
                # PROTECTION RENDER dans le scan rapide
                if 'search_start_time' in globals() and search_start_time:
                    elapsed = time.time() - search_start_time
                    if elapsed > 8:  # Arrêt très tôt dans le scan rapide
                        logger.warning(f"⏰ TIMEOUT dans scan rapide à {elapsed:.1f}s")
                        break
                
                try:
                    response = self.session.get(link, timeout=2)  # Timeout réduit à 2s
                    page_text = response.text.lower()
                    
                    # Vérification plus approfondie pour présence d'emails
                    # Recherche de domaines courants identifiés
                    email_indicators = [
                        '@', 'hotmail.com', 'gmail.com', 'orange.fr', 'wanadoo.fr',
                        'outlook.fr', 'yahoo.fr', 'free.fr', 'sfr.fr', 'neuf.fr',
                        'contact@', 'info@', 'email', 'e-mail', 'mail'
                    ]
                    
                    has_email_content = any(indicator in page_text for indicator in email_indicators)
                    
                    if has_email_content:
                        email_pages.append(link)
                        keyword_info = f"'{keyword}'" if keyword else "TOUS"
                        logger.info(f"⭐ Page avec mot-clé {keyword_info} et emails détectée: {link}")
                except:
                    continue
            
            keyword_info = f"'{keyword}'" if keyword else "TOUS"
            logger.info(f"✅ Scan rapide terminé: {len(email_pages)} pages avec mot-clé {keyword_info} et emails trouvées")
            return email_pages
            
        except Exception as e:
            logger.error(f"❌ Erreur lors du scan rapide: {e}")
            return []
    def search_emails(self, url, max_pages=1000, max_workers=8, known_emails=None, excluded_links=None, keyword='informations'):
        """Rechercher les emails sur un site web (avec système anti-doublons optimisé et timeout Render)"""
        # TIMER GLOBAL pour Render
        global search_start_time
        search_start_time = time.time()
        
        logger.info(f"🚀 DÉBUT recherche d'emails - URL: {url}, max_pages: {max_pages}, mot-clé: '{keyword if keyword else 'TOUS'}', timeout: {SEARCH_TIMEOUT}s")
        
        # Vérification timeout en continu
        def check_timeout():
            if time.time() - search_start_time > SEARCH_TIMEOUT:
                logger.warning(f"⏰ TIMEOUT RENDER atteint ({SEARCH_TIMEOUT}s), arrêt forcé de la recherche")
                raise TimeoutError(f"Recherche interrompue après {SEARCH_TIMEOUT}s pour éviter timeout Render")
        
        # Initialiser les listes de filtrage
        if known_emails is None:
            known_emails = []
        if excluded_links is None:
            excluded_links = []
            
        # Normaliser les emails connus (en minuscules)
        known_emails_set = {email.lower().strip() for email in known_emails if email.strip()}
        excluded_links_set = {link.strip() for link in excluded_links if link.strip()}
        
        logger.info(f"🔍 Filtrage activé: {len(known_emails_set)} emails connus, {len(excluded_links_set)} liens exclus")
        
        results = {
            'url': url,
            'emails': set(),
            'emails_with_sources': {},  
            'pages_scanned': [],
            'errors': [],
            'total_pages': 0,
            'new_emails': set(),  # NOUVEAU: Seulement les nouveaux emails
            'known_emails_found': set(),  # NOUVEAU: Emails connus retrouvés
            'links_by_status': {  # NOUVEAU: Classification des liens
                'with_emails': [],
                'without_emails': [],
                'excluded': list(excluded_links_set),
                'error': []
            }
        }
        
        # Normaliser l'URL
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        parsed_url = urlparse(url)
        base_domain = f"{parsed_url.scheme}://{parsed_url.netloc}"
        logger.info(f"🌐 Domaine de base: {base_domain}")
        
        # NOUVELLE FONCTIONNALITÉ: Pré-scan pour identifier les pages avec mot-clé et emails
        # DÉSACTIVÉ SUR RENDER pour éviter timeout
        if max_pages > 10 and max_pages < 100:  # Seulement pour les scans moyens (pas profonds)
            email_priority_pages = self.quick_scan_for_email_pages(url, max_check=20, excluded_links=excluded_links_set, keyword=keyword)
        else:
            email_priority_pages = []  # Pas de pré-scan pour éviter timeout
        
        # Pages à analyser avec priorité SIMPLIFIÉE
        pages_to_scan = [url] if url not in excluded_links_set else []  # Page principale d'abord
        scanned_pages = set()
        information_priority_queue = [page for page in email_priority_pages if page not in excluded_links_set]  # Filtrer les exclus
        
        keyword_info = f"'{keyword}'" if keyword else "TOUS"
        logger.info(f"📋 Initialisation OPTIMISÉE: {len(information_priority_queue)} pages avec mot-clé {keyword_info} pré-identifiées")
        
        logger.info(f"📋 Pages initiales à scanner: {pages_to_scan}")
        
        while (pages_to_scan or information_priority_queue) and len(scanned_pages) < max_pages:
            # Vérification du timeout au début de chaque itération - TRÈS AGRESSIF
            if check_timeout():
                logger.warning(f"⏰ TIMEOUT ATTEINT dans la boucle principale après {len(scanned_pages)} pages")
                break
            
            # PROTECTION RENDER : Vérification temps écoulé
            elapsed = time.time() - search_start_time
            if elapsed > 10:  # Arrêt à 10 secondes pour être ULTRA sûr
                logger.warning(f"⏰ PROTECTION RENDER : Arrêt préventif à {elapsed:.1f}s")
                break
            
            logger.info(f"🔄 BOUCLE OPTIMISÉE - Pages avec mot-clé: {len(information_priority_queue)}, Pages restantes: {len(pages_to_scan)}, Scannées: {len(scanned_pages)}/{max_pages} - Temps: {elapsed:.1f}s")
            
            # Prioriser les liens avec mot-clé et emails
            current_batch = []
            
            # 1. D'abord traiter les pages avec mot-clé et emails (priorité maximale)
            while information_priority_queue and len(current_batch) < max_workers:
                page = information_priority_queue.pop(0)
                if page not in excluded_links_set:  # Double vérification
                    current_batch.append(page)
            
            # 2. Puis traiter les autres pages
            while pages_to_scan and len(current_batch) < max_workers:
                page = pages_to_scan.pop(0)
                if page not in excluded_links_set:  # Double vérification
                    current_batch.append(page)
            
            if not current_batch:
                logger.info("❌ Aucune page à traiter, arrêt de la boucle")
                break
            
            logger.info(f"⚡ Traitement du batch: {current_batch}")
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_url = {
                    executor.submit(self.search_emails_on_page, page_url, keyword): page_url 
                    for page_url in current_batch
                }
                
                for future in as_completed(future_to_url):
                    # Vérification du timeout pendant le traitement concurrent - ULTRA AGRESSIF
                    elapsed = time.time() - search_start_time
                    if elapsed > 10 or check_timeout():
                        logger.warning(f"⏰ TIMEOUT ATTEINT dans ThreadPoolExecutor après {len(scanned_pages)} pages - Temps: {elapsed:.1f}s")
                        break
                    
                    page_url = future_to_url[future]
                    scanned_pages.add(page_url)
                    
                    try:
                        emails, links, has_email_keyword = future.result()
                        logger.info(f"📄 Page {page_url} traitée: {len(emails)} emails, {len(links)} liens avec mot-clé")
                        
                        # NOUVEAU: Classifier les emails (nouveaux vs connus)
                        new_emails_on_page = set()
                        known_emails_on_page = set()
                        
                        for email in emails:
                            if email in known_emails_set:
                                known_emails_on_page.add(email)
                                logger.info(f"🔄 Email déjà connu: {email}")
                            else:
                                new_emails_on_page.add(email)
                                logger.info(f"✨ NOUVEL email: {email}")
                                
                            if email not in results['emails_with_sources']:  
                                results['emails_with_sources'][email] = page_url
                        
                        results['emails'].update(emails)
                        results['new_emails'].update(new_emails_on_page)
                        results['known_emails_found'].update(known_emails_on_page)
                        
                        # NOUVEAU: Classifier le lien par statut
                        if emails:
                            results['links_by_status']['with_emails'].append({
                                'url': page_url,
                                'emails_count': len(emails),
                                'new_emails': list(new_emails_on_page),
                                'known_emails': list(known_emails_on_page)
                            })
                        else:
                            results['links_by_status']['without_emails'].append(page_url)
                        
                        results['pages_scanned'].append({
                            'url': page_url,
                            'emails_found': len(emails),
                            'emails': list(emails),
                            'new_emails': list(new_emails_on_page),
                            'known_emails': list(known_emails_on_page),
                            'has_email_keyword': has_email_keyword
                        })
                        
                        # Ajouter UNIQUEMENT les nouveaux liens avec mot-clé non exclus
                        new_keyword_links = []
                        
                        for link in links:
                            parsed_link = urlparse(link)
                            if (parsed_link.netloc == parsed_url.netloc and 
                                link not in scanned_pages and 
                                link not in pages_to_scan and
                                link not in information_priority_queue and
                                link not in excluded_links_set):  # NOUVEAU: vérifier exclusion
                                
                                new_keyword_links.append(link)
                        
                        keyword_info = f"'{keyword}'" if keyword else "TOUS"
                        logger.info(f"🔗 Nouveaux liens avec mot-clé {keyword_info} (non exclus): {len(new_keyword_links)}")
                        if new_keyword_links:
                            logger.info(f"🎯 Liens avec mot-clé: {new_keyword_links[:3]}")
                        
                        # Ajouter les nouveaux liens avec mot-clé directement
                        pages_to_scan.extend(new_keyword_links)
                                
                    except Exception as e:
                        logger.error(f"❌ Erreur sur {page_url}: {str(e)}")
                        results['errors'].append(f"Erreur sur {page_url}: {str(e)}")
                        results['links_by_status']['error'].append(page_url)
        
        results['total_pages'] = len(scanned_pages)
        results['emails'] = list(results['emails'])
        results['new_emails'] = list(results['new_emails'])
        results['known_emails_found'] = list(results['known_emails_found'])
        
        logger.info(f"🏁 RÉSULTAT FINAL OPTIMISÉ:")
        logger.info(f"   📧 Total emails: {len(results['emails'])}")
        logger.info(f"   ✨ Nouveaux emails: {len(results['new_emails'])}")
        logger.info(f"   🔄 Emails connus retrouvés: {len(results['known_emails_found'])}")
        logger.info(f"   📊 Pages scannées: {results['total_pages']}")
        logger.info(f"   ✅ Liens avec emails: {len(results['links_by_status']['with_emails'])}")
        logger.info(f"   ❌ Liens sans emails: {len(results['links_by_status']['without_emails'])}")
        logger.info(f"   🚫 Liens exclus: {len(results['links_by_status']['excluded'])}")
        
        if results['new_emails']:
            logger.info(f"NOUVEAUX EMAILS: {results['new_emails']}")
        if results['known_emails_found']:
            logger.info(f"EMAILS CONNUS RETROUVÉS: {results['known_emails_found']}")
        
        return results

# Instance globale du chercheur d'emails
logger.info("🚀 Initialisation de EmailSearcher...")
email_searcher = EmailSearcher()
logger.info("✅ EmailSearcher initialisé avec succès")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/search', methods=['POST'])
def search_emails_endpoint():
    logger.info("🔍 Endpoint /search appelé")
    try:
        data = request.get_json()
        logger.info(f"📝 Données reçues: {data}")
        url = data.get('url', '').strip()
        deep_scan = data.get('deep_scan', False)
        known_emails = data.get('known_emails', [])  # NOUVEAU: emails déjà trouvés
        excluded_links = data.get('excluded_links', [])  # NOUVEAU: liens à éviter
        custom_keyword = data.get('custom_keyword', '').strip()  # NOUVEAU: mot-clé personnalisé
        max_pages_param = data.get('max_pages', None)  # NOUVEAU: limite de pages personnalisée
        
        # Déterminer le mot-clé à utiliser
        keyword = custom_keyword if custom_keyword else 'informations'
        if custom_keyword == '':  # Chaîne vide = chercher tout
            keyword = None
            
        # Déterminer la limite de pages
        if max_pages_param is not None:
            max_pages = max_pages_param
        else:
            max_pages = 1000 if deep_scan else 1
            
        logger.info(f"🎯 URL: {url}, Deep scan: {deep_scan}, Mot-clé: '{keyword if keyword else 'TOUS'}', Max pages: {max_pages}")
        logger.info(f"📧 Emails déjà connus: {len(known_emails)} - {known_emails[:5]}...")
        logger.info(f"🚫 Liens exclus: {len(excluded_links)} - {excluded_links[:3]}...")
        
        if not url:
            logger.error("❌ URL manquante")
            return jsonify({'error': 'URL requise'}), 400
        
        logger.info(f"📊 Recherche avec max_pages: {max_pages}, mot-clé: '{keyword if keyword else 'TOUS'}'")
        
        # PROTECTION RENDER : Vérification immédiate si timeout déjà atteint
        import time
        if 'search_start_time' in globals() and search_start_time and time.time() - search_start_time > SEARCH_TIMEOUT:
            logger.warning(f"⏰ TIMEOUT IMMÉDIAT - Recherche abandonnée avant démarrage")
            return jsonify({
                'success': False,
                'error': 'Timeout prédictif - recherche trop longue pour Render',
                'timeout_reached': True
            })
        
        results = email_searcher.search_emails(url, max_pages=max_pages, known_emails=known_emails, excluded_links=excluded_links, keyword=keyword)
        logger.info(f"✅ Résultats obtenus: {len(results.get('emails', []))} emails")
        
        return jsonify({
            'success': True,
            'data': results
        })
        
    except Exception as e:
        logger.error(f"❌ Erreur: {e}")
        import traceback
        logger.error(f"🔍 Traceback complet: {traceback.format_exc()}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/test')
def test_api():
    return jsonify({'status': 'API fonctionnelle', 'timestamp': time.time()})

if __name__ == '__main__':
    # Configuration pour développement local
    app.run(debug=True, host='0.0.0.0', port=5000)
else:
    # Configuration pour production (Render, PythonAnywhere, Heroku, etc.)
    app.config['DEBUG'] = False
