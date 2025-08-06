# Configuration pour Email Searcher

# Parametres du serveur
HOST = '0.0.0.0'  # Adresse d'ecoute (0.0.0.0 pour toutes les interfaces)
PORT = 5000       # Port d'ecoute
DEBUG = True      # Mode debug (False en production)

# Parametres de recherche
MAX_PAGES_DEFAULT = 200   # Augmenté de 100 à 200 pages pour une recherche plus complète
MAX_WORKERS = 10          # Augmenté de 8 à 10 threads pour plus de parallélisme
REQUEST_TIMEOUT = 20      # Augmenté de 15 à 20 secondes

# Parametres de recherche approfondie
DEEP_SEARCH_ENABLED = True        # Activer la recherche approfondie
SEARCH_IN_SCRIPTS = True          # Chercher dans les scripts JavaScript
SEARCH_IN_COMMENTS = True         # Chercher dans les commentaires HTML
SEARCH_IN_ATTRIBUTES = True       # Chercher dans tous les attributs HTML
SEARCH_IN_CSS = True              # Chercher dans les styles CSS
SEARCH_IN_JSON = True             # Chercher dans les données JSON
DECODE_OBFUSCATED = True          # Décoder les emails obfusqués ([at], [dot])
SEARCH_RAW_HTML = True            # Chercher dans le HTML brut (avant parsing)

# Parametres de securite
MAX_URL_LENGTH = 2048     # Longueur maximum autorisee pour les URLs
ALLOWED_SCHEMES = ['http', 'https']  # Schemas d'URL autorises

# Headers HTTP
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'

# Domaines a eviter (optionnel)
BLOCKED_DOMAINS = [
    # 'example-blocked.com',
    # 'spam-site.com'
]

# Extensions de fichiers a ignorer
IGNORED_EXTENSIONS = [
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.zip', '.rar', '.tar', '.gz', '.7z',
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg',
    '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv',
    '.exe', '.msi', '.dmg', '.deb', '.rpm'
]

# Patterns d'emails a ignorer (optionnel)
IGNORED_EMAIL_PATTERNS = [
    # r'.*@example\.com',
    # r'.*noreply.*',
    # r'.*no-reply.*'
]
