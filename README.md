# Email Searcher 🔍

Application Flask pour rechercher automatiquement tous les emails sur un site web avec interface mobile-optimisée.

## ✨ Fonctionnalités

- 🔍 **9 méthodes d'extraction** d'emails avancées
- 🎯 **Focus mot-clé** personnalisé pour cibler vos recherches
- 📊 **Limite configurable** de 10 à 100,000 pages
- 🔄 **Système anti-doublons** intelligent
- 📱 **Interface mobile** parfaitement responsive
- ⚡ **Recherche rapide** avec optimisations
- 📧 **Classification automatique** (nouveaux vs connus)
- 🌐 **Compatible web** - fonctionne sur tous les appareils

## 🚀 Démo en ligne

🌐 **Accès direct** : [https://email-searcher.onrender.com](https://email-searcher.onrender.com) *(bientôt disponible)*

## 💻 Installation locale

```bash
# Cloner le repository
git clone https://github.com/VOTRE-USERNAME/email-searcher.git
cd email-searcher

# Installer les dépendances
pip install -r requirements.txt

# Lancer l'application
python app.py
```

Accédez à `http://127.0.0.1:5000` dans votre navigateur.

## 🔧 Configuration

### Paramètres de base
- **URL** : Site web à analyser
- **Mot-clé** : Focus sur pages contenant ce terme (optionnel)
- **Limite pages** : Nombre maximum de pages à analyser

### Gestion des doublons
- **Emails connus** : Liste d'emails déjà collectés
- **Liens exclus** : URLs à ignorer lors du scan

## 📊 Méthodes d'extraction

1. **Mailto links** - Liens `mailto:` directs
2. **Text patterns** - Motifs email dans le texte
3. **JavaScript** - Emails dans le code JavaScript
4. **Comments** - Emails dans les commentaires HTML
5. **Meta tags** - Données structurées et méta
6. **Forms** - Champs de formulaires
7. **Social links** - Liens réseaux sociaux
8. **Contact pages** - Pages de contact spécialisées
9. **Deep scan** - Analyse approfondie multi-niveaux

## 🌐 Déploiement

### Render.com (Recommandé)
1. Fork ce repository
2. Connecter à Render.com
3. Déploiement automatique

### Vercel
1. Connecter le repository à Vercel
2. Configuration automatique via `vercel.json`

### Autres plateformes
Compatible avec Heroku, Railway, PythonAnywhere, etc.

## 📱 Interface mobile

L'interface s'adapte automatiquement :
- **Design responsive** pour tous les écrans
- **Boutons tactiles** optimisés
- **Navigation simplifiée** sur mobile
- **Sections organisées** pour une meilleure lisibilité

## 🛠️ Technologies

- **Backend** : Python Flask
- **Frontend** : HTML5, CSS3, JavaScript
- **Scraping** : BeautifulSoup, Requests
- **Server** : Gunicorn (production)
- **Styling** : CSS moderne avec Flexbox/Grid

## 📧 Utilisation

1. **Entrez l'URL** du site à analyser
2. **Configurez les paramètres** selon vos besoins
3. **Lancez la recherche** intelligente
4. **Récupérez les résultats** avec classification automatique

## 🔒 Respect de la vie privée

- Aucun stockage permanent des données
- Respect des robots.txt
- Limitation des requêtes
- Code source ouvert et transparent

## 🤝 Contribution

Les contributions sont les bienvenues ! N'hésitez pas à :
- Signaler des bugs
- Proposer des améliorations
- Ajouter de nouvelles fonctionnalités

## 📄 Licence

MIT License - Libre d'utilisation

## 🆘 Support

Pour toute question ou problème :
- Ouvrir une **Issue** sur GitHub
- Description détaillée du problème
- Logs d'erreur si disponibles

---

⭐ **N'oubliez pas de star le repo si il vous aide !** ⭐
