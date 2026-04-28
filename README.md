# Script de Chiffrement Multi-Étapes DES & AES

## 📋 Description

`encrypt.py` est un script Python qui implémente un **système de chiffrement multi-étapes** avec support de **DES (Data Encryption Standard)** et **AES (Advanced Encryption Standard)** avec classification par niveaux de sensibilité. Le script s'inspire de l'article académique : *"An Efficient and Secure Big Data Storage in Cloud Environment by Using Triple Data Encryption Standard"*.

Le système adapte le nombre d'étapes de chiffrement en fonction de la sensibilité des données :
- **Niveau 1 (Bas)** : 1 étape de chiffrement
- **Niveau 2 (Moyen)** : 2 étapes de chiffrement
- **Niveau 3 (Haut/Critique)** : 3 étapes de chiffrement (Triple encryption)

Algorithmes supportés:
- **DES** : Triple DES (3DES) - Algorithme classique
- **AES** : Advanced Encryption Standard - Algorithme moderne

---

## 🎯 Fonctionnalités Principales

### 1. **Choix de l'Algorithme**
- **DES (Triple DES)** : Algorithme classique, bloc de 8 octets
- **AES (Advanced Encryption Standard)** : Algorithme moderne, bloc de 16 octets
- Sélection interactive ou via ligne de commande

### 2. **Classification par Sensibilité**
Le script classe les données selon trois niveaux de sensibilité :

| Niveau | Nom | Étapes | Taille de clé | Cas d'usage |
|--------|-----|--------|---------------|-----------|
| 1 | Bas | 1 | 16 octets | Données non sensibles |
| 2 | Moyen | 2 | 16 octets | Données sensibles |
| 3 | Haut/Critique | 3 | 24 octets | Données très sensibles/confidentielles |

### 3. **Génération Sécurisée de Clés**
- Génération de clés aléatoires cryptographiquement sûres
- Une clé distincte par étape de chiffrement
- Format Base64 pour les logs (pour une lisibilité facile)

### 4. **Processus de Chiffrement Multi-Étapes**
- **Padding adapté** : Padding PKCS7 sur 8 octets (DES) ou 16 octets (AES)
- **Chiffrement itératif** : Application successive avec des clés différentes
- **Mode ECB** : Electronic Code Book mode

### 5. **Sources de Données Flexibles**
- **Texte manuel** : Saisie directe du texte à chiffrer
- **Fichier texte** : Lecture depuis un fichier (texte brut ou volumineux)
- Support en ligne de commande ou mode interactif

### 6. **Processus de Déchiffrement**
- **Déchiffrement en ordre inverse** : Les étapes sont appliquées en ordre inverse
- **Suppression du padding** : Récupération des données originales
- **Vérification automatique** : Le script déchiffre pour vérifier l'intégrité

### 7. **Logging Détaillé avec Performances**
- Enregistrement complet dans `encryption_process.log`
- Affichage en console et fichier simultanément
- **Timestamps précis** : Format HH:MM:SS.mmm avec millisecondes
- **Mesures de performance** :
  - ⏱️ Temps d'exécution total en millisecondes
  - ⏱️ Temps de chiffrage spécifique
  - ⏱️ Temps de déchiffrage spécifique
  - 📊 Utilisation CPU moyenne pendant l'exécution

---

## 🔧 Installation et Configuration

### Prérequis
```bash
Python 3.7+
```

### Dépendances
```bash
pip install -r requirements.txt
```

Ou installer manuellement :
```bash
pip install pycryptodome>=3.15.0 psutil>=5.9.0
```

---

## 📱 Utilisation

### Mode Interactif (Par défaut)

```bash
python encrypt.py
```

Le script vous guidera à travers les étapes :
1. **Sélection de l'algorithme** (DES ou AES)
2. **Sélection du niveau de sensibilité** (1, 2, ou 3)
3. **Génération automatique des clés**
4. **Sélection de la source de données** (texte manuel ou fichier)
5. **Saisie du texte** ou **chemin du fichier**
6. **Chiffrement multi-étapes**
7. **Déchiffrement automatique pour vérification**
8. **Rapport de performance**

**Exemple d'interaction :**
```
Veuillez selectionner (1 pour DES / 2 pour AES): 2
Veuillez selectionner le niveau de sensibilite (1/2/3): 3
Veuillez selectionner (1 pour texte / 2 pour fichier): 1
Entrez le texte a chiffrer: Donnees confidentielles
```

### Mode Test Automatisé

#### Avec texte direct
```bash
python encrypt.py --auto --level 3 --algo AES --data "Texte de test"
```

#### Avec fichier
```bash
python encrypt.py --auto --level 3 --algo DES --file mon_fichier.txt
```

#### Avec DES (par défaut)
```bash
python encrypt.py --auto --level 2 --data "Test"
```

### Paramètres en Ligne de Commande

| Paramètre | Valeurs | Description |
|-----------|---------|-------------|
| `--auto` ou `--test` | - | Active le mode test automatisé |
| `--level` | 1, 2, 3 | Définit le niveau de sensibilité |
| `--algo` | DES, AES | Choisit l'algorithme de chiffrement |
| `--data` | texte | Fournit le texte à chiffrer directement |
| `--file` | chemin | Fournit le chemin d'un fichier texte |

### Exemples Pratiques

**Exemple 1 : Chiffrer un texte court avec AES (niveau élevé)**
```bash
python encrypt.py --auto --level 3 --algo AES --data "Mon secret"
```

**Exemple 2 : Chiffrer un fichier volumineux avec DES (niveau moyen)**
```bash
python encrypt.py --auto --level 2 --algo DES --file /chemin/vers/fichier.txt
```

**Exemple 3 : Mode interactif classique**
```bash
python encrypt.py
```

---

## 🔐 Architecture Technique

### Flux de Chiffrement

```
Données originales
    ↓
Padding PKCS7 (8 ou 16 octets selon algo)
    ↓
Étape 1 : Chiffrement DES/AES avec clé 1
    ↓
Étape 2 : Chiffrement DES/AES avec clé 2 (si niveau ≥ 2)
    ↓
Étape 3 : Chiffrement DES/AES avec clé 3 (si niveau = 3)
    ↓
Données chiffrées (base64)
```

### Flux de Déchiffrement

```
Données chiffrées (base64)
    ↓
Décodage base64
    ↓
Étape 3 : Déchiffrement avec clé 3 (ordre inverse)
    ↓
Étape 2 : Déchiffrement avec clé 2
    ↓
Étape 1 : Déchiffrement avec clé 1
    ↓
Suppression du padding PKCS7
    ↓
Données originales
```

---

## 📊 Résultats et Rapports

### Structure du Logging

Le script génère un fichier `encryption_process.log` contenant :

1. **Initialisation** : Configuration du système
2. **Sélections** : Algorithme, niveau, source de données
3. **Génération des clés** : Détails de chaque clé générée
4. **Étapes de chiffrement** : Détail de chaque étape avec les données
5. **Résultat du chiffrement** : Données chiffrées en base64
6. **Déchiffrement** : Vérification étape par étape
7. **Résultats de vérification** : Comparaison données originales/déchiffrées
8. **Rapport de performance** : Timings et utilisation CPU

### Exemple de Rapport de Performance

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                            RAPPORT DE PERFORMANCE                            ║
║──────────────────────────────────────────────────────────────────────────────║
║ ⏱️  Chiffrage: 104.24ms | CPU: 0.0%                                            ║
║ ⏱️  Dechiffrage: 102.54ms | CPU: 0.0%                                          ║
║ ⏱️  Execution totale: 210.15ms | CPU: 0.1%                                     ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## 🔐 Structure du Code

### Classe Principale : `SensitivityBasedEncryption`

#### Attributs
```python
SENSITIVITY_LEVELS    # Dictionnaire des niveaux de sensibilité
DES_BLOCK_SIZE       # Taille des blocs DES (8 octets)
AES_BLOCK_SIZE       # Taille des blocs AES (16 octets)
keys                 # Liste des clés générées
sensitivity_level    # Niveau de sensibilité sélectionné
data_to_encrypt      # Données à chiffrer
algorithm            # Algorithme choisi (DES ou AES)
```

#### Méthodes Clés

| Méthode | Description |
|---------|-------------|
| `ask_algorithm()` | Demande à l'utilisateur de choisir DES ou AES |
| `ask_sensitivity_level()` | Demande à l'utilisateur le niveau de sensibilité |
| `ask_data_source()` | Demande le choix entre texte manuel ou fichier |
| `read_file_data(filepath)` | Lit un fichier texte |
| `generate_keys()` | Génère les clés aléatoires nécessaires |
| `pad_data(data)` | Applique le padding PKCS7 adapté (8 ou 16 octets) |
| `encrypt_stage(data, key, stage)` | Effectue une étape de chiffrement DES/AES |
| `encrypt_data(data)` | Applique toutes les étapes de chiffrement |
| `decrypt_stage(data, key, stage)` | Effectue une étape de déchiffrement |
| `decrypt_data(encrypted)` | Applique toutes les étapes de déchiffrement (ordre inverse) |
| `run_demonstration()` | Exécute la démonstration complète |

---

## 🔒 Considérations de Sécurité

### Points Forts
✅ Génération cryptographiquement sûre de clés  
✅ Logging détaillé pour audit  
✅ Vérification automatique par déchiffrement  
✅ Support de trois niveaux de sensibilité  
✅ Padding adapté à la taille de bloc de chaque algorithme
✅ Support de DES et AES modernes

### Limitations ⚠️
⚠️ **Mode ECB** : Non recommandé pour la production (patterns visibles)  
⚠️ **DES obsolète** : DES est considéré comme faible ; préférer AES pour la production  
⚠️ **Pas de gestion de clés persistante** : Les clés ne sont pas sauvegardées de manière sécurisée  
⚠️ **Pas de MAC** : Aucune vérification d'intégrité (HMAC)  

### Recommandations pour la Production
```python
# Utiliser AES plutôt que DES
--algo AES

# Utiliser le niveau 3 pour les données critiques
--level 3

# Implémenter une persistance sécurisée des clés
# Considérer des modes de chiffrement plus sûrs (CBC, CTR, GCM)
# Ajouter des MAC pour l'authentification
```

---

## 📁 Fichiers Générés

- **encrypt.py** : Script principal
- **encryption_process.log** : Journal détaillé de l'exécution
- **requirements.txt** : Dépendances Python
- **README.md** : Cette documentation

---

## 🧪 Tests

Pour tester rapidement :

```bash
# Test avec DES, niveau 1
python encrypt.py --auto --level 1 --algo DES --data "Test DES"

# Test avec AES, niveau 3
python encrypt.py --auto --level 3 --algo AES --data "Test AES"

# Test avec fichier
python encrypt.py --auto --level 2 --algo AES --file test.txt
```

---

## 📝 Notes de Conception

- Logging avec timestamps au format HH:MM:SS.mmm pour précision
- Interface Unicode avec des symboles visuels (╔═╗ ✓ ⏱️ 🔐 etc.)
- Gestion robuste des erreurs avec messages détaillés
- Support des caractères spéciaux et encodage UTF-8
- Affichage limité à 100 caractères pour les textes longs dans les logs
- Padding automatiquement adapté au bloc size de l'algorithme

---

## 📄 Licence et Attribution

Ce script s'inspire de l'article académique :
*"An Efficient and Secure Big Data Storage in Cloud Environment by Using Triple Data Encryption Standard"*

---

## 🤝 Support

Pour toute question ou amélioration, veuillez consulter les logs détaillés dans `encryption_process.log`.

# Utiliser CBC/GCM au lieu d'ECB
cipher = AES.new(key, AES.MODE_GCM)

# Ajouter un HMAC pour vérifier l'intégrité
from Crypto.Hash import HMAC, SHA256
```

---

## 📚 Exemples d'Utilisation

### Exemple 1 : Données de Niveau 1 (Non sensibles)
```bash
python encrypt.py --auto --level 1 --data "Hello World"
```
→ 1 étape de chiffrement, clé de 16 octets

### Exemple 2 : Données Critiques (Niveau 3)
```bash
python encrypt.py --auto --level 3 --data "Informations confidentielles"
```
→ Triple DES, clé de 24 octets, 3 étapes

### Exemple 3 : Mode Interactif
```bash
python encrypt.py
```
→ Interface guidée pas à pas

---

## 🐛 Dépannage

| Problème | Cause | Solution |
|----------|-------|----------|
| `ModuleNotFoundError: No module named 'Crypto'` | pycryptodome non installé | `pip install pycryptodome` |
| Erreur d'encodage UTF-8 dans les logs | Encodage système différent | Vérifier l'encodage système |
| Les données déchiffrées ne correspondent pas | Mauvaise clé ou corruption | Vérifier les logs dans `encryption_process.log` |
| Timeout du script | Données trop grandes | Réduire la taille des données |

---

## 📖 Références

- **Algorithme DES** : Federal Information Processing Standards (FIPS 46-3)
- **Triple DES (3DES)** : NIST SP 800-67 Revision 1
- **Padding PKCS7** : RFC 5652
- **Article inspirant** : "An Efficient and Secure Big Data Storage in Cloud Environment by Using Triple Data Encryption Standard"
- **Bibliothèque** : [PyCryptodome](https://www.dlitz.net/software/pycryptodome/)

---

## 📄 Licence

Ce script est fourni à titre éducatif.

---

## ✅ Checklist de Vérification

- [ ] Python 3.7+ installé
- [ ] pycryptodome installé (`pip install pycryptodome`)
- [ ] Fichier `encrypt.py` présent
- [ ] Permissions d'exécution appropriées
- [ ] Fichier `encryption_process.log` généré après première exécution
- [ ] Vérification réussie à chaque déchiffrement

---

**Créé** : 2026  
**Version** : 1.0  
**État** : Production (à titre éducatif)
