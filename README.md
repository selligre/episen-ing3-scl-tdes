# Script de Chiffrement Multi-Étapes DES

## 📋 Description

`encrypt.py` est un script Python qui implémente un **système de chiffrement multi-étapes basé sur DES (Data Encryption Standard)** avec classification par niveaux de sensibilité. Le script s'inspire de l'article académique : *"An Efficient and Secure Big Data Storage in Cloud Environment by Using Triple Data Encryption Standard"*.

Le système adapte le nombre d'étapes de chiffrement en fonction de la sensibilité des données :
- **Niveau 1 (Bas)** : 1 étape de chiffrement DES
- **Niveau 2 (Moyen)** : 2 étapes de chiffrement DES
- **Niveau 3 (Haut/Critique)** : 3 étapes de chiffrement DES (Triple DES)

---

## 🎯 Fonctionnalités Principales

### 1. **Classification par Sensibilité**
Le script classe les données selon trois niveaux de sensibilité :

| Niveau | Nom | Étapes | Taille de clé | Cas d'usage |
|--------|-----|--------|---------------|-----------|
| 1 | Bas | 1 | 16 octets | Données non sensibles |
| 2 | Moyen | 2 | 16 octets | Données sensibles |
| 3 | Haut/Critique | 3 | 24 octets | Données très sensibles/confidentielles |

### 2. **Génération Sécurisée de Clés**
- Génération de clés aléatoires cryptographiquement sûres
- Une clé distincte par étape de chiffrement
- Format Base64 pour les logs (pour une lisibilité facile)

### 3. **Processus de Chiffrement Multi-Étapes**
- **Padding PKCS7** : Les données sont complétées pour avoir une longueur multiple de 8 octets
- **Chiffrement itératif** : Application successive de DES avec des clés différentes
- **Mode ECB** : Electronic Code Book mode (bien que non recommandé en production)

### 4. **Processus de Déchiffrement**
- **Déchiffrement en ordre inverse** : Les étapes sont appliquées en ordre inverse de leur génération
- **Suppression du padding** : Récupération des données originales sans le padding
- **Vérification** : Le script déchiffre automatiquement pour vérifier l'intégrité

### 5. **Logging Détaillé**
- Enregistrement complet du processus dans `encryption_process.log`
- Affichage en console et fichier simultanément
- Timestamps et niveaux de sévérité (INFO, WARNING, ERROR)

---

## 🔧 Installation et Configuration

### Prérequis
```bash
Python 3.7+
```

### Dépendances
```bash
pip install pycryptodome
```

Ou installer via `requirements.txt` si disponible :
```bash
pip install -r requirements.txt
```

---

## 📱 Utilisation

### Mode Interactif (Par défaut)

```bash
python encrypt.py
```

Le script vous guidera à travers les étapes :
1. Sélection du niveau de sensibilité (1, 2, ou 3)
2. Génération automatique des clés
3. Saisie du texte à chiffrer
4. Chiffrement multi-étapes
5. Déchiffrement automatique pour vérification

**Exemple d'interaction :**
```
Veuillez selectionner le niveau de sensibilite (1/2/3): 3
Entrez le texte a chiffrer: Donnees confidentielles
```

### Mode Test Automatisé

```bash
python encrypt.py --auto --level 2 --data "Texte de test"
```

**Paramètres** :
- `--auto` ou `--test` : Activates automatic test mode
- `--level {1|2|3}` : Spécifie le niveau de sensibilité
- `--data "texte"` : Fournit le texte à chiffrer directement

---

## 🔐 Structure du Code

### Classe Principale : `SensitivityBasedEncryption`

#### Attributs
```python
SENSITIVITY_LEVELS    # Dictionnaire des niveaux de sensibilité
DES_BLOCK_SIZE       # Taille des blocs DES (8 octets)
keys                 # Liste des clés générées
sensitivity_level    # Niveau de sensibilité sélectionné
data_to_encrypt      # Données à chiffrer
```

#### Méthodes Clés

| Méthode | Description |
|---------|-------------|
| `ask_sensitivity_level()` | Demande à l'utilisateur le niveau de sensibilité |
| `generate_keys()` | Génère les clés aléatoires nécessaires |
| `pad_data(data)` | Applique le padding PKCS7 |
| `encrypt_stage(data, key, stage)` | Effectue une étape de chiffrement DES |
| `encrypt_data(data)` | Applique toutes les étapes de chiffrement |
| `decrypt_stage(data, key, stage)` | Effectue une étape de déchiffrement |
| `decrypt_data(encrypted)` | Applique toutes les étapes de déchiffrement (ordre inverse) |
| `run_demonstration()` | Exécute la démonstration complète |

---

## 📊 Flux du Processus de Chiffrement

```
DONNÉES ORIGINALES
        ↓
[PADDING PKCS7] → Données alignées sur 8 octets
        ↓
[ÉTAPE 1 : Chiffrement DES avec Clé 1]
        ↓
[ÉTAPE 2 : Chiffrement DES avec Clé 2] ← optionnel (niveau 2+)
        ↓
[ÉTAPE 3 : Chiffrement DES avec Clé 3] ← optionnel (niveau 3 uniquement)
        ↓
DONNÉES CHIFFRÉES (format Base64 en logs)
```

### Flux du Processus de Déchiffrement

```
DONNÉES CHIFFRÉES
        ↓
[ÉTAPE 3 : Déchiffrement DES avec Clé 3] ← optionnel (niveau 3 uniquement)
        ↓
[ÉTAPE 2 : Déchiffrement DES avec Clé 2] ← optionnel (niveau 2+)
        ↓
[ÉTAPE 1 : Déchiffrement DES avec Clé 1]
        ↓
[SUPPRESSION DU PADDING PKCS7] → Récupération des données originales
        ↓
DONNÉES DÉCRYPTÉES (vérification d'intégrité)
```

---

## 📝 Fichiers Générés

### `encryption_process.log`
Fichier de log détaillé contenant :
- Timestamps de chaque opération
- Niveaux de sensibilité sélectionnés
- Clés générées (en Base64)
- Taille des données à chaque étape
- Résultats du chiffrement et déchiffrement
- Statut de vérification (succès/échec)

**Exemple de contenu :**
```
2026-04-28 10:30:45,123 - INFO - [__init__] - INITIALISATION DU SYSTEME DE CHIFFREMENT MULTI-ETAPES
...
2026-04-28 10:30:46,456 - INFO - [generate_des_key] - Cle 1 generee (24 octets): base64_key_here...
2026-04-28 10:30:47,789 - INFO - [encrypt_stage] - [OK] Donnees chiffrees: 32 octets
```

---

## 🔒 Considérations de Sécurité

### Points Forts
✅ Génération cryptographiquement sûre de clés  
✅ Logging détaillé pour audit  
✅ Vérification automatique par déchiffrement  
✅ Support de trois niveaux de sensibilité  

### Limitations ⚠️
⚠️ **Mode ECB** : Non recommandé pour la production (patterns visibles)  
⚠️ **DES obsolète** : DES est considéré comme faible ; préférer AES pour la production  
⚠️ **Pas de gestion de clés** : Les clés ne sont pas sauvegardées de manière sécurisée  
⚠️ **Pas de MAC** : Aucune vérification d'intégrité (HMAC)  

### Recommandations pour la Production
```python
# Remplacer DES3 par AES
from Crypto.Cipher import AES

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
