"""
Script de chiffrement multi-etapes base sur DES
Selon l'article: "An Efficient and Secure Big Data Storage in Cloud Environment
by Using Triple Data Encryption Standard"

Le script implemente un systeme de sensibilite pour les donnees:
- Niveau 1 (Bas): 1 etape de chiffrement DES
- Niveau 2 (Moyen): 2 etapes de chiffrement DES
- Niveau 3 (Haut/Critique): 3 etapes de chiffrement DES (Triple DES)
"""

import logging
from Crypto.Cipher import DES3, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import time
import psutil
import os
from contextlib import contextmanager
from datetime import datetime

# Configuration du logging detaille avec UTF-8 et timestamps améliorés
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s.%(msecs)03d | %(levelname)s | %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.FileHandler("encryption_process.log", encoding="utf-8", mode="w"),
    ],
)

# Ajouter un handler console
console_handler = logging.StreamHandler()
console_handler.setFormatter(
    logging.Formatter("%(asctime)s.%(msecs)03d | %(levelname)s | %(message)s", datefmt="%H:%M:%S")
)
logging.getLogger().addHandler(console_handler)

logger = logging.getLogger(__name__)

# Classe pour mesurer les performances
class PerformanceTimer:
    def __init__(self, name):
        self.name = name
        self.start_time = None
        self.end_time = None
        self.duration = None
        self.start_cpu = None
        self.end_cpu = None
        self.cpu_usage = None
        
    def __enter__(self):
        self.start_time = time.time()
        process = psutil.Process(os.getpid())
        self.start_cpu = process.cpu_percent(interval=0.1)
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end_time = time.time()
        self.duration = (self.end_time - self.start_time) * 1000  # en millisecondes
        process = psutil.Process(os.getpid())
        self.end_cpu = process.cpu_percent(interval=0.1)
        self.cpu_usage = (self.start_cpu + self.end_cpu) / 2  # moyenne
        
    def get_report(self):
        if self.duration:
            return f"{self.name}: {self.duration:.2f}ms | CPU: {self.cpu_usage:.1f}%"
        return f"{self.name}: Non exécuté"


class SensitivityBasedEncryption:
    """
    Classe qui gere le chiffrement multi-etapes selon le niveau de sensibilite
    """

    # Mapping des niveaux de sensibilite
    SENSITIVITY_LEVELS = {
        1: {
            "name": "Bas",
            "stages": 1,
            "description": "1 etape de chiffrement",
            "key_size": 16,
        },
        2: {
            "name": "Moyen",
            "stages": 2,
            "description": "2 etapes de chiffrement",
            "key_size": 16,
        },
        3: {
            "name": "Haut/Critique",
            "stages": 3,
            "description": "3 etapes de chiffrement (Triple encryption)",
            "key_size": 24,
        },
    }

    DES_BLOCK_SIZE = 8  # DES fonctionne avec des blocs de 8 octets
    AES_BLOCK_SIZE = 16  # AES fonctionne avec des blocs de 16 octets

    def __init__(self):
        logger.info("╔" + "=" * 78 + "╗")
        logger.info("║ " + "INITIALISATION DU SYSTEME DE CHIFFREMENT MULTI-ETAPES".center(76) + " ║")
        logger.info("╚" + "=" * 78 + "╝")
        self.keys = []
        self.sensitivity_level = None
        self.data_to_encrypt = None
        self.algorithm = None  # "DES" ou "AES"
        self.timers = {
            'total': None,
            'encrypt': None,
            'decrypt': None
        }
        
        # Paramètres selon l'algorithme
        self.ALGORITHM_PARAMS = {
            "DES": {
                "block_size": 8,
                "iv_size": 8,
                "description": "Triple DES (3DES)"
            },
            "AES": {
                "block_size": 16,
                "iv_size": 16,
                "description": "Advanced Encryption Standard (AES)"
            }
        }

    def display_sensitivity_levels(self):
        """Affiche les niveaux de sensibilite disponibles"""
        logger.info("\n┌" + "─" * 78 + "┐")
        logger.info("│ " + "NIVEAUX DE SENSIBILITE DISPONIBLES".center(76) + " │")
        logger.info("├" + "─" * 78 + "┤")
        for level, info in self.SENSITIVITY_LEVELS.items():
            logger.info("│ Niveau {}: {}".format(level, info["name"]).ljust(78) + " │")
            logger.info("│   • Description: {}".format(info["description"]).ljust(77) + "│")
            logger.info("│   • Nombre d'etapes: {}".format(info["stages"]).ljust(77) + "│")
            logger.info("│   • Taille de cle: {} octets".format(info["key_size"]).ljust(77) + "│")
        logger.info("└" + "─" * 78 + "┘")

    def ask_sensitivity_level(self):
        """Demande a l'utilisateur le niveau de sensibilite"""
        logger.info("\n┌" + "─" * 78 + "┐")
        logger.info("│ " + "DEMANDE DU NIVEAU DE SENSIBILITE".ljust(76) + " │")
        logger.info("└" + "─" * 78 + "┘")
        self.display_sensitivity_levels()

        while True:
            try:
                level = int(
                    input("Veuillez selectionner le niveau de sensibilite (1/2/3): ")
                )
                if level in self.SENSITIVITY_LEVELS:
                    self.sensitivity_level = level
                    level_info = self.SENSITIVITY_LEVELS[level]
                    logger.info(
                        "[✓] Niveau de sensibilite selectionne: {} ({})".format(
                            level, level_info["name"]
                        )
                    )
                    logger.info("  • {}".format(level_info["description"]))
                    logger.info(
                        "  • Nombre d'etapes d'encryptage: {}\n".format(
                            level_info["stages"]
                        )
                    )
                    return level
                else:
                    logger.warning(
                        "Niveau invalide: {}. Veuillez choisir entre 1 et 3.".format(
                            level
                        )
                    )
                    print("Erreur: Veuillez choisir entre 1 et 3.")
            except ValueError:
                logger.warning("Entree invalide: veuillez entrer un nombre.")
                print("Erreur: Veuillez entrer un nombre valide.")

    def ask_algorithm(self):
        """Demande a l'utilisateur de choisir l'algorithme de chiffrement"""
        logger.info("\n┌" + "─" * 78 + "┐")
        logger.info("│ " + "CHOIX DE L'ALGORITHME DE CHIFFREMENT".ljust(76) + " │")
        logger.info("└" + "─" * 78 + "┘")
        
        logger.info("\nAlgorithmes disponibles:")
        logger.info("  1. DES  - Triple DES (3DES) - Algorithme classique")
        logger.info("  2. AES  - Advanced Encryption Standard - Algorithme moderne")
        
        while True:
            try:
                choice = input("\nVeuillez selectionner (1 pour DES / 2 pour AES): ").strip()
                if choice == "1":
                    self.algorithm = "DES"
                    logger.info("[✓] Algorithme selectionne: DES (Triple DES)")
                    return "DES"
                elif choice == "2":
                    self.algorithm = "AES"
                    logger.info("[✓] Algorithme selectionne: AES (Advanced Encryption Standard)")
                    return "AES"
                else:
                    if choice == "":
                        logger.warning("Veuillez entrer une valeur.")
                    else:
                        logger.warning("Choix invalide: {}. Veuillez entrer 1 ou 2.".format(choice))
                    print("Erreur: Veuillez entrer 1 ou 2.")
            except ValueError:
                logger.warning("Entree invalide: veuillez entrer un nombre.")
                print("Erreur: Veuillez entrer un nombre valide.")

    def ask_data_source(self):
        """Demande a l'utilisateur de choisir entre texte manuel ou fichier"""
        logger.info("\n┌" + "─" * 78 + "┐")
        logger.info("│ " + "SOURCE DES DONNEES A CHIFFRER".ljust(76) + " │")
        logger.info("└" + "─" * 78 + "┘")
        
        logger.info("\nSources disponibles:")
        logger.info("  1. Texte manuel - Saisir le texte directement")
        logger.info("  2. Fichier     - Lire depuis un fichier texte")
        
        while True:
            try:
                choice = input("\nVeuillez selectionner (1 pour texte / 2 pour fichier): ").strip()
                if choice == "1":
                    return "manual"
                elif choice == "2":
                    return "file"
                else:
                    if choice == "":
                        logger.warning("Veuillez entrer une valeur.")
                    else:
                        logger.warning("Choix invalide: {}. Veuillez entrer 1 ou 2.".format(choice))
                    print("Erreur: Veuillez entrer 1 ou 2.")
            except ValueError:
                logger.warning("Entree invalide: veuillez entrer un nombre.")
                print("Erreur: Veuillez entrer un nombre valide.")

    def read_file_data(self, filepath):
        """Lit les donnees depuis un fichier texte"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = f.read()
            logger.info("[✓] Fichier lu avec succes: {}".format(filepath))
            logger.info("   Taille: {} caracteres".format(len(data)))
            return data
        except FileNotFoundError:
            logger.error("[ERREUR] Fichier non trouve: {}".format(filepath))
            print("Erreur: Le fichier '{}' n'a pas ete trouve.".format(filepath))
            return None
        except Exception as e:
            logger.error("[ERREUR] Erreur lors de la lecture du fichier: {}".format(str(e)))
            print("Erreur: {}".format(str(e)))
            return None

    def generate_des_key(self, key_number, key_size):
        """
        Genere une cle DES aleatoire unique
        key_size: 8 pour simple DES, 16 pour double DES, 24 pour triple DES
        """
        key = get_random_bytes(key_size)
        logger.info(
            "  Cle {} generee ({} octets): {}".format(
                key_number, key_size, base64.b64encode(key).decode()
            )
        )
        return key

    def generate_keys(self):
        """Genere les cles DES necessaires selon le niveau de sensibilite"""
        if self.sensitivity_level is None:
            raise ValueError("Le niveau de sensibilite doit d'abord etre defini")

        num_stages = self.SENSITIVITY_LEVELS[self.sensitivity_level]["stages"]
        key_size = self.SENSITIVITY_LEVELS[self.sensitivity_level]["key_size"]

        logger.info("\n┌" + "─" * 78 + "┐")
        logger.info("│ " + f"GENERATION DES CLES D'ENCRYPTAGE ({num_stages} cle(s), {key_size} octets chacune)".ljust(76) + " │")
        logger.info("└" + "─" * 78 + "┘")

        self.keys = []
        for i in range(1, num_stages + 1):
            key = self.generate_des_key(i, key_size)
            self.keys.append(key)

        logger.info("[✓] {} cle(s) generee(s) avec succes\n".format(num_stages))

    def pad_data(self, data):
        """
        Ajoute du padding PKCS7 aux donnees pour qu'elles soient un multiple de la taille de bloc
        """
        block_size = self.AES_BLOCK_SIZE if self.algorithm == "AES" else self.DES_BLOCK_SIZE
        padded_data = pad(data, block_size)

        padding_length = len(padded_data) - len(data)
        logger.info("  ✓ Padding applique: {} octets ajoutes".format(padding_length))
        logger.info("    Taille avant padding: {} octets".format(len(data)))
        logger.info("    Taille apres padding: {} octets (bloc: {})".format(len(padded_data), block_size))

        return padded_data

    def encrypt_stage(self, data, key, stage_number):
        """Effectue une etape de chiffrement DES ou AES"""
        try:
            logger.info("")
            logger.info("  ╔═══ ETAPE {} DE CHIFFREMENT ({}) ═══╗".format(stage_number, self.algorithm))

            # Affiche les informations de la cle
            key_b64 = base64.b64encode(key).decode()
            logger.info("    🔑 Cle utilisee: {}".format(key_b64))
            logger.info("       Taille de la cle: {} octets".format(len(key)))
            logger.info("       Donnees a chiffrer: {} octets".format(len(data)))

            # Creation du chiffre selon l'algorithme
            if self.algorithm == "DES":
                des_cipher = DES3.new(key, DES3.MODE_ECB)
                encrypted_data = des_cipher.encrypt(data)
            elif self.algorithm == "AES":
                aes_cipher = AES.new(key, AES.MODE_ECB)
                encrypted_data = aes_cipher.encrypt(data)
            else:
                raise ValueError("Algorithme non supporté: {}".format(self.algorithm))

            encrypted_b64 = base64.b64encode(encrypted_data).decode()
            logger.info(
                "    ✓ Donnees chiffrees: {} octets".format(len(encrypted_data))
            )
            if len(encrypted_b64) > 100:
                logger.info("       (base64): {}...".format(encrypted_b64[:100]))
            else:
                logger.info("       (base64): {}".format(encrypted_b64))

            return encrypted_data

        except Exception as e:
            logger.error(
                "[ERREUR] Erreur lors du chiffrement etape {}: {}".format(
                    stage_number, str(e)
                )
            )
            raise

    def encrypt_data(self, data):
        """
        Applique les etapes d'encryptage selon le niveau de sensibilite
        """
        if self.sensitivity_level is None:
            raise ValueError("Le niveau de sensibilite doit d'abord etre defini")

        num_stages = self.SENSITIVITY_LEVELS[self.sensitivity_level]["stages"]

        with PerformanceTimer("Chiffrage") as timer:
            self.timers['encrypt'] = timer
            
            logger.info("\n┌" + "─" * 78 + "┐")
            logger.info("│ " + f"PROCESSUS DE CHIFFREMENT MULTI-ETAPES ({num_stages} etape(s), {self.algorithm})".ljust(76) + " │")
            logger.info("└" + "─" * 78 + "┘")

            # Convertir les donnees en bytes si necessaire
            if isinstance(data, str):
                data = data.encode("utf-8")

            logger.info("📦 Donnees originales: {} octets".format(len(data)))
            if len(data) > 50:
                logger.info("   Contenu: {}...".format(data[:50]))
            else:
                logger.info("   Contenu: {}".format(data))

            # Padding
            logger.info("\n▶ 1. APPLICATION DU PADDING")
            logger.info("  " + "─" * 76)
            padded_data = self.pad_data(data)

            # Chiffrement multi-etapes
            encrypted_data = padded_data
            logger.info("\n▶ 2. ETAPES DE CHIFFREMENT {} ".format(self.algorithm))
            logger.info("  " + "─" * 76)

            for stage in range(1, num_stages + 1):
                key = self.keys[stage - 1]
                encrypted_data = self.encrypt_stage(encrypted_data, key, stage)

            logger.info("\n╔" + "=" * 78 + "╗")
            logger.info("║ " + "[✓] CHIFFREMENT TERMINE AVEC SUCCES".ljust(76) + " ║")
            logger.info("╚" + "=" * 78 + "╝")

            return encrypted_data

    def decrypt_stage(self, data, key, stage_number, total_stages):
        """Effectue une etape de dechiffrement DES ou AES"""
        try:
            logger.info("")
            logger.info("  ╔═══ ETAPE {} DE DECHIFFREMENT ({}) ═══╗".format(stage_number, self.algorithm))

            key_b64 = base64.b64encode(key).decode()
            logger.info("    🔑 Cle utilisee: {}".format(key_b64))
            logger.info("       Donnees a dechiffrer: {} octets".format(len(data)))

            # Dechiffrement selon l'algorithme
            if self.algorithm == "DES":
                des_cipher = DES3.new(key, DES3.MODE_ECB)
                decrypted_data = des_cipher.decrypt(data)
            elif self.algorithm == "AES":
                aes_cipher = AES.new(key, AES.MODE_ECB)
                decrypted_data = aes_cipher.decrypt(data)
            else:
                raise ValueError("Algorithme non supporté: {}".format(self.algorithm))

            logger.info(
                "    ✓ Donnees dechiffrees: {} octets".format(len(decrypted_data))
            )

            return decrypted_data

        except Exception as e:
            logger.error(
                "[ERREUR] Erreur lors du dechiffrement etape {}: {}".format(
                    stage_number, str(e)
                )
            )
            raise

    def decrypt_data(self, encrypted_data):
        """
        Applique les etapes de dechiffrement dans l'ordre inverse
        """
        if self.sensitivity_level is None:
            raise ValueError("Le niveau de sensibilite doit d'abord etre defini")

        num_stages = self.SENSITIVITY_LEVELS[self.sensitivity_level]["stages"]

        with PerformanceTimer("Dechiffrage") as timer:
            self.timers['decrypt'] = timer
            
            logger.info("\n┌" + "─" * 78 + "┐")
            logger.info("│ " + f"PROCESSUS DE DECHIFFREMENT ({num_stages} etape(s), {self.algorithm})".ljust(76) + " │")
            logger.info("└" + "─" * 78 + "┘")

            logger.info("🔒 Donnees chiffrees recues: {} octets".format(len(encrypted_data)))

            # Dechiffrement en ordre inverse
            decrypted_data = encrypted_data
            logger.info("\n▶ 2. ETAPES DE DECHIFFREMENT {} (ordre inverse)".format(self.algorithm))
            logger.info("  " + "─" * 76)

            for stage in range(num_stages, 0, -1):
                key = self.keys[stage - 1]
                decrypted_data = self.decrypt_stage(
                    decrypted_data, key, num_stages - stage + 1, num_stages
                )

            # Suppression du padding
            logger.info("\n▶ 1. SUPPRESSION DU PADDING")
            logger.info("  " + "─" * 76)
            block_size = self.AES_BLOCK_SIZE if self.algorithm == "AES" else self.DES_BLOCK_SIZE
            unpadded_data = unpad(decrypted_data, block_size)
            padding_length = len(decrypted_data) - len(unpadded_data)
            logger.info("  Padding detecte: {} octets".format(padding_length))
            logger.info(
                "  Donnees apres suppression du padding: {} octets".format(
                    len(unpadded_data)
                )
            )

            logger.info("\n╔" + "=" * 78 + "╗")
            logger.info("║ " + "[✓] DECHIFFREMENT TERMINE AVEC SUCCES".ljust(76) + " ║")
            logger.info("╚" + "=" * 78 + "╝")

            return unpadded_data

    def run_demonstration(
        self, auto_test=False, sensitivity_level=None, test_data=None, algorithm=None, input_file=None
    ):
        """Execute une demonstration complete du systeme"""
        with PerformanceTimer("Execution totale") as timer:
            self.timers['total'] = timer
            
            logger.info("\n\n")
            logger.info("╔" + "=" * 78 + "╗")
            logger.info("║ " + "DEMONSTRATION DU SYSTEME DE CHIFFREMENT MULTI-ETAPES".center(76) + " ║")
            logger.info("╚" + "=" * 78 + "╝")

            # Etape 0: Choisir l'algorithme
            if auto_test and algorithm:
                self.algorithm = algorithm
                logger.info("[TEST] Algorithme selectionne: {}".format(algorithm))
            else:
                self.ask_algorithm()

            # Etape 1: Demander le niveau de sensibilite
            if auto_test and sensitivity_level:
                self.sensitivity_level = sensitivity_level
                level_info = self.SENSITIVITY_LEVELS[sensitivity_level]
                logger.info(
                    "[TEST] Niveau de sensibilite selectionne: {} ({})".format(
                        sensitivity_level, level_info["name"]
                    )
                )
                logger.info("  - {}".format(level_info["description"]))
                logger.info(
                    "  - Nombre d'etapes d'encryptage: {}\n".format(level_info["stages"])
                )
            else:
                self.ask_sensitivity_level()

            # Etape 2: Generer les cles
            self.generate_keys()

            # Etape 3: Demander les donnees a chiffrer
            logger.info("\n┌" + "─" * 78 + "┐")
            logger.info("│ " + "SAISIE DES DONNEES A CHIFFRER".ljust(76) + " │")
            logger.info("└" + "─" * 78 + "┘")
            
            if auto_test and test_data:
                data = test_data
                logger.info("[TEST] Donnees de test: {}".format(data))
            elif input_file:
                logger.info("[FICHIER] Lecture depuis: {}".format(input_file))
                data = self.read_file_data(input_file)
                if data is None:
                    raise ValueError("Impossible de lire le fichier: {}".format(input_file))
            else:
                # Mode interactif
                source = self.ask_data_source()
                if source == "manual":
                    data = input("Entrez le texte a chiffrer: ")
                else:
                    while True:
                        filepath = input("Entrez le chemin du fichier: ").strip()
                        data = self.read_file_data(filepath)
                        if data is not None:
                            break
                        print("Veuillez entrer un chemin valide.")
            
            self.data_to_encrypt = data

            # Etape 4: Chiffrer les donnees
            encrypted = self.encrypt_data(data)

            # Afficher le resultat
            logger.info("\n┌" + "─" * 78 + "┐")
            logger.info("│ " + "RESULTAT DU CHIFFREMENT".ljust(76) + " │")
            logger.info("└" + "─" * 78 + "┘")
            encrypted_b64 = base64.b64encode(encrypted).decode()
            logger.info("🔐 Donnees chiffrees (base64): {}".format(encrypted_b64[:100]))
            if len(encrypted_b64) > 100:
                logger.info("   ... (affichage tronque)")
            logger.info("   Taille: {} octets".format(len(encrypted)))

            # Etape 5: Dechiffrer pour verification
            logger.info("")
            logger.info("┌" + "─" * 78 + "┐")
            logger.info("│ " + "VERIFICATION PAR DECHIFFREMENT".ljust(76) + " │")
            logger.info("└" + "─" * 78 + "┘")
            decrypted = self.decrypt_data(encrypted)

            # Afficher les resultats de verification
            logger.info("\n┌" + "─" * 78 + "┐")
            logger.info("│ " + "RESULTATS DE LA VERIFICATION".ljust(76) + " │")
            logger.info("└" + "─" * 78 + "┘")
            try:
                decrypted_text = decrypted.decode("utf-8")
                
                # Afficher un extrait si le texte est trop long
                if len(decrypted_text) > 100:
                    logger.info("✓ Donnees dechiffrees: {}...".format(decrypted_text[:100]))
                else:
                    logger.info("✓ Donnees dechiffrees: {}".format(decrypted_text))

                if decrypted_text == data:
                    logger.info("╔" + "=" * 78 + "╗")
                    logger.info("║ " + "[✓] VERIFICATION REUSSIE: Les donnees correspondent!".ljust(76) + " ║")
                    logger.info("╚" + "=" * 78 + "╝")
                else:
                    logger.error("[✗] ERREUR: Les donnees ne correspondent pas!")
            except Exception as e:
                logger.error("[✗] Erreur lors du decodage: {}".format(str(e)))

            # Afficher le rapport de performance
            logger.info("\n╔" + "=" * 78 + "╗")
            logger.info("║ " + "RAPPORT DE PERFORMANCE".center(76) + " ║")
            logger.info("║" + "─" * 78 + "║")
            
            if self.timers['encrypt'] and self.timers['encrypt'].duration:
                logger.info("║ ⏱️  " + self.timers['encrypt'].get_report().ljust(74) + " ║")
            if self.timers['decrypt'] and self.timers['decrypt'].duration:
                logger.info("║ ⏱️  " + self.timers['decrypt'].get_report().ljust(74) + " ║")
            if self.timers['total'] and self.timers['total'].duration:
                logger.info("║ ⏱️  " + self.timers['total'].get_report().ljust(74) + " ║")
            
            logger.info("╚" + "=" * 78 + "╝")
            logger.info(
                "📄 Le fichier 'encryption_process.log' contient tous les details du processus"
            )


def main():
    """Fonction principale"""
    import sys

    # Supporter les arguments en ligne de commande pour les tests
    auto_test = "--auto" in sys.argv or "--test" in sys.argv
    sensitivity_level = None
    test_data = None
    algorithm = None
    input_file = None

    # Parser les arguments
    for i, arg in enumerate(sys.argv[1:]):
        if arg == "--level" and i + 1 < len(sys.argv) - 1:
            try:
                sensitivity_level = int(sys.argv[i + 2])
            except:
                pass
        elif arg == "--data" and i + 1 < len(sys.argv) - 1:
            test_data = sys.argv[i + 2]
        elif arg == "--algo" and i + 1 < len(sys.argv) - 1:
            algo_arg = sys.argv[i + 2].upper()
            if algo_arg in ["DES", "AES"]:
                algorithm = algo_arg
        elif arg == "--file" and i + 1 < len(sys.argv) - 1:
            input_file = sys.argv[i + 2]

    try:
        encryptor = SensitivityBasedEncryption()
        encryptor.run_demonstration(
            auto_test=auto_test,
            sensitivity_level=sensitivity_level,
            test_data=test_data,
            algorithm=algorithm,
            input_file=input_file,
        )

        logger.info("\n╔" + "=" * 78 + "╗")
        logger.info("║ " + "DEMONSTRATION TERMINEE AVEC SUCCES".center(76) + " ║")
        logger.info("╚" + "=" * 78 + "╝")

    except KeyboardInterrupt:
        logger.warning("\n\n[⚠️ ARRET] Demonstration interrompue par l'utilisateur")
        print("\n\nDemonstration interrompue.")
    except Exception as e:
        logger.error("\n\n[❌ ERREUR CRITIQUE] {}".format(str(e)))
        print("\n\nErreur: {}".format(str(e)))
        sys.exit(1)


if __name__ == "__main__":
    main()
