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
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

# Configuration du logging detaille avec UTF-8
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - [%(funcName)s] - %(message)s",
    handlers=[
        logging.FileHandler("encryption_process.log", encoding="utf-8", mode="w"),
    ],
)

# Ajouter un handler console
console_handler = logging.StreamHandler()
console_handler.setFormatter(
    logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
)
logging.getLogger().addHandler(console_handler)

logger = logging.getLogger(__name__)


class SensitivityBasedEncryption:
    """
    Classe qui gere le chiffrement multi-etapes selon le niveau de sensibilite
    """

    # Mapping des niveaux de sensibilite
    SENSITIVITY_LEVELS = {
        1: {
            "name": "Bas",
            "stages": 1,
            "description": "1 etape de chiffrement DES",
            "key_size": 16,
        },
        2: {
            "name": "Moyen",
            "stages": 2,
            "description": "2 etapes de chiffrement DES",
            "key_size": 16,
        },
        3: {
            "name": "Haut/Critique",
            "stages": 3,
            "description": "Triple DES (3 etapes)",
            "key_size": 24,
        },
    }

    DES_BLOCK_SIZE = 8  # DES fonctionne avec des blocs de 8 octets

    def __init__(self):
        logger.info("=" * 80)
        logger.info("INITIALISATION DU SYSTEME DE CHIFFREMENT MULTI-ETAPES")
        logger.info("=" * 80)
        self.keys = []
        self.sensitivity_level = None
        self.data_to_encrypt = None

    def display_sensitivity_levels(self):
        """Affiche les niveaux de sensibilite disponibles"""
        logger.info("\n" + "=" * 80)
        logger.info("NIVEAUX DE SENSIBILITE DISPONIBLES")
        logger.info("=" * 80)
        for level, info in self.SENSITIVITY_LEVELS.items():
            logger.info("Niveau {}: {}".format(level, info["name"]))
            logger.info("  - Description: {}".format(info["description"]))
            logger.info("  - Nombre d'etapes: {}".format(info["stages"]))
            logger.info("  - Taille de cle: {} octets".format(info["key_size"]))
        logger.info("=" * 80 + "\n")

    def ask_sensitivity_level(self):
        """Demande a l'utilisateur le niveau de sensibilite"""
        logger.info("DEMANDE DU NIVEAU DE SENSIBILITE")
        logger.info("-" * 80)
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
                        "[OK] Niveau de sensibilite selectionne: {} ({})".format(
                            level, level_info["name"]
                        )
                    )
                    logger.info("  - {}".format(level_info["description"]))
                    logger.info(
                        "  - Nombre d'etapes d'encryptage: {}\n".format(
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

        logger.info("\n" + "=" * 80)
        logger.info(
            "GENERATION DES CLES D'ENCRYPTAGE ({} cle(s), {} octets chacune)".format(
                num_stages, key_size
            )
        )
        logger.info("=" * 80)

        self.keys = []
        for i in range(1, num_stages + 1):
            key = self.generate_des_key(i, key_size)
            self.keys.append(key)

        logger.info("[OK] {} cle(s) generee(s) avec succes\n".format(num_stages))

    def pad_data(self, data):
        """
        Ajoute du padding PKCS7 aux donnees pour qu'elles soient un multiple de 8 octets
        """
        block_size = self.DES_BLOCK_SIZE
        padded_data = pad(data, block_size)

        padding_length = len(padded_data) - len(data)
        logger.info("  Padding applique: {} octets ajoutes".format(padding_length))
        logger.info("  Taille avant padding: {} octets".format(len(data)))
        logger.info("  Taille apres padding: {} octets".format(len(padded_data)))

        return padded_data

    def encrypt_stage(self, data, key, stage_number):
        """Effectue une etape de chiffrement DES"""
        try:
            logger.info("")
            logger.info("  [=== ETAPE {} DE CHIFFREMENT ===]".format(stage_number))

            # Affiche les informations de la cle
            key_b64 = base64.b64encode(key).decode()
            logger.info("    Cle utilisee: {}".format(key_b64))
            logger.info("    Taille de la cle: {} octets".format(len(key)))
            logger.info("    Donnees a chiffrer: {} octets".format(len(data)))

            # Creation du chiffre DES3
            des_cipher = DES3.new(key, DES3.MODE_ECB)
            encrypted_data = des_cipher.encrypt(data)

            encrypted_b64 = base64.b64encode(encrypted_data).decode()
            logger.info(
                "    [OK] Donnees chiffrees: {} octets".format(len(encrypted_data))
            )
            logger.info("    [OK] Donnees chiffrees (base64): {}".format(encrypted_b64))

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

        logger.info("\n" + "=" * 80)
        logger.info(
            "PROCESSUS DE CHIFFREMENT MULTI-ETAPES ({} etape(s))".format(num_stages)
        )
        logger.info("=" * 80)

        # Convertir les donnees en bytes si necessaire
        if isinstance(data, str):
            data = data.encode("utf-8")

        logger.info("Donnees originales: {} octets".format(len(data)))
        if len(data) > 50:
            logger.info("Contenu: {}...".format(data[:50]))
        else:
            logger.info("Contenu: {}".format(data))

        # Padding
        logger.info("1. APPLICATION DU PADDING")
        logger.info("-" * 40)
        padded_data = self.pad_data(data)

        # Chiffrement multi-etapes
        encrypted_data = padded_data
        logger.info("2. ETAPES DE CHIFFREMENT DES")
        logger.info("-" * 40)

        for stage in range(1, num_stages + 1):
            key = self.keys[stage - 1]
            encrypted_data = self.encrypt_stage(encrypted_data, key, stage)

        logger.info("\n" + "=" * 80)
        logger.info("[OK] CHIFFREMENT TERMINE AVEC SUCCES")
        logger.info("=" * 80)

        return encrypted_data

    def decrypt_stage(self, data, key, stage_number, total_stages):
        """Effectue une etape de dechiffrement DES"""
        try:
            logger.info("")
            logger.info("  [=== ETAPE {} DE DECHIFFREMENT ===]".format(stage_number))

            key_b64 = base64.b64encode(key).decode()
            logger.info("    Cle utilisee: {}".format(key_b64))
            logger.info("    Donnees a dechiffrer: {} octets".format(len(data)))

            des_cipher = DES3.new(key, DES3.MODE_ECB)
            decrypted_data = des_cipher.decrypt(data)

            logger.info(
                "    [OK] Donnees dechiffrees: {} octets".format(len(decrypted_data))
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

        logger.info("\n" + "=" * 80)
        logger.info("PROCESSUS DE DECHIFFREMENT ({} etape(s))".format(num_stages))
        logger.info("=" * 80)

        logger.info("Donnees chiffrees recues: {} octets".format(len(encrypted_data)))

        # Dechiffrement en ordre inverse
        decrypted_data = encrypted_data
        logger.info("2. ETAPES DE DECHIFFREMENT DES (ordre inverse)")
        logger.info("-" * 40)

        for stage in range(num_stages, 0, -1):
            key = self.keys[stage - 1]
            decrypted_data = self.decrypt_stage(
                decrypted_data, key, num_stages - stage + 1, num_stages
            )

        # Suppression du padding
        logger.info("1. SUPPRESSION DU PADDING")
        logger.info("-" * 40)
        unpadded_data = unpad(decrypted_data, self.DES_BLOCK_SIZE)
        padding_length = len(decrypted_data) - len(unpadded_data)
        logger.info("  Padding detecte: {} octets".format(padding_length))
        logger.info(
            "  Donnees apres suppression du padding: {} octets".format(
                len(unpadded_data)
            )
        )

        logger.info("\n" + "=" * 80)
        logger.info("[OK] DECHIFFREMENT TERMINE AVEC SUCCES")
        logger.info("=" * 80)

        return unpadded_data

    def run_demonstration(
        self, auto_test=False, sensitivity_level=None, test_data=None
    ):
        """Execute une demonstration complete du systeme"""
        logger.info("\n\n")
        logger.info("#" * 80)
        logger.info("# DEMONSTRATION DU SYSTEME DE CHIFFREMENT MULTI-ETAPES")
        logger.info("#" * 80)

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
        logger.info("\n" + "=" * 80)
        logger.info("SAISIE DES DONNEES A CHIFFRER")
        logger.info("=" * 80)
        if auto_test and test_data:
            data = test_data
            logger.info("[TEST] Donnees de test: {}".format(data))
        else:
            data = input("Entrez le texte a chiffrer: ")
        self.data_to_encrypt = data

        # Etape 4: Chiffrer les donnees
        encrypted = self.encrypt_data(data)

        # Afficher le resultat
        logger.info("\n" + "=" * 80)
        logger.info("RESULTAT DU CHIFFREMENT")
        logger.info("=" * 80)
        encrypted_b64 = base64.b64encode(encrypted).decode()
        logger.info("Donnees chiffrees (base64): {}".format(encrypted_b64))
        logger.info("Taille: {} octets".format(len(encrypted)))

        # Etape 5: Dechiffrer pour verification
        logger.info("")
        logger.info("=" * 80)
        logger.info("VERIFICATION PAR DECHIFFREMENT")
        logger.info("=" * 80)
        decrypted = self.decrypt_data(encrypted)

        # Afficher les resultats de verification
        logger.info("\n" + "=" * 80)
        logger.info("RESULTATS DE LA VERIFICATION")
        logger.info("=" * 80)
        try:
            decrypted_text = decrypted.decode("utf-8")
            logger.info("Donnees dechiffrees: {}".format(decrypted_text))

            if decrypted_text == data:
                logger.info("[OK] VERIFICATION REUSSIE: Les donnees correspondent!")
            else:
                logger.error("[ERREUR] Les donnees ne correspondent pas!")
        except Exception as e:
            logger.error("[ERREUR] Erreur lors du decodage: {}".format(str(e)))

        logger.info("=" * 80)
        logger.info(
            "Le fichier 'encryption_process.log' contient tous les details du processus"
        )


def main():
    """Fonction principale"""
    import sys

    # Supporter les arguments en ligne de commande pour les tests
    auto_test = "--auto" in sys.argv or "--test" in sys.argv
    sensitivity_level = None
    test_data = None

    # Parser les arguments
    for i, arg in enumerate(sys.argv[1:]):
        if arg == "--level" and i + 1 < len(sys.argv) - 1:
            try:
                sensitivity_level = int(sys.argv[i + 2])
            except:
                pass
        elif arg == "--data" and i + 1 < len(sys.argv) - 1:
            test_data = sys.argv[i + 2]

    try:
        encryptor = SensitivityBasedEncryption()
        encryptor.run_demonstration(
            auto_test=auto_test,
            sensitivity_level=sensitivity_level,
            test_data=test_data,
        )

        logger.info("\n" + "#" * 80)
        logger.info("# DEMONSTRATION TERMINEE AVEC SUCCES")
        logger.info("#" * 80)

    except KeyboardInterrupt:
        logger.warning("\n\n[ARRET] Demonstration interrompue par l'utilisateur")
        print("\n\nDemonstration interrompue.")
    except Exception as e:
        logger.error("\n\n[ERREUR CRITIQUE] {}".format(str(e)))
        print("\n\nErreur: {}".format(str(e)))
        sys.exit(1)


if __name__ == "__main__":
    main()
