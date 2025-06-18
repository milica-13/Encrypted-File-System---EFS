import random
from key_manager import KeyManager

class CertificateManager:
    ENCRYPTION_ALGORITHMS = ['RSA']  # Ostavljen samo RSA za sada, može se proširiti.

    @staticmethod
    def generate_certificate(username):
        """Bira algoritam i osigurava da se koriste isti ključevi za sertifikat."""
        algorithm = random.choice(CertificateManager.ENCRYPTION_ALGORITHMS)

        if algorithm == 'RSA':
            private_key_path, public_key_path = KeyManager.generate_rsa_keys(username)
            return private_key_path, public_key_path

        raise ValueError("Nepodržani algoritam!")
