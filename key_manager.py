import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

class KeyManager:
    CERTIFICATE_PATH = "certificates"  # Folder za sertifikate
    USER_KEYS_PATH = "file_system"  # Folder za korisničke ključeve

    @staticmethod
    def _key_paths(username):
        """Vraća putanje privatnog i javnog ključa korisnika u korisničkom folderu."""
        user_dir = f"{KeyManager.USER_KEYS_PATH}/{username}"
        os.makedirs(user_dir, exist_ok=True)  # Osiguravamo da folder postoji
        return (f"{user_dir}/private_key.pem", f"{user_dir}/public_key.pem")

    @staticmethod
    def generate_rsa_keys(username):
        """Generiše RSA ključeve samo ako ne postoje u korisničkom folderu."""
        private_key_path, public_key_path = KeyManager._key_paths(username)

        if os.path.exists(private_key_path) and os.path.exists(public_key_path):
            print(f"🔑 Ključevi za {username} već postoje.")
            return private_key_path, public_key_path

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        with open(private_key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        with open(public_key_path, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        print(f"✅ RSA ključevi generisani za {username}.")
        return private_key_path, public_key_path
