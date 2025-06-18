import os
import hashlib
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding

""" def generate_keys():
    if not os.path.exists("private_key.pem") or not os.path.exists("public_key.pem"):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()

        with open("private_key.pem", "wb") as priv_file:
            priv_file.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        with open("public_key.pem", "wb") as pub_file:
            pub_file.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )) """

from key_manager import KeyManager

def load_keys(username):
    private_key_path, public_key_path = KeyManager._key_paths(username)

    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(), password=None
        )

    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read()
        )

    return private_key, public_key


def generate_hash(file_path):
    try:
        with open(file_path, "rb") as f:
            file_data = f.read()
        file_hash = hashlib.sha256(file_data).digest()
        return file_hash
    except Exception as e:
        print(f"Greška pri generisanju hasha fajla: {e}")
        return None

def sign_file(username, filename):
    file_path = os.path.join("file_system", username, filename)
    private_key, public_key = load_keys(username)
    #print("Kljucevi prije potpisivanja ucitani sa load keys:")
    #print(private_key, public_key)

    if not os.path.exists(file_path):
        print("Fajl ne postoji!")
        return
    
    private_key, _ = load_keys(username)
    
    file_hash = generate_hash(file_path)
    #print("Hash fajla pre potpisivanja:", file_hash)

    if file_hash is None:
        return
    
    try:
        signature = private_key.sign(
            file_hash,
            asym_padding.PKCS1v15(),  
            hashes.SHA256()
        )

        signature_path = file_path + ".sig"
        with open(signature_path, "wb") as sig_file:
            sig_file.write(signature)
        print(f"Potpis sačuvan: {signature_path}")
    except Exception as e:
        print(f"Greška pri potpisivanju fajla: {e}")

def verify_file(sender_username, filename):
    if not filename.endswith(".txt"):
        filename += ".txt"

    # Potpis se nalazi kod pošiljaoca
    sig_path = f"file_system/{sender_username}/{filename}.sig"
    if not os.path.exists(sig_path):
        print(f"❌ Greška: Potpisni fajl {sig_path} ne postoji!")
        return False

    # ✅ Učitavanje javnog ključa pošiljaoca (verifikacija koristi *javni* ključ)
    _, public_key = load_keys(sender_username)

    #print(f"✅ Koristimo sledeći javni ključ pošiljaoca ({sender_username}) za verifikaciju:\n  Javni ključ: {public_key}\n")

    # Učitavanje potpisa
    with open(sig_path, "rb") as f:
        signature = f.read()

    # Učitavanje originalnog fajla pošiljaoca
    file_path = f"file_system/{sender_username}/{filename}"
    if not os.path.exists(file_path):
        print(f"❌ Greška: Originalni fajl {file_path} ne postoji!")
        return False

    file_hash = generate_hash(file_path)

    try:
        public_key.verify(
            signature,
            file_hash,
            asym_padding.PKCS1v15(),
            hashes.SHA256()
        )
        print(f"✅ Potpis je validan!")
        return True
    except Exception as e:
        print("❌ Potpis nije validan:", e)
        return False


""" 
def verify_file(username, filename):
    if not filename.endswith(".txt"):
        filename += ".txt"

    sig_path = f"file_system/{username}/{filename}.sig"
    if not os.path.exists(sig_path):
        print(f"❌ Greška: Potpisni fajl {sig_path} ne postoji!")
        return False

    # ✅ Učitavanje ključeva
    private_key, public_key = load_keys(username)

    print(f"✅ Koristimo sledeće ključeve za verifikaciju:\n  Privatni ključ: {private_key}\n  Javni ključ: {public_key}\n")

    with open(sig_path, "rb") as f:
       signature = f.read()

    file_path = f"file_system/{username}/{filename}"
    with open(file_path, "rb") as f:
        file_data = f.read()
        file_hash = generate_hash(file_path)

    try:
        public_key.verify(
                         signature,
             file_hash,
             asym_padding.PKCS1v15(),  # 📌 Promeni da bude isto kao u sign_file()
             hashes.SHA256()
         )
        print(f"✅ Potpis je validan! Sadržaj fajla:\n{file_data.decode()}")
        return True
    except Exception as e:
         print("❌ Potpis nije validan:", e)
         return False

 """