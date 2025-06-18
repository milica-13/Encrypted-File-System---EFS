import os
import json
import random
import hashlib
import base64
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from certificate_authority import CertificateAuthority
from key_manager import KeyManager  # Koristimo KeyManager za generisanje ključeva

class User:
    HASH_ALGORITHMS = ['sha256', 'sha512', 'blake2b']   
    USER_FILE = "file_system/user.json"

    @staticmethod
    def hash_password(password, algo):
        """Generiše hash lozinke koristeći definisani algoritam."""
        if algo == 'sha256':
            hashed = hashlib.sha256(password.encode()).hexdigest()
        elif algo == 'sha512':
            hashed = hashlib.sha512(password.encode()).hexdigest()
        else:
            hashed = hashlib.blake2b(password.encode()).hexdigest()
    
        return hashed  # Nema više base64 enkodiranja!


    def register_user(username, password):
        """Registruje novog korisnika, generiše ključeve i izdaje sertifikat."""
        if not os.path.exists("file_system"):
            os.makedirs("file_system")

        users = {}
        if os.path.exists(User.USER_FILE) and os.path.getsize(User.USER_FILE) > 0:
            with open(User.USER_FILE, "r") as f:
                try:
                    users = json.load(f)
                except json.JSONDecodeError:
                    print("⚠️ GRESKA! Nevalidan JSON format. Kreiramo novi fajl.")
                    users = {}

        if username in users:
            print("🚫 Korisnik već postoji!")
            return

        hash_algo = 'sha256'  # UVEK koristimo isti algoritam!
        hashed_password = User.hash_password(password, hash_algo)

        user_folder = f"file_system/{username}"
        os.makedirs(user_folder, exist_ok=True)

        # Generisanje ključeva putem KeyManager-a
        private_key_path, public_key_path = KeyManager.generate_rsa_keys(username)

        # Čuvanje korisnika
        users[username] = {
            "password": hashed_password,
            "hash_algo": hash_algo,  # Sada čuvamo tačno koji je algoritam korišćen
            "public_key": public_key_path,
            "private_key": private_key_path,
            "certificate": f"{user_folder}/certificate.pem"
        }

        with open(User.USER_FILE, "w") as f:
            json.dump(users, f, indent=4)

        # Izdavanje sertifikata
        CertificateAuthority.issue_certificate(username)

        print(f"✅ Korisnik {username} uspešno registrovan!")

    @staticmethod
    def login(username, password):
        """Proverava lozinku, sertifikat i ključeve pri prijavi."""
        if not os.path.exists(User.USER_FILE):
            print("🚫 Fajl sa korisnicima ne postoji!")
            return False

        with open(User.USER_FILE, "r") as f:
            try:
                users = json.load(f)
            except json.JSONDecodeError:
                print("⚠️ GRESKA! JSON fajl je oštećen!")
                return False

        if username not in users:
            print("🚫 Korisnik ne postoji!")
            return False

        if not CertificateAuthority.validate_certificate(username):  
            print("❌ Prijava neuspešna - nevalidan sertifikat!")  
            return False
        
        user_data = users[username]
    
        # Dodaj debug print za proveru
        #print(f"🔍 Sačuvana lozinka: {user_data['password']}")
        #print(f"🔍 Korisćeni hash algoritam: {user_data['hash_algo']}")

        hashed_password = User.hash_password(password, user_data["hash_algo"])

        #print(f"🔍 Unesena hashirana lozinka: {hashed_password}")

        if user_data["password"] != hashed_password:
            print("🚫 Pogrešna lozinka!")
            return False

        print(f"✅ Korisnik {username} uspešno prijavljen!")
        return True

    @staticmethod
    def logout():
        global logged_in_user
        logged_in_user = None
        print("👋 Uspješno ste se odjavili.")


"""     @staticmethod
    def hash_password(password, algo):
        if algo == 'sha256':
            hashed = hashlib.sha256(password.encode()).digest()
        elif algo == 'sha512':
            hashed = hashlib.sha512(password.encode()).digest()
        else:
            hashed = hashlib.blake2b(password.encode()).digest()
        return base64.b64encode(hashed).decode()

    @staticmethod
    def register_user(username, password):
        if not os.path.exists("file_system"):
            os.makedirs("file_system")

        users = {}
        if os.path.exists(User.USER_FILE) and os.path.getsize(User.USER_FILE) > 0:
            with open(User.USER_FILE, "r") as f:
                try:
                    users = json.load(f)
                except json.JSONDecodeError:
                    print("⚠️ GRESKA! Nevalidan JSON format. Kreiramo novi fajl.")
                    users = {}
        
        if username in users:
            print("🚫 Korisnik već postoji!")
            return

        hashed_password = User.hash_password(password, random.choice(User.HASH_ALGORITHMS))
        user_folder = f"file_system/{username}"
        os.makedirs(user_folder, exist_ok=True)

        # Generisanje ključeva putem KeyManager-a
        private_key_path, public_key_path = KeyManager.generate_rsa_keys(username)

        # Čuvanje korisnika
        users[username] = {
            "password": hashed_password,
            "hash_algo": 'sha256',  # Postavljamo podrazumevani algoritam
            "public_key": public_key_path,
            "private_key": private_key_path,
            "certificate": f"{user_folder}/certificate.pem"
        }

        with open(User.USER_FILE, "w") as f:
            json.dump(users, f, indent=4)

        # Izdavanje sertifikata
        CertificateAuthority.issue_certificate(username)

        print(f"✅ Korisnik {username} uspešno registrovan!")

    @staticmethod
    def login(username, password):
        if not os.path.exists(User.USER_FILE):
            print("🚫 Fajl sa korisnicima ne postoji!")
            return False

        with open(User.USER_FILE, "r") as f:
            try:
                users = json.load(f)
            except json.JSONDecodeError:
                print("⚠️ GRESKA! JSON fajl je oštećen!")
                return False

        if username not in users:
            print("🚫 Korisnik ne postoji!")
            return False

        user_data = users[username]
        hashed_password = User.hash_password(password, user_data["hash_algo"])

        if user_data["password"] != hashed_password:
            print("🚫 Pogrešna lozinka!")
            return False

        # Provera sertifikata
        cert_path = user_data["certificate"]
        ca_cert_path = "certificates/ca_cert.pem"

        if not os.path.exists(cert_path):
            print("🚫 Sertifikat ne postoji!")
            return False

        with open(cert_path, "rb") as f:
            user_cert = x509.load_pem_x509_certificate(f.read())

        with open(ca_cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())

        if user_cert.issuer != ca_cert.subject:
            print("🚫 Nevalidan sertifikat!")
            return False

        # Provera ključeva
        private_key_path = user_data["private_key"]
        public_key_path = user_data["public_key"]

        if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
            print("🚫 Privatni ili javni ključ ne postoji.")
            return False

        try:
            with open(private_key_path, "rb") as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)

            with open(public_key_path, "rb") as f:
                public_key = serialization.load_pem_public_key(f.read())

            test_message = b"test"
            signature = private_key.sign(
                test_message,
                padding.PKCS1v15(),
                hashes.SHA256()
            )

            public_key.verify(
                signature,
                test_message,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        except Exception as e:
            print("🚫 Nevalidan privatni ključ:", e)
            return False

        print(f"✅ Korisnik {username} uspešno prijavljen!")
        return True """
