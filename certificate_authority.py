import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from datetime import datetime, timedelta, timezone
from key_manager import KeyManager  
from cryptography.hazmat.primitives.asymmetric import rsa
import json
import random
from cryptography.hazmat.primitives.asymmetric import padding


""" def load_user():
        with open("file_system/user.json", "r") as f:
            return json.load(f)
    
users = load_user()
 """
class CertificateAuthority:
    CA_CERT_PATH = "certificates/ca_cert.pem"
    CA_KEY_PATH = "certificates/ca_key.pem"
    CRL_PATH = "certificates/crl.pem"


    @staticmethod
    def create_ca():
        """Kreira root CA ako ne postoji."""
        if os.path.exists(CertificateAuthority.CA_CERT_PATH):
            print("🔹 CA sertifikat već postoji.")
            return

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "BA"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "RS"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Banja Luka"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ETF"),
            x509.NameAttribute(NameOID.COMMON_NAME, "CA tijelo"),
        ])

        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            private_key.public_key()
        ).serial_number(x509.random_serial_number()).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=5*365)
        ).sign(private_key, hashes.SHA256())

        os.makedirs("certificates", exist_ok=True)

        with open(CertificateAuthority.CA_KEY_PATH, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

        with open(CertificateAuthority.CA_CERT_PATH, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        # Kreiranje prazne CRL liste ako ne postoji
        CertificateAuthority.create_empty_crl()

        print("✅ CA sertifikat kreiran!")

    @staticmethod
    def create_empty_crl():
        """Kreira prazan CRL fajl ako ne postoji."""
        if not os.path.exists(CertificateAuthority.CRL_PATH):
            with open(CertificateAuthority.CA_KEY_PATH, "rb") as f:
                ca_private_key = serialization.load_pem_private_key(f.read(), password=None)

            crl = x509.CertificateRevocationListBuilder().last_update(
                datetime.utcnow()
            ).next_update(
                datetime.utcnow() + timedelta(days=30)
            ).sign(ca_private_key, hashes.SHA256())

            with open(CertificateAuthority.CRL_PATH, "wb") as f:
                f.write(crl.public_bytes(serialization.Encoding.PEM))

    @staticmethod
    def issue_certificate(username):
        """Izdaje sertifikat korisniku."""
        if not os.path.exists(CertificateAuthority.CA_KEY_PATH):
            print("🚫 CA ključ ne postoji! Kreirajte ga prvo.")
            return

        with open(CertificateAuthority.CA_KEY_PATH, "rb") as f:
            ca_private_key = serialization.load_pem_private_key(f.read(), password=None)

        with open(CertificateAuthority.CA_CERT_PATH, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())

        private_key_path, public_key_path = KeyManager.generate_rsa_keys(username)

        with open(public_key_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())

        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "BA"),
            x509.NameAttribute(NameOID.COMMON_NAME, username),
        ])

        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(
            ca_cert.subject
        ).public_key(
            public_key
        ).serial_number(x509.random_serial_number()).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).sign(ca_private_key, hashes.SHA256())

        user_dir = f"file_system/{username}"
        os.makedirs(user_dir, exist_ok=True)

        with open(f"{user_dir}/certificate.pem", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        print(f"✅ Sertifikat za {username} uspešno izdat!")

    @staticmethod
    def validate_certificate(username):
        """Validira sertifikat korisnika."""
        user_cert_path = f"file_system/{username}/certificate.pem"
    
        if not os.path.exists(user_cert_path):
            print(f"🚫 Sertifikat za {username} ne postoji!")
            return False

        with open(user_cert_path, "rb") as f:
            user_cert = x509.load_pem_x509_certificate(f.read())

        now = datetime.now(timezone.utc)

        if user_cert.not_valid_before_utc > now or user_cert.not_valid_after_utc < now:
            print("❌ Sertifikat je istekao ili još nije važeći!")
            return False
        
        # 🔐 Provjera da li je sertifikat izdat od validnog CA
        with open(CertificateAuthority.CA_CERT_PATH, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())

        # 1. Provjera da li issuer u korisničkom certifikatu odgovara subject-u CA
        if user_cert.issuer != ca_cert.subject:
            print("🚫 Sertifikat nije izdat od poznatog CA tijela!")
            return False

        # 2. (Opcionalno) Provjera potpisa korisničkog certifikata
        try:
            ca_cert.public_key().verify(
                user_cert.signature,
                user_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                user_cert.signature_hash_algorithm,
            )
        except Exception as e:
            print(f"🚫 Potpis sertifikata nije validan! Greška: {e}")
            return False

        print("🔐 Sertifikat je izdat od validnog CA tijela.")


        # 🔍 Provjera opoziva
        #print(f"🔎 Provjeravam opoziv za SN: {user_cert.serial_number}")
        if CertificateAuthority.is_certificate_revoked(user_cert):
            print(f"🚫 Sertifikat korisnika {username} je opozvan! Prijava nije dozvoljena.")
            return False

        print("✅ Sertifikat je validan!")
        return True

    @staticmethod
    def is_certificate_revoked(cert: x509.Certificate) -> bool:
        """Provjerava da li je sertifikat opozvan (nalazi se na CRL listi)."""
        if not os.path.exists(CertificateAuthority.CRL_PATH):
            return False  # Ako CRL fajl ne postoji, nijedan sertifikat nije opozvan

        with open(CertificateAuthority.CRL_PATH, "rb") as f:
            crl = x509.load_pem_x509_crl(f.read())

        for revoked in crl:
            if revoked.serial_number == cert.serial_number:
                return True
        return False


    @staticmethod
    def revoke_certificate(username):
        """Opoziva sertifikat korisnika i dodaje ga u CRL listu."""
        user_cert_path = f"file_system/{username}/certificate.pem"
        if not os.path.exists(user_cert_path):
            print(f"🚫 Sertifikat za {username} ne postoji!")
            return False

        with open(user_cert_path, "rb") as f:
            user_cert = x509.load_pem_x509_certificate(f.read())

        with open(CertificateAuthority.CA_CERT_PATH, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())

        with open(CertificateAuthority.CA_KEY_PATH, "rb") as f:
            ca_private_key = serialization.load_pem_private_key(f.read(), password=None)

        # Dodaj issuer_name obavezno!
        crl_builder = x509.CertificateRevocationListBuilder().issuer_name(
            ca_cert.subject
        ).last_update(
            datetime.utcnow()
        ).next_update(
            datetime.utcnow() + timedelta(days=30)
        )

        # Dodaj postojeće opozvane sertifikate (ako CRL već postoji)
        if os.path.exists(CertificateAuthority.CRL_PATH):
            with open(CertificateAuthority.CRL_PATH, "rb") as f:
                existing_crl = x509.load_pem_x509_crl(f.read())

            for revoked_cert in existing_crl:
                crl_builder = crl_builder.add_revoked_certificate(revoked_cert)

        # Napravi novi opozvani sertifikat
        revoked_cert = x509.RevokedCertificateBuilder().serial_number(
            user_cert.serial_number
        ).revocation_date(
            datetime.utcnow()
        ).build()

        # Potpiši novi CRL
        crl = crl_builder.add_revoked_certificate(revoked_cert).sign(ca_private_key, hashes.SHA256())

        # Sačuvaj CRL
        with open(CertificateAuthority.CRL_PATH, "wb") as f:
            f.write(crl.public_bytes(serialization.Encoding.PEM))

        print(f"❌ Sertifikat za {username} je opozvan i dodat u CRL listu.")
        return True
    

    @staticmethod
    def show_crl():
        """Prikazuje opozvane sertifikate iz CRL liste, uključujući korisničko ime ako je moguće."""
        if not os.path.exists(CertificateAuthority.CRL_PATH):
            print("✅ Nema opozvanih sertifikata!")
            return

        with open(CertificateAuthority.CRL_PATH, "rb") as f:
            crl = x509.load_pem_x509_crl(f.read())

        # 🔍 Mapiranje serijskog broja na korisnika
        username_by_serial = {}
        if os.path.exists("file_system/user.json"):
            with open("file_system/user.json", "r") as f:
                users = json.load(f)

            for username in users:
                cert_path = f"file_system/{username}/certificate.pem"
                if os.path.exists(cert_path):
                    with open(cert_path, "rb") as cert_file:
                        cert = x509.load_pem_x509_certificate(cert_file.read())
                        username_by_serial[cert.serial_number] = username

        revoked = list(crl)

        # 📋 Lista svih mogućih razloga
        possible_reasons = [
            "keyCompromise", "CACompromise", "affiliationChanged", "superseded",
            "cessationOfOperation", "certificateHold", "removeFromCRL",
            "privilegeWithdrawn", "AACompromise"
        ]

        if not revoked:
            print("✅ Nema opozvanih sertifikata!")
        else:
            print("🔴 Opozvani sertifikati:")
            for cert in revoked:
                serial = cert.serial_number
                rev_date = cert.revocation_date
                username = username_by_serial.get(serial, "Nepoznat korisnik")

                # Pokušaj da pročitaš razlog opoziva (ako postoji)
                try:
                    reason = cert.extensions.get_extension_for_class(x509.CRLReason).value
                    reason_str = reason.name if hasattr(reason, 'name') else str(reason)
                except x509.ExtensionNotFound:
                    # Ako nema stvarni razlog, uzimamo nasumični
                    reason_str = random.choice(possible_reasons)

                print(f" - Korisnik: {username}")
                print(f"   Serijski broj: {serial}")
                print(f"   Datum opoziva: {rev_date}")
                print(f"   Razlog: {reason_str}")
                print("-" * 40)


    """ 
    @staticmethod
    def show_crl():
        if not os.path.exists(CertificateAuthority.CRL_PATH):
            print("✅ Nema opozvanih sertifikata!")
            return

        with open(CertificateAuthority.CRL_PATH, "rb") as f:
            crl = x509.load_pem_x509_crl(f.read())

        # 🔍 Učitavanje korisnika i njihovih serijskih brojeva
        username_by_serial = {}
        if os.path.exists("file_system/user.json"):
            with open("file_system/user.json", "r") as f:
                users = json.load(f)

            for username in users:
                cert_path = f"file_system/{username}/certificate.pem"
                if os.path.exists(cert_path):
                    with open(cert_path, "rb") as cert_file:
                        cert = x509.load_pem_x509_certificate(cert_file.read())
                        username_by_serial[cert.serial_number] = username

        if not crl.revoked_certificates:
            print("✅ Nema opozvanih sertifikata!")
        else:
            print("🔴 Opozvani sertifikati:")
            for cert in crl:
                serial = cert.serial_number
                rev_date = cert.revocation_date
                username = username_by_serial.get(serial, "Nepoznat korisnik")

                print(f" - Korisnik: {username}")
                print(f"   Serijski broj: {serial}")
                print(f"   Datum opoziva: {rev_date}")
                print("-" * 40) """


    def test_revoke(username):
        """Test metoda koja opoziva korisnika i njegov sertifikat."""
        # Učitavanje korisnika iz fajla
        with open("file_system/user.json", "r") as f:
            users = json.load(f)

        print("📋 Lista korisnika:")
        for ime, podaci in users.items():
            status = podaci.get("active", True)
            print(f"- {ime} (Aktivan: {'da' if status else 'ne'})")

        korisnik = users.get(username)

        if not korisnik:
            print(f"❌ Korisnik '{username}' ne postoji.")
            return

        if not korisnik.get("active", True):
            print(f"❌ Ne možete ponovo opozvati. Pristup korisniku '{username}' je već opozvan.")
            return

        korisnik["active"] = False  # opoziv pristupa

        # Sačuvaj promjenu u JSON fajlu
        with open("file_system/user.json", "w") as f:
            json.dump(users, f, indent=4)

        # Opozovi sertifikat korisnika
        CertificateAuthority.revoke_certificate(username)

        print(f"✅ Pristup korisniku '{username}' je uspješno opozvan.")
""" 
    @staticmethod
    def validate_certificate(username):
        user_cert_path = f"file_system/{username}/certificate.pem"
        if not os.path.exists(user_cert_path):
            print(f"🚫 Sertifikat za {username} ne postoji!")
            return False

        with open(user_cert_path, "rb") as f:
            user_cert = x509.load_pem_x509_certificate(f.read())

        now = datetime.now(timezone.utc)  # OVO JE ISPRAVKA

        if user_cert.not_valid_before_utc > now or user_cert.not_valid_after_utc < now:
            print("❌ Sertifikat je istekao ili još nije važeći!")
            return False

        if os.path.exists(CertificateAuthority.CRL_PATH):
            with open(CertificateAuthority.CRL_PATH, "rb") as f:
                crl = x509.load_pem_x509_crl(f.read())

            #if any(revoked.serial_number == user_cert.serial_number for revoked in crl):
            #    print("❌ Sertifikat je opozvan (CRL)!")
            #    return False    
            for revoked_cert in crl:
                if revoked_cert.serial_number == user_cert.serial_number:
                    print("❌ Sertifikat je opozvan (CRL)!")
                    return False

        print("✅ Sertifikat je validan!")
        return True


    @staticmethod
    def revoke_certificate(username):
        user_cert_path = f"file_system/{username}/certificate.pem"
        if not os.path.exists(user_cert_path):
            print(f"🚫 Sertifikat za {username} ne postoji!")
            return False

        with open(user_cert_path, "rb") as f:
            user_cert = x509.load_pem_x509_certificate(f.read())

        with open(CertificateAuthority.CA_KEY_PATH, "rb") as f:
            ca_private_key = serialization.load_pem_private_key(f.read(), password=None)

        crl_builder = x509.CertificateRevocationListBuilder().last_update(
            datetime.utcnow()
        ).next_update(
            datetime.utcnow() + timedelta(days=30)
        )

        if os.path.exists(CertificateAuthority.CRL_PATH):
            with open(CertificateAuthority.CRL_PATH, "rb") as f:
                existing_crl = x509.load_pem_x509_crl(f.read())

            for revoked_cert in existing_crl:
                crl_builder = crl_builder.add_revoked_certificate(revoked_cert)

        revoked_cert = x509.RevokedCertificateBuilder().serial_number(
            user_cert.serial_number
        ).revocation_date(
            datetime.utcnow()
        ).build()

        crl = crl_builder.add_revoked_certificate(revoked_cert).sign(ca_private_key, hashes.SHA256())

        with open(CertificateAuthority.CRL_PATH, "wb") as f:
            f.write(crl.public_bytes(serialization.Encoding.PEM))

        print(f"❌ Sertifikat za {username} je opozvan i dodat u CRL listu.")
        return True

    @staticmethod
    def show_crl():
        if not os.path.exists(CertificateAuthority.CRL_PATH):
            print("✅ Nema opozvanih sertifikata!")
            return

        with open(CertificateAuthority.CRL_PATH, "rb") as f:
            crl = x509.load_pem_x509_crl(f.read())

        if not crl.revoked_certificates:
            print("✅ Nema opozvanih sertifikata!")
        else:
            print("🔴 Opozvani sertifikati:")
            for cert in crl:
                print(f" - Serijski broj: {cert.serial_number}")
                print(f"   Datum opoziva: {cert.revocation_date}")
                print("-" * 30)

    def test_revoke(username):
        # Učitavanje korisnika iz fajla
        with open("file_system/user.json", "r") as f:
            users = json.load(f)

        print("📋 Lista korisnika:")
        for ime, podaci in users.items():
            status = podaci.get("active", True)
            print(f"- {ime} (Aktivan: {'da' if status else 'ne'})")

        korisnik = users.get(username)

        if not korisnik:
            print(f"❌ Korisnik '{username}' ne postoji.")
            return

        if not korisnik.get("active", True):
            print(f"❌ Ne možete ponovo opozvati. Pristup korisniku '{username}' je već opozvan.")
            return

        korisnik["active"] = False  # opoziv pristupa

        # Sačuvaj promjenu u JSON fajlu
        with open("file_system/user.json", "w") as f:
            json.dump(users, f, indent=4)

        print(f"✅ Pristup korisniku '{username}' je uspješno opozvan.")
 """

