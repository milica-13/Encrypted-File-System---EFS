import os
from fpdf import FPDF 
from PIL import Image
import io, secrets
from PyPDF2 import PdfReader
from check_integrity_manager import sign_file, verify_file, load_keys  
from key_manager import KeyManager
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
import shutil, base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import padding  # ✅ Pravilno!

def list_user_files(username):
    """Prikaz korisničkih fajlova i direktorijuma"""
    user_dir = os.path.join("file_system", username)
    if os.path.exists(user_dir):
        files = os.listdir(user_dir)
        if files:
            print(f"Sadržaj direktorijuma {username}: {', '.join(files)}")
        else:
            print(f"Direktorijum {username} je prazan.")
    else:
        print(f"Direktorijum {username} ne postoji.")

def derive_key(password, salt):
    """ Generiše AES ključ iz korisničke lozinke koristeći PBKDF2 """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  
        salt=salt,
        iterations=100000,  
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def create_txt_file(username, filename, content):
    """ Kreira, potpisuje i enkriptuje tekstualni fajl """

    user_dir = os.path.join("file_system", username)
    os.makedirs(user_dir, exist_ok=True)  # 📂 Osiguravamo da direktorijum postoji

    file_path = os.path.join(user_dir, filename + ".txt")

    # ✍️ Upisujemo sadržaj u fajl
    with open(file_path, "w", encoding="utf-8") as file:
        file.write(content)

    # 🔏 Potpisivanje fajla
    sign_file(username, filename + ".txt")

    # 🔒 Enkripcija fajla
    encrypted_path = encrypt_file(username, file_path, encryption_type="AES")

    # 🗑️ Brišemo originalni fajl nakon enkripcije
    if encrypted_path and os.path.exists(file_path):
        os.remove(file_path)

    print(f"✅ Kreiran, potpisan i enkriptovan tekstualni fajl: {filename}.txt")

def read_txt_file(username, filename):
    """ Dekriptuje i čita sadržaj tekstualnog fajla """

    encrypted_file_path = os.path.join("file_system", username, filename + ".txt.enc")

    if not os.path.exists(encrypted_file_path):
        print(f"❌ Fajl {filename}.txt.enc ne postoji.")
        return

    # 🔓 Dekripcija fajla
    decrypted_file_path = decrypt_file(username, encrypted_file_path, encryption_type="AES")

    if decrypted_file_path is None:
        print(f"❌ Neuspešna dekripcija fajla {filename}.txt!")
        return

    # ✅ Proveravamo integritet fajla
    if not verify_file(username, filename + ".txt"):
        print(f"⚠️ Integritet fajla {filename}.txt je narušen! Čitanje nije dozvoljeno.")
        return

    # 📖 Čitamo dekriptovan fajl
    try:
        with open(decrypted_file_path, "r", encoding="utf-8") as file:
            content = file.read()

        print(f"📜 Sadržaj fajla {filename}.txt:\n{content}")

    except Exception as e:
        print(f"❌ Greška pri čitanju TXT fajla: {e}")

    # 🗑️ Brišemo dekriptovan fajl nakon čitanja
    if os.path.exists(decrypted_file_path):
        os.remove(decrypted_file_path)

""" 
def create_txt_file(username, filename, content):
    
    user_dir = os.path.join("file_system", username)
    os.makedirs(user_dir, exist_ok=True)  # Osigurava da direktorijum postoji

    file_path = os.path.join(user_dir, filename + ".txt")
    with open(file_path, "w", encoding="utf-8") as file:
        file.write(content)

    # Potpisivanje fajla
    sign_file(username, filename + ".txt")

    print(f"Kreiran je i potpisan tekstualni fajl {filename}.txt.") 

def read_txt_file(username, filename):
    file_path = os.path.join("file_system", username, filename + ".txt")

    if not os.path.exists(file_path):
        print(f"Fajl {filename}.txt ne postoji.")
        return

    # Provjera integriteta prije čitanja
    if not verify_file(username, filename + ".txt"):
        print(f"Integritet fajla {filename}.txt je narušen! Čitanje nije dozvoljeno.")
        return

    try:
        with open(file_path, "rb") as file:
            content = file.read()

        try:
            text_content = content.decode("utf-8")
            print(f"Sadržaj fajla {filename}.txt:\n{text_content}")
        except UnicodeDecodeError:
            print(f"Fajl {filename}.txt sadrži binarne podatke i ne može se direktno pročitati kao tekst.")

    except Exception as e:
        print(f"Greška pri čitanju TXT fajla: {e}") 
 """
def create_pdf_file(username, filename, content):
    """Kreiranje PDF fajla"""
    user_dir = os.path.join("file_system", username)
    os.makedirs(user_dir, exist_ok=True)

    file_path = os.path.join(user_dir, filename + ".pdf")

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=11)
    pdf.multi_cell(200, 10, content)
    pdf.output(file_path)

    sign_file(username, filename + ".pdf")  # Potpisivanje fajla

    print(f"Kreiran je PDF dokument {filename}.pdf i potpisan.")

def read_pdf_file(username, filename):
    """Čitanje PDF fajla uz proveru integriteta"""
    file_path = os.path.join("file_system", username, filename + ".pdf")

    if not os.path.exists(file_path):
        print(f"Fajl {filename}.pdf ne postoji.")
        return

    if not verify_file(username, filename + ".pdf"):
        print(f"Integritet fajla {filename}.pdf je narušen! Čitanje nije dozvoljeno.")
        return

    try:
        with open(file_path, "rb") as file:
            reader = PdfReader(file)
            text = "\n".join([page.extract_text() for page in reader.pages if page.extract_text()])
            print(f"Sadržaj PDF fajla {filename}.pdf:\n{text if text else 'Nema vidljivog teksta.'}")
    except Exception as e:
        print(f"Greška pri čitanju PDF fajla: {e}")

def save_image(username, filename, image_data):
    """Čuvanje slike u korisnikovom direktorijumu"""
    user_dir = os.path.join("file_system", username)
    os.makedirs(user_dir, exist_ok=True)

    file_path = os.path.join(user_dir, filename)
    image = Image.open(io.BytesIO(image_data))
    image.save(file_path)

    sign_file(username, filename)  # Potpisivanje slike za integritet

    print(f"Sačuvana je i potpisana slika {filename}.")

def delete_file(username, filename):
        """Brisanje fajla uz proveru integriteta"""
        base_path = os.path.join("file_system", username)
    
        # Ako korisnik nije naveo ekstenziju, dodajemo .txt
        if "." not in filename:
            filename += ".txt"

        original_file = os.path.join(base_path, filename)
        encrypted_file = original_file + ".enc"
        signature_file = original_file + ".sig"

        # Provjera da li fajl uopšte postoji (bilo koji od njih)
        if any(os.path.exists(p) for p in [original_file, encrypted_file, signature_file]):
            # Ako postoji originalni, proveri integritet
            if os.path.exists(original_file):
                if not verify_file(username, filename):
                    print(f"⚠ Fajl {filename} je oštećen ili izmenjen. Ne može se obrisati!")
                    return

            # Brisanje svih povezanih fajlova
            for path in [original_file, encrypted_file, signature_file]:
                if os.path.exists(path):
                    os.remove(path)
                    print(f"🗑️ Obrisan: {os.path.basename(path)}")
            print(f"✅ Fajl '{filename}' i povezani podaci su uspešno obrisani.")
        else:
            print(f"❌ Fajl {filename} ne postoji.")

        key_file = original_file + ".key"
        if os.path.exists(key_file):
            os.remove(key_file)
            print(f"🗝️ Obrisan: {os.path.basename(key_file)}")



""" def delete_file(username, filename):
    file_path = os.path.join("file_system", username, filename)

    if "." not in filename:
        file_path += ".txt"

    if os.path.exists(file_path) and os.path.isfile(file_path):
        if verify_file(username, filename):
            os.remove(file_path)
            print(f"Obrisan je fajl {filename}.")
        else:
            print(f"Fajl {filename} je oštećen ili izmenjen. Ne može se obrisati!")
    else:
        print(f"Fajl {filename} ne postoji.") """

def create_directory(username, dir_name):
    """Kreiranje direktorijuma"""
    user_dir = os.path.join("file_system", username, dir_name)
    os.makedirs(user_dir, exist_ok=True)
    print(f"Kreiran je direktorijum '{dir_name}' unutar direktorijuma korisnika '{username}'.")

def delete_directory(username, dir_name):
    """Brisanje direktorijuma ako je prazan"""
    user_dir = os.path.join("file_system", username, dir_name)
    
    if os.path.exists(user_dir) and os.path.isdir(user_dir):
        if not os.listdir(user_dir):  # Provjera da li je direktorijum prazan
            os.rmdir(user_dir)
            print(f"Obrisan je direktorijum '{dir_name}'.")
        else:
            print(f"Direktorijum '{dir_name}' nije prazan. Obrišite fajlove pre brisanja.")
    else:
        print(f"Direktorijum '{dir_name}' ne postoji.")


import os
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import padding as asy_padding

def upload_file(username, local_path, efs_path):
    """
    Prenosi fajl sa host sistema na EFS.
    - Šifrira fajl pomoću AES-256.
    - Potpisuje fajl privatnim ključem korisnika.
    - Čuva šifrovani fajl i potpis na EFS-u.
    """
    if not os.path.exists(local_path):
        print("❌ Greška: Fajl ne postoji na host sistemu!")
        return
    
    print(f"🔄 Učitavanje ključeva za korisnika {username}...")
    private_key, public_key = load_keys(username)

    # 1️⃣ Učitavamo originalni sadržaj fajla
    with open(local_path, "rb") as f:
        original_data = f.read()

    # 2️⃣ Padovanje podataka pomoću PKCS7
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(original_data) + padder.finalize()

    # 3️⃣ Generišemo ključ i IV za AES-256
    symmetric_key = secrets.token_bytes(32)
    iv = secrets.token_bytes(16)

    # 4️⃣ Šifrujemo fajl
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # 5️⃣ Kreiramo SHA-256 heš
    file_hash = hashes.Hash(hashes.SHA256())
    file_hash.update(original_data)
    digest = file_hash.finalize()
    print(f"📜 Heš originalnog fajla: {digest.hex()}")

    # 6️⃣ Potpisujemo fajl privatnim ključem korisnika
    signature = private_key.sign(
        digest,
        asy_padding.PSS(
            mgf=asy_padding.MGF1(hashes.SHA256()),
            salt_length=asy_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # 7️⃣ Pravimo putanje i čuvamo fajl
    os.makedirs(os.path.dirname(efs_path), exist_ok=True)
    with open(f"{efs_path}.enc", "wb") as f:
        f.write(encrypted_data)

    with open(f"{efs_path}.sig", "wb") as f:
        f.write(signature)

    with open(f"{efs_path}.key", "wb") as f:
        f.write(symmetric_key + iv)

    print(f"✅ Fajl {local_path} je uspješno šifrovan i sačuvan na EFS.")


def download_file(username, efs_path, local_path):
    """
    Preuzima fajl sa EFS-a na host sistem.
    - Učitava šifrovani fajl, potpis i ključ.
    - Dešifruje fajl pomoću AES-256.
    - Verifikuje potpis pomoću javnog ključa korisnika.
    - Čuva dešifrovani fajl na host sistemu.
    """
    encrypted_file_path = f"{efs_path}.enc"
    signature_path = f"{efs_path}.sig"
    key_path = f"{efs_path}.key"

    if not all(os.path.exists(p) for p in [encrypted_file_path, signature_path, key_path]):
        print("❌ Greška: Nedostaju podaci na EFS-u!")
        return
    
    print(f"🔄 Učitavanje ključeva za korisnika {username}...")
    private_key, public_key = load_keys(username)

    # 1️⃣ Učitavamo podatke
    with open(encrypted_file_path, "rb") as f:
        encrypted_data = f.read()

    with open(signature_path, "rb") as f:
        signature = f.read()

    with open(key_path, "rb") as f:
        key_data = f.read()
        symmetric_key = key_data[:32]  # AES-256 ključ
        iv = key_data[32:]  # Inicijalizacioni vektor

    # 2️⃣ Dešifrujemo podatke pomoću AES-256
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # 3️⃣ Uklanjamo PKCS7 padding
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    # 4️⃣ Kreiramo SHA-256 heš i upoređujemo
    file_hash = hashes.Hash(hashes.SHA256())
    file_hash.update(decrypted_data)
    digest = file_hash.finalize()

    print(f"📜 Heš dešifrovanog fajla: {digest.hex()}")
    print(f"📜 Očekivani potpis: {signature.hex()}")

    # 5️⃣ Verifikujemo potpis
    try:
        public_key.verify(
            signature,
            digest,
            asy_padding.PSS(
                mgf=asy_padding.MGF1(hashes.SHA256()),
                salt_length=asy_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("✅ Potpis je validan.")
    except InvalidSignature:
        print("❌ Greška: Potpis nije validan! Fajl može biti kompromitovan.")
        return

    # 6️⃣ Čuvamo dešifrovani fajl
    with open(local_path, "wb") as f:
        f.write(decrypted_data)

    print(f"✅ Fajl je uspješno preuzet i sačuvan kao {local_path}.")


def encrypt_file(username, file_path, encryption_type="AES"):
    """
    Enkriptuje fajl koristeći odabranu metodu (AES, RSA ili hibridnu enkripciju).
    - AES: Simetrična enkripcija
    - RSA: Asimetrična enkripcija (za male fajlove)
    - Hybrid: Simetrična enkripcija sa AES + RSA za ključ
    """
    if not os.path.exists(file_path):
        print("❌ Greška: Fajl ne postoji!")
        return None

    #print(f"🔒 Enkriptovanje fajla '{file_path}' koristeći {encryption_type}...")

    # Učitavamo podatke iz fajla
    with open(file_path, "rb") as f:
        file_data = f.read()

    encrypted_data = None
    key_info = None  # Dodatni podaci o ključu, ako su potrebni

    if encryption_type == "AES":
        # 🔹 AES-256 enkripcija (simetrična)
        key = secrets.token_bytes(32)  # 256-bitni ključ
        iv = secrets.token_bytes(16)  # Inicijalizacioni vektor

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()

        # Padujemo podatke ako nisu u punom bloku od 16 bajtova
        padding_length = 16 - (len(file_data) % 16)
        file_data += bytes([padding_length]) * padding_length

        encrypted_data = encryptor.update(file_data) + encryptor.finalize()
        key_info = key + iv  # Čuvamo ključ i IV zajedno

    elif encryption_type == "RSA":
        # 🔹 RSA enkripcija (asimetrična, pogodna za manje fajlove)
        public_key = KeyManager.load_keys(username)[1]

        encrypted_data = public_key.encrypt(
            file_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    elif encryption_type == "Hybrid":
        # 🔹 Hibridna enkripcija (AES + RSA za ključ)
        public_key = KeyManager.load_keys(username)[1]
        key = secrets.token_bytes(32)  # AES ključ
        iv = secrets.token_bytes(16)  # IV

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()

        # Padujemo podatke
        padding_length = 16 - (len(file_data) % 16)
        file_data += bytes([padding_length]) * padding_length

        encrypted_data = encryptor.update(file_data) + encryptor.finalize()

        # Šifriramo AES ključ RSA javnim ključem
        encrypted_key = public_key.encrypt(
            key + iv,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        key_info = encrypted_key  # Čuvamo šifrovani ključ

    # Čuvamo enkriptovan fajl
    encrypted_path = file_path + ".enc"
    with open(encrypted_path, "wb") as f:
        f.write(encrypted_data)

    # Ako koristimo AES ili Hybrid, sačuvamo i ključne podatke
    if key_info:
        with open(file_path + ".key", "wb") as f:
            f.write(key_info)

    print(f"✅ Fajl enkriptovan i sačuvan kao '{encrypted_path}'!")
    return encrypted_path
""" 
def share_file(sender_username, receiver_username, filename, encryption_type="AES"):
    sender_path = f"file_system/{sender_username}/{filename}"
    shared_folder = "file_system/shared"
    shared_file_path = f"{shared_folder}/{receiver_username}_{filename}.enc"

    if not os.path.exists(sender_path):
        print("❌ Greška: Fajl ne postoji kod pošiljaoca!")
        return False

    if not os.path.exists(shared_folder):
        os.makedirs(shared_folder)

    # Enkriptujemo fajl prije dijeljenja
    encrypted_file_path = encrypt_file(sender_username, sender_path, encryption_type)
    if not encrypted_file_path:
        print("❌ Greška prilikom enkripcije fajla!")
        return False

    shutil.copy(encrypted_file_path, shared_file_path)

    # Kopiramo i ključ ako postoji (za AES ili Hybrid)
    key_path = sender_path + ".key"
    if os.path.exists(key_path):
        shutil.copy(key_path, shared_file_path + ".key")

    print(f"✅ Fajl '{filename}' uspješno podijeljen sa '{receiver_username}'.")
    return True """


def decrypt_file(username, encrypted_file_path, encryption_type="AES"):
    
    if not os.path.exists(encrypted_file_path):
        print("❌ Greška: Enkriptovani fajl ne postoji!")
        return None

    print(f"🔓 Dekriptovanje fajla '{encrypted_file_path}'...")

    decrypted_data = None
    original_file_path = encrypted_file_path.replace(".enc", "")

    if encryption_type == "AES":
        # Učitavamo ključ i IV
        key_path = encrypted_file_path.replace(".enc", ".key")
        if not os.path.exists(key_path):
            print("❌ Greška: Ključ za dekripciju nije pronađen!")
            return None

        with open(key_path, "rb") as f:
            key_info = f.read()

        key = key_info[:32]
        iv = key_info[32:]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()

        with open(encrypted_file_path, "rb") as f:
            encrypted_data = f.read()

        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        decrypted_data = decrypted_data[:-decrypted_data[-1]]  # Uklanjamo padding

    elif encryption_type == "RSA":
        private_key = KeyManager.load_keys(username)[0]

        with open(encrypted_file_path, "rb") as f:
            encrypted_data = f.read()

        decrypted_data = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    with open(original_file_path, "wb") as f:
        f.write(decrypted_data)

    print(f"✅ Fajl dekriptovan i sačuvan kao '{original_file_path}'!")
    return original_file_path 



""" def retrieve_shared_file(username, filename, encryption_type="AES"):
    shared_folder = "file_system/shared"
    shared_file_path = f"{shared_folder}/{username}_{filename}.enc"
    user_path = f"file_system/{username}/{filename}"

    if not os.path.exists(shared_file_path):
        print("❌ Greška: Fajl nije dostupan ili nije podijeljen sa vama!")
        return False

    # Premještanje enkriptovanog fajla u korisnički direktorijum
    shutil.move(shared_file_path, user_path + ".enc")

    # Premještanje ključa ako postoji
    key_path = shared_file_path + ".key"
    if os.path.exists(key_path):
        shutil.move(key_path, user_path + ".key")

    # Automatska dekripcija
    decrypted_path = decrypt_file(username, user_path + ".enc", encryption_type)

    if decrypted_path:
        print(f"✅ Fajl '{filename}' uspješno preuzet i dekriptovan!")
        return True
    else:
        print("❌ Greška prilikom dekripcije fajla!")
        return False
 """


def share_file(sender_username, receiver_username, filename, encryption_type="AES"):
    sender_path = f"file_system/{sender_username}/{filename}.txt.enc"
    shared_folder = "file_system/shared"
    shared_file_path = f"{shared_folder}/{receiver_username}_{filename}.enc"

    print("Posiljaoc salje:")
    print(sender_path)

    if not os.path.exists(sender_path):
        print("❌ Greška: Fajl ne postoji kod pošiljaoca!")
        return False

    if not os.path.exists(shared_folder):
        os.makedirs(shared_folder)

    # Enkriptujemo fajl prije dijeljenja
    #encrypted_file_path = encrypt_file(sender_username, sender_path, encryption_type)
    #if not encrypted_file_path:
    #    print("❌ Greška prilikom enkripcije fajla!")
    #    return False

    shutil.copy(sender_path, shared_file_path)

    # Kopiramo i ključ ako postoji (za AES ili Hybrid)
    key_path = f"file_system/{sender_username}/{filename}.txt.key"
    sig_path=f"file_system/{sender_username}/{filename}.txt.sig"
    if os.path.exists(key_path):
        shutil.copy(key_path, shared_file_path + ".key")

    if os.path.exists(sig_path):
        shutil.copy(sig_path, shared_file_path + ".sig")

    print(f"✅ Fajl '{filename}' uspješno podijeljen sa '{receiver_username}'.")
    return True

""" def retrieve_shared_file(username, filename, encryption_type="AES"):
    shared_folder = "file_system/shared"
    shared_file_path = f"{shared_folder}/{username}_{filename}.enc"
    user_path = f"file_system/{username}/{filename}.txt"

    print(shared_file_path)

    if not os.path.exists(shared_file_path):
        print("❌ Greška: Fajl nije dostupan ili nije podijeljen sa vama!")
        return False

    # Premještanje enkriptovanog fajla u korisnički direktorijum
    shutil.move(shared_file_path, user_path + ".enc")

    # Premještanje ključa ako postoji
    key_path = shared_file_path + ".key"
    if os.path.exists(key_path):
        shutil.move(key_path, user_path + ".key")

    sig_path = shared_file_path + ".sig"
    if os.path.exists(sig_path):
        shutil.move(sig_path, user_path + ".sig")
    # Automatska dekripcija
    decrypted_path = decrypt_file(username, user_path + ".enc", encryption_type)

    if decrypted_path:
        print(f"✅ Fajl '{filename}' uspješno preuzet i dekriptovan!")
        return True
    else:
        print("❌ Greška prilikom dekripcije fajla!")
        return False """


def retrieve_shared_file(username, filename, encryption_type="AES"):
    shared_folder = "file_system/shared"
    shared_file_path = f"{shared_folder}/{username}_{filename}.enc"
    user_path = f"file_system/{username}/{filename}.txt"

    print(shared_file_path)

    if not os.path.exists(shared_file_path):
        print("❌ Greška: Fajl nije dostupan ili nije podijeljen sa vama!")
        return False

    shutil.move(shared_file_path, user_path + ".enc")

    key_path = shared_file_path + ".key"
    if os.path.exists(key_path):
        shutil.move(key_path, user_path + ".key")

    sig_path = shared_file_path + ".sig"
    if os.path.exists(sig_path):
        shutil.move(sig_path, user_path + ".sig")

    decrypted_path = decrypt_file(username, user_path + ".enc", encryption_type)

    if decrypted_path:
        print(f"✅ Fajl '{filename}' uspješno preuzet i dekriptovan!")
        return True
    else:
        print("❌ Greška prilikom dekripcije fajla!")
        return False


def safe_read_shared_file(sender_username, receiver_username, filename):
    """ Bezbedno čitanje preuzetog fajla uz proveru potpisa i dekripciju """
    
    encrypted_file_path = os.path.join("file_system", receiver_username, filename + ".txt.enc")

    if not os.path.exists(encrypted_file_path):
        print(f"❌ Enkriptovani fajl {filename}.txt.enc ne postoji!")
        return

    # 🔓 Dekripcija fajla
    decrypted_file_path = decrypt_file(receiver_username, encrypted_file_path, encryption_type="AES")
    if not decrypted_file_path:
        print(f"❌ Neuspešna dekripcija fajla {filename}.txt!")
        return

    # ✅ Verifikacija potpisa sa javnim ključem pošiljaoca
    if not verify_file(sender_username, filename + ".txt"):
        print(f"⚠️ Integritet fajla {filename}.txt je narušen! Čitanje nije dozvoljeno.")
        if os.path.exists(decrypted_file_path):
            os.remove(decrypted_file_path)
        return

    # 📖 Čitanje fajla
    try:
        with open(decrypted_file_path, "r", encoding="utf-8") as f:
            content = f.read()
        print(f"📜 Sadržaj fajla {filename}.txt:\n{content}")
    except Exception as e:
        print(f"❌ Greška pri čitanju fajla: {e}")
    finally:
        if os.path.exists(decrypted_file_path):
            os.remove(decrypted_file_path)
