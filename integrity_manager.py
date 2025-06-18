import hashlib
import json
import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


PRIVATE_KEY_PATH = "private_key.pem"
PUBLIC_KEY_PATH = "public_key.pem"

def generate_aes_key():
    """Generisanje nasumicnog AES-kljuca"""
    return os.urandom(32)

def encrypt_file(username, filename, content):
    """Enkriptuje fajl AES-om pre nego što ga sačuva"""
    aes_key = generate_aes_key()
    iv = os.urandom(16)  # IV za AES-CBC
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # Padovanje sadržaja na 16 bajtova (za AES blokove)
    content_bytes = content.encode()
    padding_length = 16 - (len(content_bytes) % 16)
    padded_content = content_bytes + bytes([padding_length] * padding_length)

    encrypted_data = encryptor.update(padded_content) + encryptor.finalize()
    
    encrypted_file_path = os.path.join("file_system", username, filename)
    with open(encrypted_file_path, "wb") as f:
        f.write(iv + encrypted_data)  

    # Čuvamo AES ključ enkriptovan korisnikovim javnim ključem
    public_key = load_public_key(username)
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    with open(f"file_system/{username}/{filename}.key", "wb") as key_file:
        key_file.write(encrypted_aes_key)

    print(f"Fajl {filename} je enkriptovan i sačuvan.")

def decrypt_file(username, filename):
    """Dekriptuje AES enkriptovan fajl"""
    encrypted_file_path = os.path.join("file_system", username, filename)
    encrypted_key_path = os.path.join("file_system", username, f"{filename}.key")

    # Učitavamo enkriptovani AES ključ i dešifrujemo ga privatnim ključem korisnika
    private_key = load_private_key(username)
    with open(encrypted_key_path, "rb") as key_file:
        encrypted_aes_key = key_file.read()

    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    # Učitavamo enkriptovani fajl i dešifrujemo ga
    with open(encrypted_file_path, "rb") as f:
        file_data = f.read()

    iv = file_data[:16]
    encrypted_content = file_data[16:]

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_content) + decryptor.finalize()

    # Uklanjanje paddinga
    padding_length = decrypted_data[-1]
    decrypted_content = decrypted_data[:-padding_length].decode()

    return decrypted_content

def calculate_file_hash(file_path, algo='sha512'):
    """Računanje hash fajla."""
    hasher = hashlib.new(algo)
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            hasher.update(chunk)
    return hasher.hexdigest()


def save_file_hash(username, filename):
    """U fajl hash.json cuva hash fajla"""
    hash_file = os.path.join("file_system", username, "file_hashes.json")
    file_path = os.path.join("file_system", username, filename)

    file_hash = calculate_file_hash(file_path)

    if os.path.exists(hash_file):
        with open (hash_file, "r", encoding="utf-8") as f:
            hashes = json.load(f)
    else: 
            hashes={}
    hashes[filename] = file_hash
    with open(hash_file, "w", encoding="utf-8") as f:
        json.dump(hashes, f, indent=4)

def load_private_key(username):
    key_path = os.path.join("file_system", username, "private_key.pem")
    print(f"DEBUG: Pokušavam da učitam privatni ključ iz {key_path}")

    if not os.path.exists(key_path):
        raise FileNotFoundError(f"❌ Privatni ključ nije pronađen: {key_path}")

    with open(key_path, "rb") as f:
        key_data = f.read()
        print(f"DEBUG: Učitani privatni ključ ({username}): {key_data[:50]}...")

    private_key = serialization.load_pem_private_key(key_data, password=None)
    return private_key


def load_public_key(username):
    """Učitava javni ključ iz fajla"""
    key_path = os.path.join("file_system", username, "public_key.pem")
    print(f"DEBUG: Pokušavam da učitam javni ključ iz {key_path}")

    if not os.path.exists(key_path):
        raise FileNotFoundError(f"❌ Javni ključ nije pronađen: {key_path}")

    with open(key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    print(f"DEBUG: Učitani javni ključ tip: {type(public_key)}")  # Dodaj ovu liniju

    return public_key
    
def sign_data(username, data):
    private_key = load_private_key(username)
    encoded_data = data.encode()  # Konvertuje string u bytes
    print(f"DEBUG: Originalni podaci (bytes): {encoded_data}")

    signature = private_key.sign(
        encoded_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA512()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA512(),
    )

    print(f"DEBUG: Potpis prije kodiranja: {signature}")
    encoded_signature = base64.b16encode(signature).decode()
    print(f"DEBUG: Potpis posle kodiranja: {encoded_signature}")
    return encoded_signature

def verify_signature(data, signature, username):
    public_key = load_public_key(username)
    decoded_signature = base64.b16decode(signature)

    encoded_data = data.encode()
    print(f"DEBUG: Originalni podaci za verifikaciju (bytes): {encoded_data}")
    print(f"DEBUG: Potpis posle dekodiranja: {decoded_signature}")

    try:
        public_key.verify(
            decoded_signature,
            encoded_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA512()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA512(),
        )
        print("DEBUG: Potpis uspešno verifikovan! ✅")
        return True
    except Exception as e:
        print(f"ERROR: Neuspešna verifikacija potpisa: {e}")
        return False


def save_file_integrity(username, filename):
    """Čuva hash i digitalni potpis fajla."""
    print(f"u save_file_integrity korisnicko ime '{username}'")
    user_dir = os.path.join("file_system", username)
    hash_file = os.path.join(user_dir, "file_hashes.json")
    file_path = os.path.join(user_dir, filename)

    file_hash = calculate_file_hash(file_path)
    signature = sign_data(username, file_hash)  # <--- OVO JE POPRAVLJENO

    if os.path.exists(hash_file):
        with open(hash_file, "r", encoding="utf-8") as f:
            hashes = json.load(f)
    else:
        hashes = {}

    hashes[filename] = {"hash": file_hash, "signature": signature}

    with open(hash_file, "w", encoding="utf-8") as f:
        json.dump(hashes, f, indent=4)


def verify_file_integrity(username, filename):
    """Proverava integritet fajla."""
    user_dir = os.path.join("file_system", username)
    hash_file = os.path.join(user_dir, "file_hashes.json")
    file_path = os.path.join(user_dir, filename)

    if not os.path.exists(file_path):
        print("Fajl ne postoji.")
        return False

    if not os.path.exists(hash_file):
        print("Nema podataka o integritetu fajla.")
        return False

    with open(hash_file, "r", encoding="utf-8") as f:
        hashes = json.load(f)

    if filename not in hashes:
        print("Nema zapisa o ovom fajlu.")
        return False

    saved_hash = hashes[filename]["hash"]
    saved_signature = hashes[filename]["signature"]
    current_hash = calculate_file_hash(file_path)

    print(f"DEBUG: Sačuvani heš: {saved_hash}")
    print(f"DEBUG: Trenutni heš: {current_hash}")

    if saved_hash != current_hash:
        print("UPOZORENJE: Integritet fajla je narušen!")
        return False

    print(f"DEBUG: Proveravam potpis za heš: {saved_hash}")
    print(f"DEBUG: Sačuvani potpis: {saved_signature}")

    if not verify_signature(saved_hash, saved_signature, username):
        print("UPOZORENJE: Digitalni potpis ne odgovara!")
        return False

    return True



    
""" def read_txt_file(username, filename):

    if verify_file_integrity(username, filename + ".txt"):
        content = decrypt_file(username, filename + ".txt")
        print(f"Sadrzaj fajla {filename}.txt : \n{content}")
    else:
        print("Fajl je ostecen ili modifikovan") """