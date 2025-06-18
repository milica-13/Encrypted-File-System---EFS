from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from datetime import datetime, timedelta

CRL_PATH = "certificates/crl.pem"
CA_KEY_PATH = "certificates/ca_key.pem"

# Učitavanje CA privatnog ključa
with open(CA_KEY_PATH, "rb") as f:
    ca_private_key = serialization.load_pem_private_key(f.read(), password=None)

# Kreiranje prazne CRL liste (bez opozvanih sertifikata)
crl_builder = x509.CertificateRevocationListBuilder()
crl_builder = crl_builder.issuer_name(
    x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "CA tijelo"),
    ])
).last_update(
    datetime.utcnow()
).next_update(
    datetime.utcnow() + timedelta(days=30)  # CRL važi 30 dana
)

# Potpisivanje CRL liste CA ključem
crl = crl_builder.sign(private_key=ca_private_key, algorithm=hashes.SHA256())

# Čuvanje CRL liste u PEM formatu
with open(CRL_PATH, "wb") as f:
    f.write(crl.public_bytes(serialization.Encoding.PEM))

print("✅ Generisana nova CRL lista!")
