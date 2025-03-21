from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime


# Step 1: Generate RSA Private Key and Save to File
def generate_private_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # Save private key as .key file
    with open("privatekey.key", "wb") as key_file:
        key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    print("Private key saved as 'privatekey.key'")
    return private_key


# Step 2: Generate a Self-Signed Certificate and Save to File
def generate_self_signed_certificate(private_key):
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "TR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Istanbul"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Istanbul"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Voice guru telekom"),
        x509.NameAttribute(NameOID.COMMON_NAME, "voiceguru.net"),
    ])

    # Build the self-signed certificate
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)  # Self-signed, so issuer is the same as subject
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))  # Valid for 1 year
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("voiceguru.net")]), critical=False)
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    # Save the certificate to a .crt file
    with open("certificate.crt", "wb") as cert_file:
        cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))
    print("Self-signed certificate saved as 'certificate.crt'")

    return certificate.public_bytes(serialization.Encoding.PEM).decode()


# Main Workflow
try:
    # Generate Private Key
    private_key = generate_private_key()

    # Generate a self-signed certificate
    generate_self_signed_certificate(private_key)

except Exception as e:
    print(f"An error occurred: {e}")
