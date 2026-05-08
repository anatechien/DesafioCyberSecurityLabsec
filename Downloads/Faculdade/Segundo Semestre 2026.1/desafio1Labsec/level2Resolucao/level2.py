"""
Decifra access_code.enc com a chave privada RSA do employee.p12.

Requisito: pip install cryptography
Ficheiros na mesma pasta: employee.p12, password.txt, access_code.enc
"""

import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs12


def main() -> None:
    base = Path(__file__).resolve().parent

    password_path = base / "password.txt"
    p12_path = base / "employee.p12"
    enc_path = base / "access_code.enc"

    password = password_path.read_text(encoding="utf-8").strip().encode("utf-8")
    p12_data = p12_path.read_bytes()
    ciphertext = enc_path.read_bytes()

    private_key, cert, _ = pkcs12.load_key_and_certificates(
        p12_data, password, default_backend()
    )

    if private_key is None:
        raise SystemExit("O .p12 não contém chave privada.")

    print(f"RSA {private_key.key_size} bits | ciphertext {len(ciphertext)} bytes")
    if cert:
        print(f"Certificado: {cert.subject.rfc4514_string()}")
    print()

    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    message = plaintext.decode("utf-8")
    print("Texto claro:")
    print(message)


if __name__ == "__main__":
    main()
