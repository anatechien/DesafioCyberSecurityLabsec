"""
Nível 5 — Blackwall: serial numbers de todas as assinaturas (PKCS#7 em /Contents).

Gera várias formas plausíveis de entrega, porque o enunciado é ambíguo e o
verificador pode esperar:
  (A) inteiro do serial em hex mínimo (sem zeros à esquerda do INTEGER) — uso mais comum;
  (B) octetos do INTEGER no DER do certificado (inclui 00 de padding se existir);
  (C) SHAKE-256 com 512 bits (64 bytes = 128 hex) sobre a concatenação (A), se a
      plataforma pedir resumo conforme regras do lab.

Ordem: 9 PDFs (Inferno), dentro de cada um as assinaturas na ordem do ficheiro
(/FT /Sig → /Contents). Total 8+8+7+6+5+4+3+2+1 = 44.
"""
from __future__ import annotations

import hashlib
import warnings
from pathlib import Path

from cryptography.hazmat.primitives.serialization import Encoding, pkcs7

warnings.filterwarnings("ignore", message="PKCS#7")

PDFS_INFERNO = [
    "hell.pdf",
    "_emb_Lust.pdf",
    "_emb_Gluttony.pdf",
    "_emb_Greed.pdf",
    "_emb_Anger.pdf",
    "_emb_Heresy.pdf",
    "_emb_Violence.pdf",
    "_emb_Fraud.pdf",
    "_emb_Treachery.pdf",
]


def _read_len(buf: bytes, i: int) -> tuple[int, int]:
    first = buf[i]
    i += 1
    if first < 0x80:
        return first, i
    n = first & 0x7F
    return int.from_bytes(buf[i : i + n], "big"), i + n


def _read_tlv(buf: bytes, i: int) -> tuple[int, bytes, int]:
    tag = buf[i]
    ln, j = _read_len(buf, i + 1)
    return tag, buf[j : j + ln], j + ln


def der_integer_contents_hex_from_cert_der(cert_der: bytes) -> str:
    """Hex dos octetos do INTEGER serial no TBSCertificate (como no DER), não o int mínimo."""
    tag, cert_seq, _ = _read_tlv(cert_der, 0)
    if tag != 0x30:
        raise ValueError("certificado: SEQUENCE esperado")
    tag, tbs, _ = _read_tlv(cert_seq, 0)
    if tag != 0x30:
        raise ValueError("tbsCertificate: SEQUENCE esperado")
    i = 0
    if i < len(tbs) and tbs[i] == 0xA0:
        _, _, i = _read_tlv(tbs, i)
    tag, serial_bytes, _ = _read_tlv(tbs, i)
    if tag != 0x02:
        raise ValueError("serialNumber: INTEGER esperado")
    return serial_bytes.hex()


def pkcs7_blobs_from_pdf(raw: bytes) -> list[bytes]:
    data = raw.decode("latin-1", errors="replace")
    blobs: list[bytes] = []
    pos = 0
    while True:
        ft = data.find("/FT /Sig", pos)
        if ft == -1:
            break
        cidx = data.find("/Contents <", ft)
        if cidx == -1:
            pos = ft + 8
            continue
        i = cidx + len("/Contents <")
        hex_digits: list[str] = []
        while i < len(data):
            ch = data[i]
            if ch == ">":
                break
            if ch in " \n\r\t":
                i += 1
                continue
            hex_digits.append(ch)
            i += 1
        blobs.append(bytes.fromhex("".join(hex_digits)))
        pos = i
    return blobs


def main() -> None:
    base = Path(__file__).resolve().parent
    minimal: list[str] = []
    der_hex: list[str] = []

    for name in PDFS_INFERNO:
        path = base / name
        if not path.is_file():
            raise FileNotFoundError(path)
        for der in pkcs7_blobs_from_pdf(path.read_bytes()):
            certs = pkcs7.load_der_pkcs7_certificates(der)
            if not certs:
                raise ValueError(f"PKCS#7 sem certificados em {name}")
            cert = certs[0]
            minimal.append(f"{cert.serial_number:x}")
            cert_der = cert.public_bytes(Encoding.DER)
            der_hex.append(der_integer_contents_hex_from_cert_der(cert_der))

    concat_minimal = "".join(minimal)
    concat_der = "".join(der_hex)

    (base / "concat_serials_nivel5.txt").write_text(concat_minimal, encoding="ascii")
    (base / "concat_serials_nivel5_der_integer.txt").write_text(concat_der, encoding="ascii")

    # Regras do lab: SHAKE, 512 bits = 64 bytes de saída
    shake_a = hashlib.shake_256(concat_minimal.encode("ascii")).hexdigest(64)
    shake_b = hashlib.shake_256(bytes.fromhex(concat_minimal)).hexdigest(64)
    (base / "shake256_512b_concat_minimal_ascii.txt").write_text(shake_a, encoding="ascii")
    (base / "shake256_512b_concat_minimal_bin.txt").write_text(shake_b, encoding="ascii")

    print(f"Assinaturas: {len(minimal)}")
    print(f"(A) Hex minimo, {len(concat_minimal)} chars -> concat_serials_nivel5.txt")
    print(f"(B) INTEGER DER, {len(concat_der)} chars -> concat_serials_nivel5_der_integer.txt")
    print(f"(C) SHAKE256 512b (hex concat ASCII), 128 chars -> shake256_512b_concat_minimal_ascii.txt")
    print(f"(D) SHAKE256 512b (bytes.fromhex concat), 128 chars -> shake256_512b_concat_minimal_bin.txt")
    print()
    print("(A)", concat_minimal)
    print()
    print("(C)", shake_a)


if __name__ == "__main__":
    main()
