#!/usr/bin/env python3
"""
Nível 3 — supervisor.p12: extrair o número de série do certificado (senha da chave)
e validar desbloqueando o PKCS#12 com cryptography.

Dependências: pip install cryptography asn1crypto
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from asn1crypto import core, pkcs12, x509
from cryptography.hazmat.primitives.serialization import pkcs12 as crypto_pkcs12


def _parse_tlv(data: bytes, off: int = 0) -> tuple[int, int, int, int]:
    """Retorna (tag, length, início_do_conteúdo, fim_exclusivo)."""
    tag = data[off]
    ln = data[off + 1]
    if ln & 0x80:
        n = ln & 0x7f
        length = int.from_bytes(data[off + 2 : off + 2 + n], "big")
        content_start = off + 2 + n
    else:
        length = ln
        content_start = off + 2
    return tag, length, content_start, content_start + length


def extract_cert_der_from_second_safebag(p12_path: Path) -> bytes:
    """
    O authSafe costuma ter dois SafeBags: chave (cifrada) e certificado (claro).
    Localiza o CertBag (OID 1.2.840.113549.1.9.22.1) e devolve o DER do X.509.
    """
    data = p12_path.read_bytes()
    pfx = pkcs12.Pfx.load(data)
    raw = pfx["auth_safe"]["content"].native
    seq = core.Sequence.load(raw)
    if len(seq) < 2:
        raise ValueError("Esperava pelo menos 2 SafeBags no authSafe.")

    sb1 = pkcs12.SafeBag.load(seq[1].dump())
    inner = sb1["bag_value"].native

    # OID do x509Certificate dentro do CertBag
    marker = bytes.fromhex("060a2a864886f70d01091601")
    pos = inner.find(marker)
    if pos < 0:
        raise ValueError("CertBag (x509Certificate) não encontrado.")

    start = inner.rfind(bytes([0x30, 0x82]), 0, pos)
    if start < 0:
        raise ValueError("Início da SEQUENCE do CertBag não encontrado.")

    blob = inner[start:]
    _, _, c0, c1 = _parse_tlv(blob, 0)
    _, _, d0, d1 = _parse_tlv(blob, c0)  # OID
    _, _, e0, e1 = _parse_tlv(blob, d1)  # [0] EXPLICIT
    _, _, f0, f1 = _parse_tlv(blob, e0)  # OCTET STRING com o certificado
    cert_der = blob[f0:f1]
    if not cert_der.startswith(b"\x30\x82"):
        raise ValueError("DER do certificado parece inválido.")
    return cert_der


def serial_decimal_from_cert_der(cert_der: bytes) -> int:
    cert = x509.Certificate.load(cert_der)
    return int(cert["tbs_certificate"]["serial_number"].native)


def try_unlock_pkcs12(p12_path: Path, password: bytes) -> None:
    raw = p12_path.read_bytes()
    key, cert, _ = crypto_pkcs12.load_key_and_certificates(raw, password)
    if key is None or cert is None:
        raise ValueError("PKCS#12 abriu mas faltam chave ou certificado.")
    subj = cert.subject.rfc4514_string()
    print(f"Chave desbloqueada. Certificado: {subj}")


def main() -> int:
    if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except OSError:
            pass

    parser = argparse.ArgumentParser(description="Serial decimal do supervisor.p12 e teste de senha.")
    parser.add_argument(
        "-i",
        "--input",
        type=Path,
        default=Path(__file__).resolve().parent / "supervisor.p12",
        help="Caminho do arquivo .p12 (padrão: supervisor.p12 ao lado deste script).",
    )
    args = parser.parse_args()
    p12 = args.input
    if not p12.is_file():
        print(f"Arquivo não encontrado: {p12}", file=sys.stderr)
        return 1

    cert_der = extract_cert_der_from_second_safebag(p12)
    serial_dec = serial_decimal_from_cert_der(cert_der)
    print(f"Número de série (decimal): {serial_dec}")
    print(f"Número de série (hex, sem 0x): {format(serial_dec, 'x')}")

    pwd = str(serial_dec).encode("utf-8")
    try_unlock_pkcs12(p12, pwd)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
