#!/usr/bin/env python3
"""
Nível 4 — RSA textbook: S = m^d mod n (sem padding).
Lê number.txt (hex), assina com a chave do supervisor.p12 e grava signature.txt.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12


def main() -> int:
    if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except OSError:
            pass

    base = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--p12",
        type=Path,
        default=base.parent / "level3Resolucao" / "supervisor.p12",
    )
    parser.add_argument("--password", default="527522290")
    parser.add_argument("--number", type=Path, default=base / "number.txt")
    parser.add_argument("--out", type=Path, default=base / "signature.txt")
    args = parser.parse_args()

    if not args.p12.is_file():
        print(f"Arquivo não encontrado: {args.p12}", file=sys.stderr)
        return 1

    key, _, _ = pkcs12.load_key_and_certificates(
        args.p12.read_bytes(), args.password.encode("utf-8")
    )
    if key is None or not isinstance(key, rsa.RSAPrivateKey):
        print("PKCS#12 sem chave RSA.", file=sys.stderr)
        return 1

    pn = key.private_numbers()
    n, d = pn.public_numbers.n, pn.d

    h = args.number.read_text(encoding="utf-8").strip().replace("0x", "").replace(" ", "")
    m = int(h, 16)
    if m >= n:
        print("Aviso: m >= n (inesperado para este desafio).", file=sys.stderr)

    sig = pow(m, d, n)
    hex_sig = format(sig, "x")
    args.out.write_text(hex_sig + "\n", encoding="utf-8")
    print(hex_sig)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
