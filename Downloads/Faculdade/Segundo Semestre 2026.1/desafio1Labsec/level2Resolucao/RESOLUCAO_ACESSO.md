# Resolução: extrair o código de acesso (keystore + `access_code.enc`)

Este documento resume o que foi necessário fazer para abrir o cofre e obter o código em texto claro.

---

## Artefatos

| Arquivo | Função |
|---------|--------|
| `employee.p12` | Keystore PKCS#12 com certificado e **chave privada RSA** (2048 bits). |
| `password.txt` | Senha para desbloquear a **chave privada** dentro do `.p12`. |
| `access_code.enc` | Dados cifrados com a **chave pública** correspondente (normalmente RSA). |

**Observação do enunciado:** em muitos cenários o ficheiro `.p12` pode ser tratado sem “senha de ficheiro”; o que costuma estar protegido por senha é o **pacote da chave privada** dentro do keystore. Aqui a senha em `password.txt` foi usada para extrair a chave privada.

---

## 1. Observar o tamanho do ficheiro cifrado

- `access_code.enc` tem **256 bytes**.
- Uma chave **RSA-2048** produz blocos de ciphertext desse tamanho (2048 ÷ 8 = 256).
- Conclusão: é muito provável que seja **RSA** (uma única operação de cifra com a chave pública do certificado).

---

## 2. Por que não usei só a linha de comando OpenSSL

No ambiente testado, o comando `openssl` **não estava no PATH** do Windows. Por isso o mesmo fluxo foi feito em **Python** com a biblioteca **cryptography** (que usa OpenSSL por baixo).

Se tiveres OpenSSL instalado, podes obter a chave privada em PEM assim (substitui caminhos e senha):

```bash
openssl pkcs12 -in employee.p12 -nodes -passin pass:SENHA_AQUI -nocerts -out private.pem
```

Depois tentarias decifrar com `openssl pkeyutl -decrypt` (conforme o modo de padding usado na cifra).

---

## 3. Script em Python (o essencial)

Instalação (se ainda não tiveres):

```bash
pip install cryptography
```

Lógica:

1. Carregar o `.p12` com `pkcs12.load_key_and_certificates` e a senha em bytes.
2. Confirmar que a chave é **RSA** e **2048** bits (bate com os 256 bytes do ficheiro).
3. Ler `access_code.enc` como bytes brutos.
4. Tentar `private_key.decrypt(...)` com os paddings habituais:
   - **PKCS#1 v1.5** — aqui deu bytes que **não** eram texto legível (padding errado ou não é este modo).
   - **OAEP** — o que costuma ser usado em aplicações modernas.

Para **RSA-OAEP**, o par de algoritmos (hash da OAEP e MGF1) tem de ser **o mesmo** que quem cifrou usou. Neste desafio funcionou:

- **Hash da OAEP:** SHA-256  
- **MGF1:** SHA-1  

Código mínimo que decifra:

```python
from pathlib import Path
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

base = Path(__file__).resolve().parent
password = Path(base / "password.txt").read_text().strip().encode()

p12_data = (base / "employee.p12").read_bytes()
private_key, cert, _ = pkcs12.load_key_and_certificates(
    p12_data, password, default_backend()
)

ciphertext = (base / "access_code.enc").read_bytes()

plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA1()),
        algorithm=hashes.SHA256(),
        label=None,
    ),
)
print(plaintext.decode("utf-8"))
```

Saída esperada:

```text
Seu número da sorte é: 567320
```

O **código de acesso** em texto claro é o número: **`567320`**.

---

## 4. Resumo mental

1. Senha do post-it → abre a chave privada no `.p12`.  
2. Quem gerou `access_code.enc` cifrou com a **chave pública** (do certificado).  
3. Tu **decifras com a chave privada** (RSA + OAEP com os parâmetros certos).  
4. O resultado é uma mensagem UTF-8; o código pedido é o valor numérico na frase.

---

## 5. Notas do enunciado (hex e SHAKE)

- **Flag em hexadecimal:** usar **minúsculas** e **sem** prefixo `0x` (para outros níveis do desafio).  
- **SHAKE:** quando pedirem resumo da família SHAKE, considerar **512 bits** de saída — não foi necessário para este ficheiro em concreto, mas vale para exercícios seguintes.

---

*Gerado para acompanhar a pasta `level2Resolucao`.*
