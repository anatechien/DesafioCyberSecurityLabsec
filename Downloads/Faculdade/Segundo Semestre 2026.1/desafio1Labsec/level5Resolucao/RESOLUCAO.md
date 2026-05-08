# Nível 5 — Blackwall (serial numbers das assinaturas)

## Enunciado e artefatos

- Objetivo: **serial number concatenado de todas as assinaturas**.
- Texto menciona `dante.pdf`; neste conjunto de ficheiros o PDF raiz é **`hell.pdf`** (equivalente ao artefato da narrativa).
- Regras gerais do laboratório que importam aqui:
  - **Flag em hexadecimal:** minúsculas, **sem** prefixo `0x`.
  - **SHAKE:** quando usado, **512 bits** de saída (64 bytes → **128 caracteres hex**).

## O que é “serial number” neste desafio

Cada assinatura PDF guarda um **PKCS#7** em **`/Contents <...>`** (hex). Dentro há **certificados X.509**. O serial é o campo **Serial Number** do certificado do **assinante**.

Para cada bloco PKCS#7 destes ficheiros há um certificado de assinante; usamos **`certs[0]`** após `load_der_pkcs7_certificates`. Isto coincide com o **`SignerInfo`** (issuer + serial) verificado com `asn1crypto`: o serial do assinante é o mesmo que o do primeiro certificado.

**Dois formatos úteis de serial em hex:**

| Forma | Significado | Tamanho da concatenação (44 assinaturas) |
|--------|-------------|------------------------------------------|
| **(A) Hex mínimo** | Inteiro do serial, `format(n, "x")` — o que Python expõe como `certificate.serial_number` | **1244** caracteres |
| **(B) INTEGER no DER** | Octetos do **ASN.1 INTEGER** no `TBSCertificate` (pode incluir byte `00` à esquerda para INTEGER positivo) | **1332** caracteres |

Se o verificador implementar “serial como no certificado em DER”, espera **(B)**. Se implementar “valor inteiro em hex”, espera **(A)** — o mais comum em CTFs.

## Ordem de processamento

1. **Ordem dos PDFs (Inferno):**  
   `hell.pdf` → `_emb_Lust.pdf` → … → `_emb_Treachery.pdf` (9 ficheiros).

2. **Dentro de cada PDF:** percorrer **`/FT /Sig`** na ordem em que aparecem e, para cada um, o **`/Contents <hex>`** seguinte.

3. **Contagem:** 8 + 8 + 7 + 6 + 5 + 4 + 3 + 2 + 1 = **44** assinaturas.

Abrir só `hell.pdf` e seguir **ficheiros embutidos** em cadeia (como num script com PyMuPDF) produz a **mesma sequência de 44 seriais** do que processar os nove PDFs já extraídos na lista acima — a ordem foi verificada.

## O que não é a resposta (para este enunciado)

- **Hash do PDF inteiro** ou da região **ByteRange** (SHAKE/SHA sobre bytes do documento) é outro exercício; aqui pede-se explicitamente **serial do certificado** dentro da assinatura.
- **Keystore .p12** entra em outros níveis; o nível 5 aqui resolve-se a partir dos **PDFs** e do PKCS#7 em `/Contents`.

## SHAKE-256 (512 bits) — quando faz sentido

As regras do lab fixam **512 bits** de saída para SHAKE. Se a plataforma, **depois** de montar a concatenação **(A)**, pedir um **resumo** (por vezes não dizem explicitamente), candidatos razoáveis são:

- **(C)** `SHAKE256(concatenação ASCII da string hex de (A))` — 128 hex.
- **(D)** `SHAKE256(bytes.fromhex(concatenação (A)))` — 128 hex.

O script gera ambos em ficheiros separados para teste.

## Como executar

```bash
pip install cryptography
python resolucao_nivel5.py
```

## Ficheiros gerados

| Ficheiro | Conteúdo |
|----------|----------|
| `concat_serials_nivel5.txt` | **(A)** Hex mínimo, 44 seriais concatenados |
| `concat_serials_nivel5_der_integer.txt` | **(B)** Hex dos octetos do INTEGER no DER |
| `shake256_512b_concat_minimal_ascii.txt` | **(C)** SHAKE-256, 512 bits, sobre string ASCII de (A) |
| `shake256_512b_concat_minimal_bin.txt` | **(D)** SHAKE-256, 512 bits, sobre bytes de `fromhex((A))` |

## Prioridade sugerida para colar na plataforma

1. **(A)** `concat_serials_nivel5.txt` — leitura literal do enunciado + uso habitual de “serial” como inteiro.  
2. **(B)** se (A) falhar — alinhado ao encoding ASN.1 do certificado.  
3. **(C)** ou **(D)** se a página pedir “flag em hex” curta e as regras SHAKE se aplicarem a um passo final.

## Dependências

- Python 3  
- **`cryptography`**
