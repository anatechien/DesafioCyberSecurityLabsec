# Desafio LabSec — Cibersegurança

Desafio progressivo de cibersegurança (LabSec): criptografia aplicada em Python — SHAKE/XOR, PKCS#12, RSA-OAEP, serial de certificado X.509, RSA “textbook” e análise de assinaturas digitais em PDF (PKCS#7).

## O que é este projeto

Projeto em Python que resolve uma sequência de níveis sobre **funções de hash (SHAKE-256)**, **armazenamento de chaves PKCS#12**, **RSA com OAEP**, **extração de metadados de certificados X.509** e **assinaturas digitais em PDF**.

- **Nível 1:** combinação de **SHAKE-256** (saída de 512 bits) sobre um PDF e sobre a matrícula, seguida de **XOR** entre os digest — exercício de manipulação de bytes e representação em hexadecimal.
- **Nível 2:** uso de um **keystore `.p12`** e senha para extrair a **chave privada RSA** e **decifrar** `access_code.enc` com **RSA-OAEP**.
- **Nível 3:** análise do **`supervisor.p12`** para obter o **número de série do certificado** e validar o desbloqueio do arquivo.
- **Nível 4:** **RSA em modo “textbook”** (sem padding): assinatura como \(S = m^d \bmod n\) a partir de um valor em **hex** em ficheiro, usando a chave do supervisor.
- **Nível 5 (“Blackwall”):** percorrer uma **cadeia de PDFs**, extrair **PKCS#7** das assinaturas, obter o **serial do certificado do assinante** e **concatenar** os seriais (44 assinaturas), com variantes documentadas nos ficheiros de resolução.

**Stack:** Python 3, `cryptography`, `asn1crypto` onde necessário.

## Estrutura (pastas principais)

| Pasta | Conteúdo |
|-------|-----------|
| `level1Python/` | Script do nível 1 |
| `level2Resolucao/` | RSA-OAEP + `.p12` |
| `level3Resolucao/` | PKCS#12 supervisor / serial |
| `level4Resolucao/` | RSA textbook |
| `level5Resolucao/` | PDFs, seriais, SHAKE |

## Como o GitHub mostra o README

Coloque **`README.md` na raiz do repositório** (mesmo nível da pasta `.git`). O GitHub renderiza esse ficheiro automaticamente na página inicial do repo.

Para enviar depois de criar/editar:

```powershell
cd "c:\Users\Ana Teichmann\Downloads\Faculdade\Segundo Semestre 2026.1\desafio1Labsec"
git add README.md
git commit -m "Adiciona README do desafio LabSec"
git push
```

Se o repositório ainda não existir no GitHub, crie-o vazio e faça o primeiro `push` incluindo este ficheiro.
