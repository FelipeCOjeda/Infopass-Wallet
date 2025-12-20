# Infopass-Wallet
Gerador determinístico de carteira **Bitcoin BIP84 (Native SegWit / P2WPKH)** a partir de:  1) Um **texto livre** (colado no GUI)   2) Uma **BIP39 passphrase** (o “segredo”)
# InfoPass → BIP84 (watch-only)

Gerador determinístico de carteira **Bitcoin BIP84 (Native SegWit / P2WPKH)** a partir de:

1) Um **texto livre** (colado no GUI)  
2) Uma **BIP39 passphrase** (o “segredo”)

O app transforma `texto + passphrase` em **entropia (256-bit)** usando:

- `SHA512(texto + passphrase)` → inverte os bytes → `SHA256(resultado)`

Com essa entropia, gera uma **mnemonic BIP39 de 24 palavras**, deriva a conta **BIP84** e exibe:

- ✅ 24 palavras (mnemonic) *(oculta por padrão)*
- ✅ 2+ endereços BIP84 `bc1...` (External `/0/` e Change `/1/`)
- ✅ `xpub` e `zpub` da conta
- ✅ Descriptors para Sparrow/Specter
- ✅ Export JSON (Sparrow-like) e Export Descriptors `.txt`

> ⚠️ **Atenção (segurança)**: se o texto for público (letra de música, frase famosa etc.), **só a BIP39 passphrase forte** impede ataques de força bruta/dicionário. Trate a passphrase como a sua chave de verdade.

---

## Features

- GUI em Tkinter (Windows-friendly)
- Fonte (texto) direto no app (sem `fonte.txt`)
- Campo de BIP39 passphrase com opção “Mostrar”
- **Mnemonic escondida** por padrão + botão **Revelar mnemonic**
- Botão **Copiar mnemonic** (só funciona se estiver revelada)
- Botão **Copiar addr/xpub/zpub**
- Botão **Copiar descriptors**
- Abas:
  - External `/0/` com N endereços
  - Change `/1/` com N endereços
- Duplo clique em um endereço → copia pro clipboard
- Export:
  - `descriptors.txt` (Sparrow/Specter)
  - `wallet.json` (Sparrow-like / watch-only)

---

## Estrutura do projeto

