# InfoPass-Wallet

Gerador determinístico de carteira **Bitcoin BIP84 (Native SegWit / P2WPKH)** a partir de texto livre + passphrase BIP39.

## Como funciona

O app transforma `texto + passphrase` em **256 bits de entropia** usando um dos três KDFs disponíveis. Com essa entropia, gera uma mnemonic BIP39 de 24 palavras, deriva a conta BIP84 e exibe endereços, xpub/zpub e descriptors.

### KDFs disponíveis

| KDF | Descrição | Quando usar |
|-----|-----------|-------------|
| **HKDF-SHA256** | RFC 5869. Rápido, padrão, sem dependência extra. | Padrão recomendado para textos com alta entropia. |
| **Argon2id** | RFC 9106. Memory-hard (64 MiB, 3 iterações). | Quando o texto-fonte tem baixa entropia (frases curtas, textos públicos). Resiste a brute-force com GPU/ASIC. |
| **Legacy** | SHA512 → reverse bytes → SHA256. | Apenas para compatibilidade com carteiras já geradas na versão anterior. |

### Fluxo de derivação

```
texto + passphrase
       │
       ▼
   KDF (HKDF / Argon2id / Legacy)
       │
       ▼
   256-bit entropy
       │
       ▼
   BIP39 mnemonic (24 palavras)
       │
       ▼
   BIP39 PBKDF2 seed (com passphrase)
       │
       ▼
   BIP32 root → m/84'/0'/0'
       │
       ▼
   xpub / zpub / endereços bc1...
```

## Instalação

```bash
# Clone
git clone https://github.com/FelipeCOjeda/Infopass-Wallet.git
cd Infopass-Wallet

# Dependências
pip install -r requirements.txt

# Executar
python gui_wallet.py
```

### Dependências

- **embit** — derivação BIP32/39/84 e geração de endereços
- **argon2-cffi** — KDF Argon2id (opcional se usar apenas HKDF/Legacy)

## Uso

1. Cole o **texto-fonte** no campo principal.
2. Digite a **BIP39 passphrase** (segredo). Quanto mais forte, melhor.
3. Selecione o **KDF** desejado.
4. Clique em **Gerar carteira**.
5. Os endereços aparecem nas abas External `/0/` e Change `/1/`.

### Exportações

- **Export Descriptors (.txt)** — compatível com Sparrow/Specter
- **Export JSON (Sparrow-like)** — watch-only wallet

### Atalhos

- Duplo clique em endereço → copia para clipboard
- Clipboard é limpo automaticamente após 30 segundos

## Estrutura

```
├── core_bip84.py      # Lógica: KDFs, derivação BIP84, Base58, exports
├── gui_wallet.py      # Interface Tkinter
├── test_core.py       # Testes unitários
├── requirements.txt   # Dependências
└── README.md
```

## Segurança

**Modelo de ameaça:** se o texto-fonte é público (letra de música, artigo, etc.), a segurança depende inteiramente da passphrase. Use Argon2id nesse cenário — ele torna brute-force ordens de magnitude mais caro.

**Recomendações:**

- Use passphrase com pelo menos 20 caracteres, misturando maiúsculas, minúsculas, números e símbolos.
- Nunca reutilize passphrase entre carteiras diferentes.
- O clipboard é limpo automaticamente após 30s, mas evite copiar a mnemonic em ambientes não confiáveis.
- A mnemonic fica em memória Python durante a sessão. Feche o app quando terminar.
- Inputs são normalizados com Unicode NFC para garantir consistência entre plataformas.

**O que este app NÃO é:**

- Não é uma carteira completa (não assina transações).
- Não armazena chaves privadas em disco.
- Não se conecta à rede Bitcoin.

## Testes

```bash
python -m pytest test_core.py -v
```

## Melhorias futuras

- [ ] Indicador visual de força da passphrase (zxcvbn)
- [ ] Suporte a BIP49 (P2SH-SegWit) e BIP44 (Legacy)
- [ ] Descriptor checksum (BIP380)
- [ ] Modo CLI (sem GUI)
- [ ] Empacotamento com PyInstaller / cx_Freeze
- [ ] Verificação de integridade do build (hash reproduzível)
- [ ] Dark mode

## Licença

MIT
