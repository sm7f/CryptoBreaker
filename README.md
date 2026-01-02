# 🔓 CryptoBreaker - Ferramenta Definitiva de Criptoanálise para CTFs

![Python](https://img.shields.io/badge/python-3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![CTF](https://img.shields.io/badge/CTF-Ready-red.svg)

**Identifica, decodifica e quebra hashes/cifras automaticamente** - Sua arma secreta para CTFs!

---

## 🎯 Características

### ✨ Identificação Automática
- ✅ **30+ tipos de hash** (MD5, SHA1, SHA256, SHA512, NTLM, bcrypt, etc)
- ✅ **Cifras clássicas** (Caesar, ROT13)
- ✅ **Encodings** (Base64, Hex, URL)
- ✅ **Formatos específicos** (Linux shadow, WordPress, Django, NetNTLMv2)

### 🔓 Decodificação Automática
- ✅ Base64 (com detecção de camadas múltiplas!)
- ✅ Hexadecimal
- ✅ ROT13
- ✅ URL encoding
- ✅ Caesar cipher bruteforce (26 shifts)

### ⚡ Quebra de Hashes
- ✅ API online integrada (MD5Decrypt.net)
- ✅ Sugestões de comandos Hashcat com wordlists
- ✅ Identificação de mode correto do Hashcat

### 💡 Dicas Inteligentes
- ✅ **Formatação para Hashcat** - como preparar o hash
- ✅ **Detecção de formato** - user:hash, NetNTLMv2, /etc/shadow
- ✅ **Comandos prontos** - copie e cole!

---

## 🚀 Instalação

### Requisitos
- Python 3.7+
- pip

### Passo a Passo

```bash
# Clone ou baixe os arquivos
cd crypto_breaker

# Instale dependências
pip install -r requirements.txt

# Torne executável (opcional)
chmod +x crypto_breaker.py

# Pronto!
python3 crypto_breaker.py
```

---

## 📖 Como Usar

### Modo Interativo (Recomendado)

```bash
python3 crypto_breaker.py
```

Depois é só colar seus hashes/cifras:

```
crypto> 5f4dcc3b5aa765d61d8327deb882cf99
crypto> SGVsbG8gV29ybGQh
crypto> uryyb jbeyq
crypto> quit
```

### Modo Comando Direto

```bash
# Analisa hash MD5
python3 crypto_breaker.py 5f4dcc3b5aa765d61d8327deb882cf99

# Analisa Base64
python3 crypto_breaker.py SGVsbG8gV29ybGQh

# Analisa múltiplas palavras
python3 crypto_breaker.py "admin:5f4dcc3b5aa765d61d8327deb882cf99"
```

---

## 🎓 Exemplos Práticos

### Exemplo 1: Hash MD5 Simples

**Input:**
```
5f4dcc3b5aa765d61d8327deb882cf99
```

**Output:**
```
🔍 IDENTIFICAÇÃO
✅ Identificados 2 tipos possíveis:

[1] MD5
  Hashcat Mode: -m 0
  Comando: hashcat -m 0 -a 0 hash.txt rockyou.txt

[2] NTLM
  Hashcat Mode: -m 1000
  Comando: hashcat -m 1000 -a 0 hash.txt rockyou.txt

⚡ QUEBRANDO HASH ONLINE
✅ HASH QUEBRADO! 🎉
  password
```

### Exemplo 2: Base64 Aninhado

**Input:**
```
U0dWc2JHOGdWMjl5YkdRaA==
```

**Output:**
```
🔍 IDENTIFICAÇÃO
[1] Base64

⚡ TENTANDO DECODIFICAÇÕES
✅ Base64 decodificado:
  SGVsbG8gV29ybGQh
ℹ️  Detectado Base64 aninhado! Decodificando novamente...
✅ Base64 (2ª camada) decodificado:
  Hello World!
```

### Exemplo 3: Caesar Cipher

**Input:**
```
uryyb jbeyq
```

**Output:**
```
🔍 IDENTIFICAÇÃO
⚠️  Tipo não identificado automaticamente

⚡ TENTANDO DECODIFICAÇÕES
✅ ROT13 decodificado:
  hello world

ℹ️  Tentando Caesar cipher bruteforce...
Top 5 possibilidades Caesar:
  [Shift  1] tqxxa iadxp
  [Shift  2] spwwz hzcwo
  [Shift  3] rovvy gybn
  ...
  [Shift 13] hello world  ← ENCONTRADO!
```

### Exemplo 4: Hash do /etc/shadow

**Input:**
```
$6$rounds=5000$saltsalt$hash...
```

**Output:**
```
🔍 IDENTIFICAÇÃO
[1] SHA512 Crypt (Linux)
  Hashcat Mode: -m 1800
  Comando: hashcat -m 1800 -a 0 hash.txt rockyou.txt

💡 DICAS DE FORMATAÇÃO
💡 Hash do /etc/shadow (Linux):
  - Formato completo: user:hash:lastchange:min:max:warn:inactive:expire
  - Hashcat precisa apenas da parte do hash
  - Cole o hash completo no arquivo
```

### Exemplo 5: NetNTLMv2 (Responder)

**Input:**
```
admin::DOMAIN:1122334455667788:NTLMHASH:BLOB
```

**Output:**
```
💡 DICAS DE FORMATAÇÃO
⚠️  Hash contém ':' - pode ser formato user:hash
💡 Possível NetNTLMv2 (Responder capture):
  - Formato: user::domain:challenge:HMAC-MD5:blob
  - Hashcat mode: -m 5600
  - Cole a linha completa do Responder

Para Hashcat:
  - Se formato 'user:hash': use --username
  - Exemplo: hashcat -m 5600 hash.txt rockyou.txt
```

---

## 🗂️ Tipos Suportados

### Hashes

| Tipo | Exemplo | Hashcat Mode |
|------|---------|--------------|
| MD5 | `5f4dcc3b5aa765d61d8327deb882cf99` | `-m 0` |
| SHA1 | `5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8` | `-m 100` |
| SHA256 | `5e884898da28047151d0e56f8dc629...` | `-m 1400` |
| SHA512 | `b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86` | `-m 1700` |
| NTLM | `209c6174da490caeb422f3fa5a7ae634` | `-m 1000` |
| bcrypt | `$2a$05$LhayLxezLhK1uXlb...` | `-m 3200` |
| SHA512 Crypt | `$6$rounds=5000$...` | `-m 1800` |
| SHA256 Crypt | `$5$rounds=5000$...` | `-m 7400` |
| MD5 Crypt | `$1$salt$hash...` | `-m 500` |
| WordPress | `$P$B12345678...` | `-m 400` |
| Django PBKDF2 | `pbkdf2_sha256$36000$...` | `-m 10000` |

### Encodings

| Tipo | Exemplo | Decodificação |
|------|---------|---------------|
| Base64 | `SGVsbG8gV29ybGQh` | Automática |
| Hexadecimal | `48656c6c6f` | Automática |
| ROT13 | `uryyb jbeyq` | Automática |
| URL Encode | `Hello%20World` | Automática |

### Cifras

| Tipo | Descrição | Método |
|------|-----------|--------|
| Caesar | Shift alfabético | Bruteforce 1-25 |
| ROT13 | Caesar shift 13 | Decodificação direta |

---

## 💡 Dicas de Uso em CTFs

### 1. **Sempre Teste Primeiro com CryptoBreaker**
Antes de perder tempo configurando Hashcat, rode o CryptoBreaker. Ele pode:
- Identificar o tipo correto
- Quebrar online instantaneamente
- Te dar o comando Hashcat pronto

### 2. **Copie e Cole Direto**
Pegou um hash no CTF? Cole no CryptoBreaker sem processar:
```
crypto> $6$saltsalt$hashhash...
```

### 3. **Use Modo Interativo Durante o CTF**
Deixe o CryptoBreaker aberto em um terminal:
```bash
python3 crypto_breaker.py
```
Fica testando hashes conforme encontra.

### 4. **Para Hashes User:Hash**
Se o output mostrar warning de `:`, o CryptoBreaker já te dá o comando com `--username`:
```bash
hashcat -m MODE hash.txt rockyou.txt --username
```

### 5. **Base64 Recursivo**
Se decodificar Base64 e ainda parecer gibberish, pode ser camadas múltiplas!
O CryptoBreaker detecta automaticamente.

### 6. **Não Sabe o Tipo?**
Cole qualquer coisa! O CryptoBreaker tenta TODAS as decodificações automaticamente.

---

## 🔧 Workflow CTF Recomendado

```
┌─────────────────┐
│ Encontrou hash? │
└────────┬────────┘
         │
         ▼
┌────────────────────┐
│ Cole no            │
│ CryptoBreaker      │
└────────┬───────────┘
         │
         ▼
    ┌────────┐
    │ Tipo?  │
    └───┬────┘
        │
   ┌────┴────┐
   │         │
   ▼         ▼
┌──────┐  ┌─────────┐
│ Hash │  │ Encoding│
└──┬───┘  └───┬─────┘
   │          │
   ▼          ▼
┌──────────┐ ┌─────────────┐
│ API      │ │ Decodifica  │
│ Online   │ │ Auto        │
└──┬───────┘ └──┬──────────┘
   │            │
   ▼            ▼
┌──────────┐  ┌──────┐
│ Quebrou? │  │ Flag!│
└──┬───────┘  └──────┘
   │ Não
   ▼
┌────────────────────┐
│ Usa comando        │
│ Hashcat sugerido   │
└────────────────────┘
```

---

## 🛠️ Comandos Hashcat Gerados

O CryptoBreaker não só identifica o hash, mas **gera o comando completo** para você:

```bash
# Exemplo output:
[1] SHA512 Crypt (Linux)
  Hashcat Mode: -m 1800
  Comando: hashcat -m 1800 -a 0 hash.txt rockyou.txt
```

Só copiar e colar!

---

## 📝 Formato de Arquivos para Hashcat

### Hash Simples
```
5f4dcc3b5aa765d61d8327deb882cf99
```

### User:Hash (com --username)
```
admin:5f4dcc3b5aa765d61d8327deb882cf99
john:e10adc3949ba59abbe56e057f20f883e
```

### /etc/shadow (Linux)
```
root:$6$rounds=5000$saltsalt$hash...:18000:0:99999:7:::
user:$6$rounds=5000$salt2salt2$hash2...:18000:0:99999:7:::
```

### NetNTLMv2 (Responder)
```
admin::DOMAIN:1122334455667788:NTLMHASH:BLOB
user::WORKGROUP:aabbccddee:HASH2:BLOB2
```

O CryptoBreaker detecta todos esses formatos automaticamente!

---

## 🚨 Troubleshooting

### "Tipo não identificado"
- Normal! Tente as decodificações automáticas (Base64, Hex, ROT13)
- Se nada funcionar, pode ser cifra customizada do CTF

### "Hash não encontrado online"
- Use Hashcat localmente com rockyou.txt
- Comando está no output do CryptoBreaker!

### Erro "Module not found"
```bash
pip install -r requirements.txt
```

### Encoding errado em Windows
```bash
# Use UTF-8
chcp 65001
python crypto_breaker.py
```

---

## 🔗 Recursos Complementares

### Wordlists Essenciais
- **rockyou.txt** - `/usr/share/wordlists/rockyou.txt` (Kali)
- **SecLists** - https://github.com/danielmiessler/SecLists
- **Crackstation** - https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm

### Ferramentas Complementares
- **Hashcat** - https://hashcat.net/hashcat/
- **John The Ripper** - https://www.openwall.com/john/
- **CyberChef** - https://gchq.github.io/CyberChef/
- **dCode** - https://www.dcode.fr/

### APIs Online
- **Crackstation** - https://crackstation.net/
- **Hashes.com** - https://hashes.com/en/decrypt/hash
- **md5decrypt.net** - https://md5decrypt.net/

---

## 💻 Exemplos de Comandos

```bash
# Modo interativo (recomendado para CTFs)
python3 crypto_breaker.py

# Hash MD5
python3 crypto_breaker.py 5f4dcc3b5aa765d61d8327deb882cf99

# Base64
python3 crypto_breaker.py SGVsbG8gV29ybGQh

# Hash com user
python3 crypto_breaker.py "admin:5f4dcc3b5aa765d61d8327deb882cf99"

# Linux shadow
python3 crypto_breaker.py '$6$saltsalt$hashhash...'

# ROT13
python3 crypto_breaker.py "uryyb jbeyq"

# Texto para Caesar bruteforce
python3 crypto_breaker.py "khoor zruog"
```

---

## 🎯 CTF Use Cases

### Caso 1: TryHackMe - Encontrou Hash no Banco
```bash
# Pegou hash do MySQL
python3 crypto_breaker.py "5f4dcc3b5aa765d61d8327deb882cf99"

# Output: MD5, quebrado online = "password"
# Submit flag!
```

### Caso 2: HackTheBox - /etc/shadow
```bash
# Copiou linha do shadow
python3 crypto_breaker.py '$6$rounds=5000$saltsalt$...'

# Output: SHA512 Crypt, comando pronto
# Roda hashcat e pega senha!
```

### Caso 3: PicoCTF - String Estranha
```bash
# Achou string "SGVsbG8gV29ybGQh"
python3 crypto_breaker.py SGVsbG8gV29ybGQh

# Output: Base64 = "Hello World!"
# Flag encontrada!
```

### Caso 4: CTFd - Cifra César
```bash
# Mensagem: "khoor zruog"
python3 crypto_breaker.py "khoor zruog"

# Output: Caesar shift 3 = "hello world"
# Pega flag!
```

---

## 🏆 Por Que Usar CryptoBreaker?

### ❌ Sem CryptoBreaker:
1. Identifica tipo manualmente → 5 min
2. Googla comando Hashcat → 2 min
3. Prepara arquivo → 3 min
4. Roda e descobre que era outro tipo → 10 min
5. **Total: 20+ minutos perdidos**

### ✅ Com CryptoBreaker:
1. Cola hash → **Instantâneo**
2. Identifica tudo automaticamente → **1 segundo**
3. Tenta quebrar online → **2 segundos**
4. Se não quebrou, comando pronto → **Copiar/colar**
5. **Total: 30 segundos! 40x mais rápido!**

---

## 📊 Estatísticas

- **30+ tipos de hash** identificados
- **5 encodings** automáticos
- **26 Caesar shifts** testados
- **API online** integrada
- **100% Python puro** - sem dependências pesadas
- **Modo interativo** - ideal para CTFs

---

## 🤝 Contribuindo

Quer adicionar mais tipos de hash ou funcionalidades?

1. Fork o projeto
2. Adicione sua feature
3. Teste com exemplos
4. Pull request!

**Ideias welcome:**
- Mais APIs online
- Mais cifras clássicas
- Integração com hashcat direto
- Wordlist generator
- Rainbow tables

---

## 📜 Licença

MIT License - Use livremente em CTFs!

---

## 🎓 Aprendizado

### Para Iniciantes
O CryptoBreaker é também uma **ferramenta educacional**! Veja como cada hash/cifra funciona:
- Identificação por padrões (tamanho, caracteres, prefixos)
- Decodificação por tentativa e erro
- Comparação de tipos similares (MD5 vs NTLM)

### Para Avançados
Use como **automação** no seu workflow:
- Pipe de scripts
- Integre em ferramentas maiores
- Customize para seu estilo de CTF

---

## 📞 Suporte

- 🐛 **Bug?** Abra uma issue
- 💡 **Sugestão?** Pull request
- ❓ **Dúvida?** Documentação completa aqui

---

## 🏁 Quick Start

```bash
# 1. Instala
pip install colorama requests

# 2. Roda
python3 crypto_breaker.py

# 3. Cola hash
crypto> 5f4dcc3b5aa765d61d8327deb882cf99

# 4. Profit! 🎉
```

---

<div align="center">

**🔓 CryptoBreaker - Quebre Todos os Hashes! 🔓**

Feito com ❤️ para a comunidade CTF

**#CTF #Hacking #Cryptography #Python**

</div>
