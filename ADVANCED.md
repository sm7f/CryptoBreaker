# 🚀 CryptoBreaker - Guia Avançado

## 🔧 Integrações Avançadas

### 1. Pipe com Grep
```bash
# Encontra hashes em arquivos
grep -r "hash" /path/to/files | python3 crypto_breaker.py

# Extrai hashes de logs
cat access.log | grep -oE '[a-f0-9]{32}' | while read hash; do
    python3 crypto_breaker.py "$hash"
done
```

### 2. Automatização em Scripts
```python
import subprocess

def analyze_hash(hash_value):
    result = subprocess.run(
        ['python3', 'crypto_breaker.py', hash_value],
        capture_output=True,
        text=True
    )
    return result.stdout

# Uso
hash_found = "5f4dcc3b5aa765d61d8327deb882cf99"
analysis = analyze_hash(hash_found)
print(analysis)
```

### 3. Batch Processing
```bash
# Processa arquivo com múltiplos hashes
while read hash; do
    echo "=== Analisando: $hash ==="
    python3 crypto_breaker.py "$hash"
    echo ""
done < hashes.txt
```

### 4. Integração com Hashcat
```bash
# CryptoBreaker identifica → Hashcat executa
HASH="5f4dcc3b5aa765d61d8327deb882cf99"

# Identifica tipo
python3 crypto_breaker.py "$HASH" > output.txt

# Extrai mode do Hashcat (exemplo)
MODE=$(grep "Hashcat Mode" output.txt | head -1 | grep -oE '[0-9]+')

# Executa Hashcat automaticamente
echo "$HASH" > hash.txt
hashcat -m $MODE -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

### 5. Web API (Flask Example)
```python
from flask import Flask, request, jsonify
import subprocess

app = Flask(__name__)

@app.route('/analyze', methods=['POST'])
def analyze():
    hash_value = request.json.get('hash')
    result = subprocess.run(
        ['python3', 'crypto_breaker.py', hash_value],
        capture_output=True,
        text=True
    )
    return jsonify({'result': result.stdout})

if __name__ == '__main__':
    app.run(port=5000)
```

## 🎯 Técnicas Avançadas CTF

### 1. Multi-Stage Decoding
Alguns CTFs usam encoding em múltiplas camadas:

```
Base64 → Hex → ROT13 → Caesar → Flag
```

CryptoBreaker detecta automaticamente Base64 aninhado. Para outros:
1. Rode primeira vez
2. Pegue output decodificado
3. Rode novamente no output
4. Repita até flag

### 2. Custom Encodings
Se CryptoBreaker não reconhecer:
```python
# Adicione ao crypto_breaker.py

def decode_custom(self, text: str) -> str:
    """Decodifica encoding customizado do CTF"""
    # Seu código aqui
    decoded = text[::-1]  # Exemplo: reverse string
    return decoded
```

### 3. Hash com Salt
Se hash tiver salt visível:
```
$6$SALT$HASH
```

CryptoBreaker mostra formato completo. Para Hashcat:
```bash
# Cole linha completa no arquivo
echo '$6$saltsalt$hash...' > hash.txt
hashcat -m 1800 hash.txt rockyou.txt
```

### 4. Wordlist Customizada
Para CTFs com contexto específico:
```bash
# Gera wordlist do site do CTF
cewl https://ctf-challenge.com -d 2 -m 5 -w wordlist.txt

# Usa no CryptoBreaker identificado hash
hashcat -m 0 hash.txt wordlist.txt
```

## 💡 Workflow Otimizado

### Setup Inicial CTF
```bash
# 1. Abre CryptoBreaker em terminal dedicado
tmux new -s crypto
python3 crypto_breaker.py

# 2. Mantém em background
# Ctrl+B, D para detach

# 3. Volta quando precisar
tmux attach -t crypto
```

### Durante o CTF
```
┌─────────────────────────────────────┐
│ 1. Achou algo suspeito?             │
│    → Cola no CryptoBreaker          │
└─────────────────────────────────────┘
                ↓
┌─────────────────────────────────────┐
│ 2. Identificou automaticamente?     │
│    → Sim: Usa resultado             │
│    → Não: Tenta decodificações      │
└─────────────────────────────────────┘
                ↓
┌─────────────────────────────────────┐
│ 3. Quebrou online?                  │
│    → Sim: Flag encontrada! 🎉       │
│    → Não: Copia comando Hashcat     │
└─────────────────────────────────────┘
                ↓
┌─────────────────────────────────────┐
│ 4. Hashcat rodando                  │
│    → Aguarda resultado              │
│    → Testa próximo desafio          │
└─────────────────────────────────────┘
```

## 🔍 Debugging

### Hash não quebra?
1. **Verifica formato**
   ```bash
   # Remove espaços/newlines
   echo -n "hash_aqui" | md5sum
   ```

2. **Testa wordlists diferentes**
   ```bash
   # FastTrack (rápido)
   hashcat -m MODE hash.txt /usr/share/wordlists/fasttrack.txt
   
   # RockYou (completo)
   hashcat -m MODE hash.txt /usr/share/wordlists/rockyou.txt
   ```

3. **Adiciona regras**
   ```bash
   # Com mutações
   hashcat -m MODE hash.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
   ```

### Encoding estranho?
```python
# Teste manualmente no Python
import base64
text = "string_suspeita"

# Base64
print(base64.b64decode(text))

# Hex
print(bytes.fromhex(text))

# ROT13
import codecs
print(codecs.decode(text, 'rot_13'))
```

## 📊 Performance Tips

### 1. Use Hashcat com GPU
```bash
# Verifica GPU
hashcat -I

# Usa GPU específica
hashcat -m MODE hash.txt rockyou.txt -d 1
```

### 2. Otimizações Hashcat
```bash
# Senhas curtas (< 32 chars)
hashcat -m MODE hash.txt rockyou.txt -O

# Workload máximo
hashcat -m MODE hash.txt rockyou.txt -w 4

# Combina ambos
hashcat -m MODE hash.txt rockyou.txt -O -w 4
```

### 3. Processa Múltiplos Hashes
```bash
# Arquivo com vários hashes
cat hashes.txt
5f4dcc3b5aa765d61d8327deb882cf99
21232f297a57a5a743894a0e4a801fc3
e10adc3949ba59abbe56e057f20f883e

# Hashcat processa todos de uma vez
hashcat -m 0 hashes.txt rockyou.txt --remove
# --remove tira hashes quebrados do arquivo
```

## 🛡️ Segurança

### Não Use em Produção!
CryptoBreaker é para CTFs/educação. Não use em sistemas reais.

### APIs Online
Hashes enviados para APIs online ficam em seus bancos de dados.
Para hashes sensíveis, use apenas localmente.

### Rate Limiting
API online tem limite. Para muitos hashes, use Hashcat local.

## 🎓 Aprendizado Contínuo

### Adicione Novos Tipos
```python
# No método identify_hash(), adicione:

# Exemplo: JWT
if text.count('.') == 2:
    possible_types.append(("JWT", "16500", "Exemplo: hashcat -m 16500"))
```

### Contribua!
Encontrou tipo não suportado? Adicione e faça PR!

### Estude os Padrões
CryptoBreaker ensina a identificar visualmente:
- 32 chars hex → MD5 ou NTLM
- 40 chars hex → SHA1
- 64 chars hex → SHA256
- Começa com $ → Crypt format
- Só A-Za-z0-9+/= → Provável Base64

## 🏆 CTF War Stories

### Case 1: Base64 Triplo
```
Input: V1ZoU2IxVjZSbmRWVkVaelRVVm9WRlpWVWtOVk1...
Camadas: Base64 → Base64 → Base64 → Flag
CryptoBreaker pegou as 2 primeiras automaticamente!
```

### Case 2: MD5 no Rodapé
```
Input: Inspecionou HTML, achou comentário:
<!-- backup_password: 5f4dcc3b5aa765d61d8327deb882cf99 -->

CryptoBreaker quebrou online em 1 segundo = "password"
Fez login e pegou flag!
```

### Case 3: /etc/shadow Completo
```
Input: root:$6$rounds=5000$...:18500:0:99999:7:::

CryptoBreaker identificou SHA512 Crypt
Gerou comando Hashcat
10 minutos depois = senha quebrada!
```

## 📞 Contato & Contribuições

Quer adicionar features? Achou bug?
- GitHub Issues
- Pull Requests
- Email

Ideias welcome:
- Mais APIs online
- Machine Learning para identificação
- Plugin para Burp Suite
- Integração com John the Ripper

---

**Happy Hacking! 🔓**
