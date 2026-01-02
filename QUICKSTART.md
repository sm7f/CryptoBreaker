# 🚀 CryptoBreaker - Quick Start

## Instalação Rápida (30 segundos)

```bash
# 1. Instale dependências
pip install colorama requests

# 2. Rode!
python3 crypto_breaker.py
```

## Primeiro Teste

Cole este hash MD5:
```
5f4dcc3b5aa765d61d8327deb882cf99
```

Resultado esperado:
```
✅ MD5 identificado
✅ Hash quebrado online!
Resultado: password
```

## Comandos Básicos

```bash
# Modo interativo (recomendado)
python3 crypto_breaker.py

# Comando direto
python3 crypto_breaker.py "5f4dcc3b5aa765d61d8327deb882cf99"

# Hash com contexto
python3 crypto_breaker.py "admin:5f4dcc3b5aa765d61d8327deb882cf99"
```

## Teste Todos os Tipos

Use o arquivo `examples.txt` - copie e cole cada linha no modo interativo!

## Arquivos do Projeto

```
crypto_breaker/
├── crypto_breaker.py    # Script principal ⭐
├── requirements.txt     # Dependências
├── README.md            # Documentação completa
├── ADVANCED.md          # Guia avançado
├── examples.txt         # Exemplos de teste
├── install.sh           # Script de instalação
└── QUICKSTART.md        # Este arquivo
```

## Durante CTFs

1. **Abra em terminal separado:**
   ```bash
   python3 crypto_breaker.py
   ```

2. **Cole qualquer hash/cifra que encontrar**

3. **Copie comando Hashcat se não quebrar online**

4. **Próximo desafio!**

## Casos de Uso Rápidos

### Hash MD5/SHA1/NTLM
```
crypto> 5f4dcc3b5aa765d61d8327deb882cf99
→ Quebra online automaticamente
```

### Base64
```
crypto> SGVsbG8gV29ybGQh
→ Decodifica: Hello World!
```

### ROT13
```
crypto> uryyb jbeyq
→ Decodifica: hello world
```

### Hash Linux (/etc/shadow)
```
crypto> $6$salt$hash...
→ Identifica: SHA512 Crypt
→ Comando: hashcat -m 1800 ...
```

### Não sabe o tipo?
```
crypto> [cole qualquer coisa]
→ Tenta TODAS decodificações automaticamente!
```

## Dicas Pro

- ✅ **Sempre teste primeiro** - pode quebrar online em 1 segundo!
- ✅ **Deixe aberto** - modo interativo durante todo o CTF
- ✅ **Copie os comandos** - Hashcat pronto para usar
- ✅ **Documente** - salve hashes quebrados para referência

## Problemas?

### "Module not found"
```bash
pip install colorama requests
```

### "Permission denied"
```bash
chmod +x crypto_breaker.py
```

### Erro de encoding (Windows)
```bash
chcp 65001
```

## Próximos Passos

1. ✅ Teste com `examples.txt`
2. 📖 Leia `README.md` para detalhes
3. 🚀 Use em CTFs reais
4. 🎓 Leia `ADVANCED.md` para automação

---

**Pronto! Agora você é 40x mais rápido em CTFs! 🎯**
