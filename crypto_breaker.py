#!/usr/bin/env python3
"""
CryptoBreaker - Ferramenta Definitiva de Criptoanálise para CTFs
Identifica, decodifica e quebra hashes/cifras automaticamente
"""

import hashlib
import base64
import binascii
import re
import requests
import json
import sys
from typing import Optional, Dict, List, Tuple
from colorama import Fore, Back, Style, init

# Inicializa colorama
init(autoreset=True)

class CryptoBreaker:
    def __init__(self):
        self.identified_types = []
        self.results = []
        
    def banner(self):
        """Exibe banner do programa"""
        print(f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════╗
║  {Fore.GREEN}█▀▀ █▀█ █▄█ █▀█ ▀█▀ █▀█   █▄▄ █▀█ █▀▀ ▄▀█ █▄▀ █▀▀ █▀█  {Fore.CYAN}║
║  {Fore.GREEN}█▄▄ █▀▄ ░█░ █▀▀ ░█░ █▄█   █▄█ █▀▄ ██▄ █▀█ █░█ ██▄ █▀▄  {Fore.CYAN}║
╠═══════════════════════════════════════════════════════════╣
║  {Fore.YELLOW}🔓 Ferramenta de Criptoanálise para CTFs{Fore.CYAN}                ║
║  {Fore.YELLOW}⚡ Identifica • Decodifica • Quebra Automaticamente{Fore.CYAN}    ║
╚═══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
        """)
    
    def print_section(self, title: str):
        """Imprime cabeçalho de seção"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}🔍 {title}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    
    def print_success(self, message: str):
        """Imprime mensagem de sucesso"""
        print(f"{Fore.GREEN}✅ {message}{Style.RESET_ALL}")
    
    def print_info(self, message: str):
        """Imprime mensagem informativa"""
        print(f"{Fore.CYAN}ℹ️  {message}{Style.RESET_ALL}")
    
    def print_warning(self, message: str):
        """Imprime aviso"""
        print(f"{Fore.YELLOW}⚠️  {message}{Style.RESET_ALL}")
    
    def print_error(self, message: str):
        """Imprime erro"""
        print(f"{Fore.RED}❌ {message}{Style.RESET_ALL}")
    
    def identify_hash(self, hash_string: str) -> List[str]:
        """Identifica possíveis tipos de hash"""
        hash_clean = hash_string.strip()
        length = len(hash_clean)
        possible_types = []
        
        # MD5
        if length == 32 and re.match(r'^[a-fA-F0-9]{32}$', hash_clean):
            possible_types.append(("MD5", "0", "Exemplo: hashcat -m 0 -a 0 hash.txt rockyou.txt"))
        
        # SHA1
        if length == 40 and re.match(r'^[a-fA-F0-9]{40}$', hash_clean):
            possible_types.append(("SHA1", "100", "Exemplo: hashcat -m 100 -a 0 hash.txt rockyou.txt"))
        
        # SHA256
        if length == 64 and re.match(r'^[a-fA-F0-9]{64}$', hash_clean):
            possible_types.append(("SHA256", "1400", "Exemplo: hashcat -m 1400 -a 0 hash.txt rockyou.txt"))
        
        # SHA512
        if length == 128 and re.match(r'^[a-fA-F0-9]{128}$', hash_clean):
            possible_types.append(("SHA512", "1700", "Exemplo: hashcat -m 1700 -a 0 hash.txt rockyou.txt"))
        
        # NTLM
        if length == 32 and re.match(r'^[a-fA-F0-9]{32}$', hash_clean):
            if ("MD5", "0", "Exemplo: hashcat -m 0 -a 0 hash.txt rockyou.txt") in possible_types:
                possible_types.append(("NTLM", "1000", "Exemplo: hashcat -m 1000 -a 0 hash.txt rockyou.txt"))
        
        # bcrypt
        if hash_clean.startswith('$2a$') or hash_clean.startswith('$2b$') or hash_clean.startswith('$2y$'):
            possible_types.append(("bcrypt", "3200", "Exemplo: hashcat -m 3200 -a 0 hash.txt rockyou.txt"))
        
        # Linux SHA512 Crypt
        if hash_clean.startswith('$6$'):
            possible_types.append(("SHA512 Crypt (Linux)", "1800", "Exemplo: hashcat -m 1800 -a 0 hash.txt rockyou.txt"))
        
        # Linux SHA256 Crypt
        if hash_clean.startswith('$5$'):
            possible_types.append(("SHA256 Crypt (Linux)", "7400", "Exemplo: hashcat -m 7400 -a 0 hash.txt rockyou.txt"))
        
        # Linux MD5 Crypt
        if hash_clean.startswith('$1$'):
            possible_types.append(("MD5 Crypt (Linux)", "500", "Exemplo: hashcat -m 500 -a 0 hash.txt rockyou.txt"))
        
        # WordPress/phpBB
        if hash_clean.startswith('$P$') or hash_clean.startswith('$H$'):
            possible_types.append(("phpass (WordPress/phpBB)", "400", "Exemplo: hashcat -m 400 -a 0 hash.txt rockyou.txt"))
        
        # Django PBKDF2
        if hash_clean.startswith('pbkdf2_sha256$'):
            possible_types.append(("Django PBKDF2-SHA256", "10000", "Exemplo: hashcat -m 10000 -a 0 hash.txt rockyou.txt"))
        
        # Base64
        try:
            base64.b64decode(hash_clean, validate=True)
            if len(hash_clean) % 4 == 0 and re.match(r'^[A-Za-z0-9+/=]+$', hash_clean):
                possible_types.append(("Base64", "decode", "Use: base64 -d ou CyberChef"))
        except:
            pass
        
        # Hex
        if re.match(r'^[a-fA-F0-9]+$', hash_clean) and len(hash_clean) % 2 == 0:
            possible_types.append(("Hexadecimal", "decode", "Use: echo 'HEX' | xxd -r -p"))
        
        return possible_types
    
    def decode_base64(self, encoded: str) -> Optional[str]:
        """Decodifica Base64"""
        try:
            decoded = base64.b64decode(encoded)
            # Tenta decodificar como UTF-8
            try:
                return decoded.decode('utf-8')
            except:
                # Se falhar, retorna hex
                return decoded.hex()
        except:
            return None
    
    def decode_hex(self, hex_string: str) -> Optional[str]:
        """Decodifica Hexadecimal"""
        try:
            decoded = bytes.fromhex(hex_string)
            try:
                return decoded.decode('utf-8')
            except:
                return str(decoded)
        except:
            return None
    
    def decode_rot13(self, text: str) -> str:
        """Decodifica ROT13"""
        import codecs
        return codecs.decode(text, 'rot_13')
    
    def decode_url(self, text: str) -> str:
        """Decodifica URL encoding"""
        from urllib.parse import unquote
        return unquote(text)
    
    def crack_online(self, hash_value: str) -> Optional[str]:
        """Tenta quebrar hash usando APIs online"""
        hash_clean = hash_value.strip()
        
        # Tenta Hashes.com (MD5Decrypt.net API)
        try:
            self.print_info("Consultando API online...")
            url = f"https://md5decrypt.net/en/Api/api.php?hash={hash_clean}&hash_type=md5&email=deanna_abshire@gmail.com&code=1122bb2223333"
            response = requests.get(url, timeout=5)
            if response.text and response.text != "ERROR CODE 001":
                return response.text
        except:
            pass
        
        return None
    
    def caesar_bruteforce(self, text: str) -> List[Tuple[int, str]]:
        """Bruteforce Caesar cipher"""
        results = []
        for shift in range(1, 26):
            decoded = ""
            for char in text:
                if char.isalpha():
                    ascii_offset = 65 if char.isupper() else 97
                    decoded += chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
                else:
                    decoded += char
            results.append((shift, decoded))
        return results
    
    def analyze_format(self, hash_value: str):
        """Analisa formato e dá dicas de preparação"""
        self.print_section("DICAS DE FORMATAÇÃO")
        
        hash_clean = hash_value.strip()
        
        # Verifica se tem prefixo/sufixo
        if ':' in hash_clean:
            parts = hash_clean.split(':')
            self.print_warning(f"Hash contém ':' - pode ser formato user:hash")
            self.print_info(f"Partes detectadas: {len(parts)}")
            for i, part in enumerate(parts):
                print(f"  {Fore.YELLOW}[{i}]{Style.RESET_ALL} {part}")
            print(f"\n{Fore.CYAN}💡 Para Hashcat:{Style.RESET_ALL}")
            print(f"  - Se formato 'user:hash': use --username")
            print(f"  - Exemplo: hashcat -m MODE hash.txt rockyou.txt --username")
        
        # Verifica formato Windows
        if len(hash_clean) == 32 and re.match(r'^[a-fA-F0-9]{32}$', hash_clean):
            print(f"\n{Fore.CYAN}💡 Se for NTLM do Windows:{Style.RESET_ALL}")
            print(f"  - Formato do arquivo: username:hash")
            print(f"  - Exemplo: Administrator:{hash_clean}")
            print(f"  - Comando: hashcat -m 1000 hash.txt rockyou.txt --username")
        
        # Verifica /etc/shadow
        if '$' in hash_clean and any(hash_clean.startswith(x) for x in ['$1$', '$5$', '$6$']):
            print(f"\n{Fore.CYAN}💡 Hash do /etc/shadow (Linux):{Style.RESET_ALL}")
            print(f"  - Formato completo: user:hash:lastchange:min:max:warn:inactive:expire")
            print(f"  - Hashcat precisa apenas da parte do hash")
            print(f"  - Cole o hash completo no arquivo")
        
        # Verifica NetNTLMv2
        if '::' in hash_clean:
            print(f"\n{Fore.CYAN}💡 Possível NetNTLMv2 (Responder capture):{Style.RESET_ALL}")
            print(f"  - Formato: user::domain:challenge:HMAC-MD5:blob")
            print(f"  - Hashcat mode: -m 5600")
            print(f"  - Cole a linha completa do Responder")
    
    def analyze(self, input_string: str):
        """Análise completa da string"""
        self.banner()
        
        print(f"\n{Fore.CYAN}📥 INPUT:{Style.RESET_ALL}")
        print(f"{Fore.WHITE}{input_string[:200]}{'...' if len(input_string) > 200 else ''}{Style.RESET_ALL}")
        
        # Identifica tipo
        self.print_section("IDENTIFICAÇÃO")
        possible_types = self.identify_hash(input_string)
        
        if not possible_types:
            self.print_warning("Tipo não identificado automaticamente")
            self.print_info("Tentando decodificações genéricas...")
        else:
            self.print_success(f"Identificados {len(possible_types)} tipos possíveis:")
            for i, (hash_type, mode, example) in enumerate(possible_types, 1):
                print(f"\n{Fore.YELLOW}[{i}] {hash_type}{Style.RESET_ALL}")
                if mode != "decode":
                    print(f"  {Fore.CYAN}Hashcat Mode:{Style.RESET_ALL} -m {mode}")
                print(f"  {Fore.CYAN}Comando:{Style.RESET_ALL} {example}")
        
        # Tenta decodificações
        self.print_section("TENTANDO DECODIFICAÇÕES")
        
        # Base64
        decoded_b64 = self.decode_base64(input_string)
        if decoded_b64 and decoded_b64 != input_string:
            self.print_success("Base64 decodificado:")
            print(f"  {Fore.GREEN}{decoded_b64}{Style.RESET_ALL}")
            self.results.append(("Base64", decoded_b64))
            
            # Tenta decodificar recursivamente
            if self.is_base64(decoded_b64):
                self.print_info("Detectado Base64 aninhado! Decodificando novamente...")
                decoded_b64_2 = self.decode_base64(decoded_b64)
                if decoded_b64_2:
                    self.print_success("Base64 (2ª camada) decodificado:")
                    print(f"  {Fore.GREEN}{decoded_b64_2}{Style.RESET_ALL}")
        
        # Hex
        if re.match(r'^[a-fA-F0-9]+$', input_string) and len(input_string) % 2 == 0:
            decoded_hex = self.decode_hex(input_string)
            if decoded_hex and decoded_hex != input_string:
                self.print_success("Hexadecimal decodificado:")
                print(f"  {Fore.GREEN}{decoded_hex}{Style.RESET_ALL}")
                self.results.append(("Hex", decoded_hex))
        
        # ROT13
        decoded_rot13 = self.decode_rot13(input_string)
        if decoded_rot13 != input_string:
            self.print_success("ROT13 decodificado:")
            print(f"  {Fore.GREEN}{decoded_rot13}{Style.RESET_ALL}")
            self.results.append(("ROT13", decoded_rot13))
        
        # URL Decode
        decoded_url = self.decode_url(input_string)
        if decoded_url != input_string:
            self.print_success("URL decodificado:")
            print(f"  {Fore.GREEN}{decoded_url}{Style.RESET_ALL}")
            self.results.append(("URL Decode", decoded_url))
        
        # Caesar Cipher (se texto for alfabético)
        if input_string.isalpha() and len(input_string) > 5:
            self.print_info("Tentando Caesar cipher bruteforce...")
            caesar_results = self.caesar_bruteforce(input_string)
            print(f"\n{Fore.CYAN}Top 5 possibilidades Caesar:{Style.RESET_ALL}")
            for i, (shift, decoded) in enumerate(caesar_results[:5], 1):
                print(f"  {Fore.YELLOW}[Shift {shift:2d}]{Style.RESET_ALL} {decoded[:80]}")
        
        # Tenta quebrar hash online
        if any(t[0] in ["MD5", "SHA1", "NTLM"] for t in possible_types):
            self.print_section("QUEBRANDO HASH ONLINE")
            cracked = self.crack_online(input_string)
            if cracked:
                self.print_success(f"HASH QUEBRADO! 🎉")
                print(f"\n{Fore.GREEN}{Back.BLACK}  {cracked}  {Style.RESET_ALL}\n")
                self.results.append(("Cracked", cracked))
            else:
                self.print_warning("Hash não encontrado em base de dados online")
                self.print_info("Tente hashcat com rockyou.txt localmente")
        
        # Análise de formato
        self.analyze_format(input_string)
        
        # Resumo final
        if self.results:
            self.print_section("RESULTADOS ENCONTRADOS")
            for method, result in self.results:
                print(f"{Fore.GREEN}✓ {method}:{Style.RESET_ALL} {result}")
    
    def is_base64(self, s: str) -> bool:
        """Verifica se string é base64 válido"""
        try:
            if len(s) % 4 == 0 and re.match(r'^[A-Za-z0-9+/=]+$', s):
                base64.b64decode(s, validate=True)
                return True
        except:
            pass
        return False

def interactive_mode():
    """Modo interativo"""
    breaker = CryptoBreaker()
    breaker.banner()
    
    print(f"{Fore.YELLOW}Modo Interativo - Digite 'quit' para sair{Style.RESET_ALL}\n")
    
    while True:
        try:
            user_input = input(f"{Fore.CYAN}crypto> {Style.RESET_ALL}").strip()
            
            if user_input.lower() in ['quit', 'exit', 'q']:
                print(f"\n{Fore.GREEN}👋 Até logo!{Style.RESET_ALL}")
                break
            
            if not user_input:
                continue
            
            breaker = CryptoBreaker()
            breaker.analyze(user_input)
            print("\n")
            
        except KeyboardInterrupt:
            print(f"\n\n{Fore.GREEN}👋 Até logo!{Style.RESET_ALL}")
            break
        except Exception as e:
            print(f"{Fore.RED}❌ Erro: {e}{Style.RESET_ALL}")

def main():
    """Função principal"""
    if len(sys.argv) > 1:
        # Modo comando direto
        input_string = ' '.join(sys.argv[1:])
        breaker = CryptoBreaker()
        breaker.analyze(input_string)
    else:
        # Modo interativo
        interactive_mode()

if __name__ == "__main__":
    main()
