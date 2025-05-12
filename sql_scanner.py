import multiprocessing
import requests, time, os
from colorama import Fore
from requests.models import HTTPError
from duckduckgo_search import DDGS
from serpapi import GoogleSearch

# === CONFIG ===
USE_SERPAPI = False  # Altere para True para usar SerpAPI
SERPAPI_KEY = "cae157ef87bb525afe01a823be7139a03bb3e902fe4529d237e94f6e288dbec9"  # Defina aqui se for usar SerpAPI

# === FUNÇÕES DE BUSCA ===
def search_duckduckgo(query, limit=10):
    try:
        with DDGS() as ddgs:
            results = ddgs.text(query, max_results=limit)
            return [r["href"] for r in results]
    except Exception as e:
        print(Fore.RED + f"[!] Erro DuckDuckGo: {e}")
        return []

def search_serpapi(query, limit=10):
    try:
        params = {
            "engine": "google",
            "q": query,
            "api_key": SERPAPI_KEY,
            "num": limit
        }
        search = GoogleSearch(params)
        results = search.get_dict()
        return [r["link"] for r in results.get("organic_results", [])]
    except Exception as e:
        print(Fore.RED + f"[!] Erro SerpAPI: {e}")
        return []

# === FUNÇÃO PRINCIPAL DE SCAN ===
def scan(query, count):
    try:
        if count <= 0:
            print(Fore.RED + "\n [!] Input inválido.")
            return

        print(Fore.YELLOW + f"\n[+] Buscando por: {query} (limit={count})\n")

        # Escolher mecanismo de busca
        if USE_SERPAPI:
            result = search_serpapi(query, limit=count)
        else:
            result = search_duckduckgo(query, limit=count)

        if not result:
            print(Fore.RED + "[!] Nenhum resultado encontrado.")
            return

        for idx, url in enumerate(result, 1):
            print(Fore.LIGHTBLUE_EX + f"\n [{idx}] Testando --> {url}")
            test_url = url + "'"

            try:
                r = requests.get(test_url, timeout=8)
                if any(x in r.text for x in ["sql", "SQL", "Sql"]):
                    print(Fore.GREEN + f"    [*] SQL Injection encontrado em: {url}")
                    with open('sql.txt', 'a') as file:
                        file.write(url + '\n')
                else:
                    print(Fore.RED + "    [!] SQL Injection não encontrado.")
            except:
                print(Fore.RED + "    [!] Timeout ou erro de conexão.")

            time.sleep(0.5)

    except KeyboardInterrupt:
        print(Fore.RED + "\n [!] Execução interrompida.")
    except HTTPError:
        print(Fore.RED + "\n [!] Erro HTTP.")
    except Exception as e:
        print(Fore.RED + f"\n [!] Erro inesperado: {e}")

# === MAIN ===
if __name__ == "__main__":
    os.system("cls" if os.name == "nt" else "clear")
    print(Fore.RED + """
         ,-.
        / \\  .  __..-,O
       :   \\ --''_..-'.'
       |    . .-' . '.
       :     .     ..'
        \\     .  /  ..
         \\      .   ' .
          ,       .   \\ 
         ,|,.        -.\\ 
        '.||  `-...__..-
         |  |
         |__|       --------------------------------------------
         /||\\      
         
        //||\\\\                      versão atualizada 2025
       // || \\\\   ---------------------------------------------
    __//__||__\\\\ __
   '--------------' 
    """)
    try:
        query = input(Fore.GREEN + "[*] Digite o termo de busca: ")
        count = int(input(Fore.GREEN + "[*] Quantidade de resultados: "))
    except KeyboardInterrupt:
        print(Fore.RED + "\n [!] Saindo...")
        exit()
    except:
        print(Fore.RED + "\n [!] Erro de entrada.")
        exit()

    p1 = multiprocessing.Process(target=scan, args=(query, count))
    p1.start()
    p1.join()
