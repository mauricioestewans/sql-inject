# 🔍 SQL Injection Scanner

Este projeto é uma ferramenta de **varredura automatizada** para identificar possíveis vulnerabilidades de **SQL Injection** em sites indexados por motores de busca como **DuckDuckGo** e **Google**, usando palavras-chave específicas.

> ⚠️ **Uso estritamente educacional. Não utilize em sistemas sem autorização expressa.**

---

## 📌 Funcionalidades

- Pesquisa por dorks como `inurl:php?id=`, `inurl:news.php?id=`, etc.
- Teste de injeção SQL básica (`'`) em URLs retornadas.
- Detecção de indícios de falhas SQL no conteúdo da resposta.
- Armazena URLs potencialmente vulneráveis em `sql.txt`.
- Suporte a múltiplos buscadores:
  - 🔎 DuckDuckGo (`duckduckgo-search`)
  - 🌐 Google (via API do [SerpAPI](https://serpapi.com))

---

## 🛠️ Instalação

1. Clone o repositório:

```bash
git clone https://github.com/mauricioestewans/sql.git
cd sql
Crie um ambiente virtual (opcional, mas recomendado):

bash
Copiar
Editar
python -m venv venv
venv\Scripts\activate  # Windows
# ou
source venv/bin/activate  # Linux/macOS
Instale as dependências:

bash
Copiar
Editar
pip install -r requirements.txt
Ou manualmente:

bash
Copiar
Editar
pip install requests colorama duckduckgo-search google-search-results
▶️ Como Usar
Execute o script:

bash
Copiar
Editar
python sql_scanner.py
Informe os dados solicitados:

yaml
Copiar
Editar
[*] Digite o termo de busca: inurl:php?id=
[*] Quantidade de resultados: 10
O script testará cada link retornado e salvará os vulneráveis em sql.txt.

🧠 Exemplo de uso (Dorks)
text
Copiar
Editar
inurl:php?id=
inurl:index.php?page=
inurl:news.php?id=
inurl:item.php?id=
✅ Requisitos
Python 3.7+

Conta gratuita no SerpAPI (opcional para buscas no Google)

Conexão com a internet

⚠️ Aviso Legal
Este projeto é apenas para fins educacionais e testes em ambientes controlados. Não use para atacar sistemas reais sem autorização. O autor não se responsabiliza por qualquer uso indevido da ferramenta.

📄 Licença
Distribuído sob a licença MIT. Veja LICENSE para mais detalhes.

✍️ Autor
Desenvolvido por @mauricioestewans
