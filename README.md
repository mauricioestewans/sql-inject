# 🔍 Advanced Security Scanner v3.0

**Scanner avançado de vulnerabilidades para Aplicações Web, APIs e Backends Mobile**

[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Licença: MIT](https://img.shields.io/badge/Licença-MIT-red.svg)](https://opensource.org/licenses/MIT)

## 📑 Visão Geral

Ferramenta profissional para identificar vulnerabilidades críticas em:
- **Aplicações Web** (SQL Injection, Vazamento de Credenciais)
- **APIs** (Endpoints Expostos, GraphQL Introspection)
- **Backends Mobile** (Segredos em Código, Más Configurações)

![Exemplo de Saída](https://via.placeholder.com/600x200.png?text=Exemplo+de+Saída)

## ✨ Funcionalidades

- **Varredura Inteligente**
  - Detecção automática do tipo de alvo (Web/API/Mobile)
  - Testes de SQL Injection com payloads avançados
  - Detecção de credenciais com filtro de falsos positivos
- **Segurança de APIs**
  - Identificação de GraphQL introspection ativada
  - Descoberta de tokens JWT e chaves de API
  - Enumeração de endpoints
- **Foco em Mobile**
  - Detecção de backends Android/iOS
  - Identificação de pacotes de aplicativos
  - Varredura de caminhos específicos para mobile
- **Relatórios Detalhados**
  - Relatório JSON completo
  - Sumário executivo com recomendações
  - Estatísticas de vulnerabilidades

## ⚙️ Instalação

```bash
# Clonar repositório
git clone https://github.com/seuusuário/advanced-security-scanner.git
cd advanced-security-scanner

# Instalar dependências
pip3 install requests colorama python-dotx
🚀 Como Usar
bash
python3 scanner.py
Exemplos de alvos:

Web: http://exemplo.com/pagina-vulneravel

API: https://api.exemplo.com/v1

Mobile: https://backend-mobile.exemplo.com/android-api

Modo interativo:

=== Advanced Security Scanner ===
Versão 3.0 - Scanner Web/API/Mobile

[*] Digite o alvo (URL, endpoint API ou backend mobile): https://api.exemplo.com/graphql
⚡️ Configuração
Edite as variáveis da classe AdvancedSecurityScanner para personalização:

python
# Ativar modo detalhado
self.VERBOSE = True

# Aumentar timeout para alvos lentos
self.TIMEOUT = 30  

# Adicionar caminhos mobile customizados
self.MOBILE_APP_PATHS += ['/api-mobile-customizada/']
📊 Estrutura dos Relatórios
Relatório JSON (full_report.json) contém:

Credenciais encontradas

Metadados de bancos de dados

Endpoints de API descobertos

Identificadores mobile

Logs de erros

Sumário Executivo (executive_summary.txt) inclui:

Estatísticas de vulnerabilidades

Principais achados

Passos para correção

Recomendações baseadas no OWASP Top 10

🔒 Considerações de Segurança
❗ Avisos Importantes:

Use somente em sistemas autorizados

Adicione 127.0.0.1 exemplo.com no /etc/hosts para testes locais

Nunca execute em ambientes de produção

Verifique cuidadosamente os resultados (falsos positivos)

🤝 Como Contribuir
Faça um fork do repositório

Crie uma branch (git checkout -b feature/melhoria)

Commit suas mudanças (git commit -am 'Adiciona novo padrão de detecção')

Push para a branch (git push origin feature/melhoria)

Abra um Pull Request


❓ Perguntas Frequentes
P: Quanto tempo demora uma varredura?
R: Entre 15-60 segundos dependendo do alvo

P: Posso usar em pipelines CI/CD?
R: Sim - integre o JSON output no seu dashboard de segurança

P: Por que aparecem avisos de SSL?
R: Verificação de certificado desativada para testes - não use em produção
