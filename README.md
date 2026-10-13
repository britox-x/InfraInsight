<div align="center">
  <h1>🔍 InfraInsight</h1>
  <p><strong>Monitor de Rede Inteligente</strong></p>
  
  [![Version](https://img.shields.io/badge/version-1.0.0-blue)](https://github.com/britox-x/InfraInsight/releases)
  [![Python](https://img.shields.io/badge/python-3.12+-green)](https://www.python.org/)
  [![License](https://img.shields.io/badge/license-MIT-yellow)](LICENSE)
  [![CI](https://github.com/britox-x/InfraInsight/actions/workflows/ci.yml/badge.svg)](https://github.com/britox-x/InfraInsight/actions/workflows/ci.yml)
  [![Telegram](https://img.shields.io/badge/Telegram-Bot-0088cc)](https://t.me/Infrainsight_bot)
  [![Status](https://img.shields.io/badge/status-active-success)](https://github.com/britox-x/InfraInsight)
  [![PRs](https://img.shields.io/badge/PRs-welcome-brightgreen)](CONTRIBUTING.md)
  
  <p>
    <a href="#-sobre-o-projeto">Sobre</a> •
    <a href="#-funcionalidades">Funcionalidades</a> •
    <a href="#-comandos-do-telegram">Comandos</a> •
    <a href="#-instalação">Instalação</a> •
    <a href="#-uso">Uso</a> •
    <a href="#-arquitetura">Arquitetura</a> •
    <a href="#-contribuindo">Contribuindo</a>
  </p>
  
  <p>
    <img src="https://img.shields.io/github/stars/britox-x/InfraInsight?style=social" alt="Stars">
    <img src="https://img.shields.io/github/forks/britox-x/InfraInsight?style=social" alt="Forks">
    <img src="https://img.shields.io/github/watchers/britox-x/InfraInsight?style=social" alt="Watchers">
  </p>
</div>

---

## Status de implementação

| Fonte/capacidade | Status |
|------------------|--------|
| Nmap (produto, versão e CPE) | Implementado |
| Correlação CVE via NVD, cache SQLite e limiar de confiança | Implementado |
| p0f (SO passivo) | Roadmap |
| WhatWeb (stack web) | Roadmap |
| JA3/JA3S (fingerprint TLS) | Roadmap |

## 📋 Sobre o Projeto

**InfraInsight** é um sistema completo para descoberta, inventário e análise de segurança em redes de pequeno porte (residências e pequenos comércios). A ferramenta combina técnicas de descoberta de dispositivos, classificação automática e uma métrica heurística (InfraScore) para avaliar a exposição de serviços.

### 🎯 Objetivo

Fornecer uma solução acessível e fácil de usar para:
- 🔍 Descobrir todos os dispositivos na rede
- 📊 Classificar dispositivos automaticamente
- 🛡️ Identificar vulnerabilidades e portas perigosas
- 📈 Monitorar a evolução da segurança
- 🤖 Receber alertas em tempo real via Telegram

### 🏆 Diferenciais

- **Acessível**: Não requer infraestrutura dedicada ou equipe especializada
- **Completo**: Descoberta, classificação, análise, relatórios e alertas
- **Leve**: Funciona em qualquer computador com Python
- **Open Source**: Código aberto para auditoria e contribuição
- **Testado**: suíte automatizada com pytest para componentes e regras principais

---

## ✨ Funcionalidades

### 🤖 Telegram Bot
| Comando | Descrição |
|---------|-----------|
| `/start` | Mensagem de boas-vindas interativa |
| `/scan` | Escanear a rede em tempo real |
| `/status` | Verificar status e saúde da rede |
| `/report` | Baixar relatório completo em PDF |
| `/ping` | Verificar se o bot está online |
| `/uptime` | Tempo de atividade do sistema |
| `/ip` | Listar IPs do servidor |
| `/info` | Informações detalhadas do sistema |
| `/dashboard` | Link para dashboard web |
| `/wifi` | Escanear redes Wi-Fi próximas |
| `/help` | Ajuda completa com todos os comandos |

### 📊 Dashboard Web
- 📈 **Gráficos interativos** de evolução do InfraScore
- 🖥️ **Inventário detalhado** com todos os dispositivos
- 🔔 **Alertas** de portas perigosas
- 📱 **Interface responsiva** com tema escuro
- 🔐 **Autenticação** de usuários

### 📄 Relatórios
- 📑 **PDF profissional** com capa, tabelas e gráficos
- 📊 **Gráficos**: Pizza (tipos de dispositivo), Barras (risco), Evolução (InfraScore)
- 📁 **Exportação CSV** para análise externa
- 🧩 **CSV adicional por software/endpoint** quando a detecção de versões está ativa
- 🕒 **Timestamp** automático em cada relatório

### 🔍 Scanner de Rede
- 🌐 **Descoberta ARP** rápida e eficiente
- 📡 **Detecção de portas abertas** (Telnet, RTSP, HTTP, HTTPS)
- 🏷️ **Classificação automática** por MAC OUI, hostname e portas
- 🧩 **Inventário de software** por produto, versão, CPE e endpoint
- 🛡️ **Correlação opcional com CVEs** pela API pública do NVD
- 📱 **Suporte a múltiplos dispositivos**: Roteadores, Smartphones, Computadores, Smart TVs, Câmeras IP, IoT

### 🚨 Sistema de Alertas
- ⚠️ **Portas perigosas** (Telnet, RTSP)
- 🆕 **Novos dispositivos** na rede
- 📊 **Resumo diário** de segurança
- 🎯 **Alertas personalizáveis** via Telegram

### 📊 InfraScore - Métrica de Exposição

O score final é limitado a 10 e segue `min(10, ((R + S) / 7) * 10)`. `R` combina
os fatores de exposição Telnet, RTSP, hosts desconhecidos, HTTP no gateway e
portas administrativas (pesos 2, 2, 1, 1 e 1; máximo 7). `S` adiciona risco CVE
por instância de software (crítica=3, alta=2, média=1), limitado a 3. A correlação
é uma indicação de exposição, não prova de explorabilidade nem substitui validação
do fornecedor.

## 🖥️ Arquitetura

```text
InfraInsight/
├── core/              # Núcleo do sistema
│   ├── classifier.py  # Classificador de dispositivos
│   ├── infra_score.py # Métrica de exposição
│   ├── persistence.py # Persistência SQLite
│   ├── cve_client.py  # Cliente da API NVD
│   ├── fingerprint/   # Parser Nmap e mapeamento CPE
│   └── telegram_bot_completo.py # Bot do Telegram
├── dashboard/         # Interface web
├── docs/              # Arquitetura e metodologia
├── examples/          # Dados sintéticos para demonstração
├── reports/           # Relatórios gerados
├── storage/           # Dados persistentes
├── scripts/           # Scripts utilitários
└── tests/             # Testes automatizados
```

---

## 🚀 Instalação

### Pré-requisitos

```bash
sudo apt update
sudo apt install nmap python3 python3-pip python3-venv -y
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

### Inventário por software e CVEs

Por segurança e para manter o scan padrão leve, a detecção ativa de versões é
opcional. Autorize os alvos antes de escaneá-los. Configure no `.env` (ou exporte
as variáveis no shell):

```dotenv
INFRA_SCAN_SERVICES=true
INFRA_CVE_LOOKUP=true
# Opcional: API key do NVD para limites de consulta maiores
INFRA_NVD_API_KEY=
```

Depois, execute `python scanner.py`.

`INFRA_SCAN_SERVICES` executa `nmap -sV --version-all -p <portas>` nos hosts
descobertos. O padrão são as 100 portas TCP listadas em [docs/portas.md](docs/portas.md);
defina `INFRA_SCAN_PORTS=22,80,443,8443` para substituí-las.
`INFRA_CVE_LOOKUP` consulta o NVD para CPEs disponíveis e persiste as
correspondências. O cache local SQLite dura 48 horas por padrão
(`INFRA_CVE_CACHE_TTL_HOURS`) e usa resultados expirados quando o NVD falha.
CPEs inferidos só são consultados com confiança mínima 70
(`INFRA_CVE_MIN_CONFIDENCE`); CPEs explícitos do Nmap podem ser consultados sem
esse limiar. Sem essas opções, a descoberta já existente continua igual.
O dashboard lista software por ativo e endpoint e inclui CVEs conhecidas no
InfraScore quando há resultados salvos.

Ativos são identificados preferencialmente pelo MAC; hostname e IP são chaves
alternativas quando o MAC não está disponível. Endpoints conservam IP, porta e
protocolo, e o histórico de software mantém versões anteriores quando o serviço
muda. CPEs são gerados apenas para produtos mapeados explicitamente; o Nmap pode
fornecer um CPE direto. Fingerprinting via p0f, WhatWeb e JA3/JA3S ainda não está
integrado.

## Prior Art

Conceitos de robótica e redes explorados anteriormente no projeto
[robo-funkeiro](https://github.com/britox-x/robo-funkeiro-) foram aplicados aqui
ao inventário e à análise de exposição de redes locais.
