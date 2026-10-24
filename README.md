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
| Classificador conservador v2 e evidências por dispositivo | Implementado; avaliação empírica pendente |
| Consulta complementar SNMPv2c somente leitura | Implementado; avaliação empírica pendente |
| Histórico de presença e eventos de entrada/saída | Implementado; avaliação empírica pendente |
| p0f (SO passivo) | Roadmap |
| WhatWeb (stack web) | Roadmap |
| JA3/JA3S (fingerprint TLS) | Roadmap |

“Implementado” descreve a disponibilidade do recurso no código e nos testes
automatizados; não significa validação empírica em uma amostra representativa
de redes ou dispositivos.

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
| `/eventos` | Consultar entradas e saídas recentes da rede |
| `/report` | Baixar relatório completo em PDF |
| `/ping` | Verificar se o bot está online |
| `/uptime` | Tempo de atividade do sistema |
| `/ip` | Listar IPs do servidor |
| `/info` | Informações detalhadas do sistema |
| `/dashboard` | Link para dashboard web |
| `/wifi` | Escanear redes Wi-Fi próximas |
| `/help` | Ajuda completa com todos os comandos |

Configure o token do bot em `INFRA_TELEGRAM_TOKEN` no arquivo local `.env`.
Não armazene tokens no `config.json`, em exemplos versionados ou em relatórios;
o arquivo `.env` é ignorado pelo Git.

### 📊 Dashboard Web
- 📈 **Gráficos interativos** de evolução do InfraScore
- 🖥️ **Inventário detalhado** com todos os dispositivos
- 🧾 **Evidências observadas** de hostname, fabricante e portas, separadas da identificação SNMP
- 🕒 **Histórico de presença** com entradas e saídas confirmadas em scans completos
- 🔔 **Alertas** de portas perigosas
- 📱 **Interface responsiva** com tema escuro
- 🔐 **Autenticação** de usuários

O usuário `admin` com senha `admin123` é criado somente quando
`INFRA_ENV=dev`. Em outros ambientes, defina `INFRA_ENV=production` e gerencie
as contas fora desse usuário de teste. Configure também `INFRA_SECRET_KEY` com
um valor aleatório estável para manter as sessões entre reinícios; a chave deve
ser mantida em segredo e fora do controle de versão. Contas existentes com hash
SHA-256 são atualizadas para o formato seguro do Werkzeug após um login válido.
Mudar um ambiente que já foi executado em desenvolvimento para produção não
remove automaticamente a conta de teste já criada; altere ou remova essa conta
antes de expor o dashboard.

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
os fatores de exposição Telnet, RTSP, hosts desconhecidos, HTTP sem HTTPS no gateway e
portas administrativas (pesos 2, 2, 1, 1 e 1; máximo 7). `S` adiciona risco CVE
por instância de software (crítica=3, alta=2, média=1), limitado a 3. A correlação
é uma indicação de exposição, não prova de explorabilidade nem substitui validação
do fornecedor. U pode crescer no modo rápido quando faltam evidências suficientes
para classificar os hosts; ele não deve ser interpretado isoladamente como risco
confirmado.

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

### Descoberta complementar via SNMP

O SNMPv2c é opcional e consulta somente os hosts já descobertos, em modo de
leitura, para enriquecer hostname, fabricante e identificação do equipamento.
Habilite `INFRA_SCAN_SNMP=true` e informe explicitamente em
`INFRA_SNMP_COMMUNITY` uma comunidade somente leitura configurada nos
equipamentos; a porta padrão é 161 (`INFRA_SNMP_PORT`). O scanner não tenta
comunidades padrão ou credenciais em sequência e não grava a comunidade no
banco ou nos relatórios. Como SNMPv2c não cifra a comunidade, prefira SNMPv3
quando disponível e execute consultas somente em redes autorizadas.

### Rastreabilidade e cobertura do scan

Cada novo scan registra modo (rápido ou serviços), consulta ao NVD, duração,
versões do classificador e da fórmula, além da decomposição T/Q/U/H/A/S.
Componentes não verificados ficam fora do score parcial e são exibidos como
“não verificado”; isso não significa risco zero. O fator U é binário: vale 1
quando a proporção de dispositivos desconhecidos excede 30%. Scans antigos são
identificados como legado (classificador v1), pois sua contagem de desconhecidos
pode não ser confiável. Compare scores apenas entre scans com modo e fórmula
compatíveis.

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
