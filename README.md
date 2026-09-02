<div align="center">
  <h1>🔍 InfraInsight</h1>
  <p><strong>Monitor de Rede Inteligente</strong></p>
  
  [![Version](https://img.shields.io/badge/version-1.0.0-blue)](https://github.com/britox-x/InfraInsight/releases)
  [![Python](https://img.shields.io/badge/python-3.12+-green)](https://www.python.org/)
  [![License](https://img.shields.io/badge/license-MIT-yellow)](LICENSE)
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
- **Testado**: 90% dos testes passando, InfraScore 100% coberto

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
- 🕒 **Timestamp** automático em cada relatório

### 🔍 Scanner de Rede
- 🌐 **Descoberta ARP** rápida e eficiente
- 📡 **Detecção de portas abertas** (Telnet, RTSP, HTTP, HTTPS)
- 🏷️ **Classificação automática** por MAC OUI, hostname e portas
- 📱 **Suporte a múltiplos dispositivos**: Roteadores, Smartphones, Computadores, Smart TVs, Câmeras IP, IoT

### 🚨 Sistema de Alertas
- ⚠️ **Portas perigosas** (Telnet, RTSP)
- 🆕 **Novos dispositivos** na rede
- 📊 **Resumo diário** de segurança
- 🎯 **Alertas personalizáveis** via Telegram

### 📊 InfraScore - Métrica de Exposição

**Fórmula:** `R = 2T + 2Q + U + H + A`

| Variável | Significado | Peso |
|----------|-------------|------|
| T | Telnet exposto | 2 |
| Q | RTSP exposto | 2 |
| U | Dispositivos desconhecidos | 1 |
| H | Gateway sem HTTPS | 1 |
| A | Portas administrativas | 1 |

**InfraScore = (R / 7) × 10** (0 = seguro, 10 = crítico)

## 🖥️ Arquitetura

InfraInsight/
├── core/              # Núcleo do sistema
│   ├── classifier.py  # Classificador de dispositivos
│   ├── infra_score.py # Métrica de exposição
│   ├── network.py     # Scanner de rede
│   └── telegram_bot_completo.py # Bot do Telegram
├── dashboard/         # Interface web
├── reports/           # Relatórios gerados
├── storage/           # Dados persistentes
├── scripts/           # Scripts utilitários
└── tests/             # Testes automatizados


---

## 🚀 Instalação

### Pré-requisitos

```bash
sudo apt update
sudo apt install nmap python3 python3-pip python3-venv -y
