# <img src="assets/logo.png" height="36" align="center" alt="logo"> &nbsp; Antena InfraInsight

<p align="center">
  <img src="assets/banner.png" alt="Antena InfraInsight Banner" width="700"/>
</p>

<p align="center">
  <strong>Visibilidade Inteligente Para Sua Rede</strong><br/>
  Scanner de rede local com classificação inteligente, risk scoring contextual, dashboard web e relatórios PDF profissionais.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python" alt="Python"/>
  <img src="https://img.shields.io/badge/Flask-Dashboard-lightgrey?style=flat-square&logo=flask" alt="Flask"/>
  <img src="https://img.shields.io/badge/nmap-integrado-green?style=flat-square" alt="nmap"/>
  <img src="https://img.shields.io/badge/Relatório-PDF-red?style=flat-square" alt="PDF"/>
  <img src="https://img.shields.io/badge/SQLite-Histórico-yellow?style=flat-square&logo=sqlite" alt="SQLite"/>
  <img src="https://img.shields.io/badge/Status-Em%20desenvolvimento-orange?style=flat-square" alt="Status"/>
</p>

---

## 📡 O que é o InfraInsight?

O **Antena InfraInsight** é uma plataforma de visibilidade de infraestrutura local desenvolvida em Python. Vai além do simples "quem está na rede" — ele **classifica**, **analisa riscos**, **persiste histórico** e **gera relatórios visuais** de forma automatizada.

Ideal para uso em ambientes domésticos, home labs e pequenas redes corporativas.

---

## 🖥️ Screenshots

<p align="center">
  <img src="assets/screenshots/dashboard.png" alt="Dashboard" width="680"/>
  <br/><em>Dashboard Flask com métricas em tempo real</em>
</p>

<p align="center">
  <img src="assets/screenshots/pdf_report.png" alt="PDF Report" width="680"/>
  <br/><em>Relatório PDF com gráficos embutidos e marca d'água</em>
</p>

---

## ✨ Funcionalidades

| Módulo | Descrição |
|--------|-----------|
| 🔍 **Scanner** | Detecção automática de sub-rede, gateway, IP, MAC e fabricante via Nmap |
| 🧠 **Classificador** | 9 categorias de dispositivos com reconhecimento de vendor e keywords |
| 🖥️ **Host Local** | Auto-reconhecimento do dispositivo que executa o scanner (sem falso positivo) |
| 📊 **Dashboard** | Painel web Flask com métricas ao vivo: IPs ativos, risco médio, desconhecidos |
| 📈 **Gráficos** | Pizza por tipo, barras por risco e evolução temporal via Matplotlib |
| 📄 **PDF Report** | Relatório profissional com capa, tabela, gráficos embutidos e marca d'água |
| 🗄️ **Histórico** | Persistência em JSON + SQLite para análise de tendências |
| ⚠️ **Risk Scoring** | Score contextual de 1 a 5 por dispositivo baseado em tipo, vendor e comportamento |

---

## 🗂️ Estrutura do Projeto

```
InfraInsight/
│
├── scanner.py              # Ponto de entrada principal
├── config.json             # Configurações (vendors, keywords, thresholds)
├── requirements.txt
├── README.md
│
├── modulos/
│   ├── classificador.py    # Classificação por tipo de dispositivo
│   ├── host_local.py       # Auto-detecção do host executando o scanner
│   ├── graph_generator.py  # Gráficos matplotlib (pizza, barras, evolução)
│   └── vendor_intelligence.py
│
├── dashboard/
│   ├── app.py              # Servidor Flask
│   ├── templates/
│   └── static/
│
├── reports/
│   ├── pdf_report.py       # Gerador de PDF com marca d'água e gráficos
│   └── graficos/           # PNGs gerados automaticamente por scan
│
└── assets/
    ├── logo.png
    ├── logo_vertical.png
    └── banner.png
```

---

## 🚀 Instalação

### Pré-requisitos

- Python 3.10+
- `nmap` instalado no sistema

```bash
# Ubuntu / Debian
sudo apt install nmap

# macOS
brew install nmap
```

### Setup

```bash
# 1. Clone o repositório
git clone https://github.com/seu-usuario/infrainsight.git
cd infrainsight

# 2. Crie o ambiente virtual
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. Instale as dependências
pip install -r requirements.txt
```

---

## ▶️ Uso

### Scanner principal

```bash
# Executar scan completo
sudo python scanner.py

# O relatório PDF é gerado automaticamente em reports/
```

### Dashboard web

```bash
cd dashboard
python app.py
# Acesse: http://localhost:5000
```

---

## 📦 Dependências

```
nmap
python-nmap
flask
reportlab
matplotlib
Pillow
sqlite3   # nativo Python
```

Instale tudo com:

```bash
pip install -r requirements.txt
```

---

## 📊 Categorias de Dispositivos

| Tipo | Descrição |
|------|-----------|
| `gateway` | Roteador / gateway da rede |
| `computador_conhecido` | PC, notebook, host local reconhecido |
| `switch_infra` | Switches e equipamentos de infraestrutura |
| `smarttv_streaming` | Smart TVs, Chromecast, Fire TV |
| `iot_rede` | Dispositivos IoT (câmeras, sensores, ESP32) |
| `camera` | Câmeras IP e de segurança |
| `impressora` | Impressoras de rede |
| `mac_randomizado` | Dispositivos com MAC address randomizado |
| `desconhecido` | Dispositivo não identificado |

---

## ⚠️ Risk Scoring

O risco é calculado de **1 (baixo)** a **5 (crítico)** com base em:

- Tipo do dispositivo
- Fabricante (vendor) reconhecido ou desconhecido
- Presença no histórico de scans anteriores
- MAC randomizado (indicativo de evasão)
- Dispositivos do tipo `desconhecido` recebem score elevado automaticamente

---

## 🛣️ Roadmap

- [x] Scanner com detecção de sub-rede e gateway
- [x] Classificador inteligente de dispositivos
- [x] Auto-reconhecimento do host local
- [x] Dashboard Flask com métricas
- [x] Geração de gráficos matplotlib
- [x] PDF com gráficos embutidos e marca d'água
- [ ] Vendor Intelligence local (base offline de fabricantes)
- [ ] Alertas por e-mail em novo dispositivo detectado
- [ ] Docker Compose com InfluxDB + Grafana
- [ ] Suporte a múltiplas sub-redes simultâneas

---

## 🤝 Contribuindo

Pull requests são bem-vindos! Para mudanças grandes, abra uma issue antes para discutir o que você gostaria de mudar.

---

## 📄 Licença

MIT License — veja [LICENSE](LICENSE) para mais detalhes.

---

<p align="center">
  Feito com 📡 por <strong>InfraInsight</strong> — <em>Gestão · Observabilidade · Análise de Redes</em>
</p>
