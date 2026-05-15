# InfraInsight

InfraInsight é um sistema de monitoramento e observabilidade de redes locais voltado para descoberta, classificação, análise de risco e histórico de dispositivos conectados.

O projeto foi desenvolvido para mapear ambientes domésticos ou pequenos escritórios utilizando múltiplas fontes de coleta, combinando varredura ativa, análise contextual e telemetria para gerar uma visão mais inteligente da infraestrutura de rede.

---

# 🚀 Principais Funcionalidades

## 🔎 Descoberta e Coleta
- Detecção automática da sub-rede local
- Varredura ativa com Nmap (`-sn`, ARP Ping)
- Coleta complementar via DD-WRT (ARP remoto por SSH)
- Identificação de gateway principal
- Descoberta de hostname
- Fingerprint por fabricante (vendor/MAC)

---

## 🧠 Classificação Inteligente
- Roteador principal
- Switch / Access Point / Infraestrutura
- Computador conhecido
- Celular
- IoT / Smart devices
- Dispositivos privados ou MAC randomizado
- Dispositivos desconhecidos

---

# ⚠️ Análise de Risco
Cada dispositivo recebe score contextual baseado em:
- Fabricante desconhecido
- Hostname ausente
- MAC randomizado
- Persistência histórica
- Frequência de aparição
- Tipo de dispositivo
- Contexto topológico

### Escala:
- **0–2:** Baixo risco  
- **3–5:** Médio risco  
- **6–10:** Alto risco  

---

# 📊 Métricas Geradas
- Total de IPs ativos
- Percentual de uso da sub-rede
- Quantidade de dispositivos desconhecidos
- MACs randomizados
- Novos dispositivos detectados
- Risco médio da rede
- Resumo por categoria de dispositivo

---

# 🗄️ Armazenamento e Histórico
## Exportações locais:
- `dados.json` → histórico estruturado por execução
- `dados.csv` → métricas consolidadas
- `historico_dispositivos.json` → persistência e frequência de dispositivos

## Telemetria:
- Integração com InfluxDB
- Base pronta para dashboards Grafana

---

# 🛠️ Stack Tecnológica
- Python 3
- Nmap
- SSH (DD-WRT)
- InfluxDB
- Docker / Docker Compose
- JSON / CSV

---

# 🏗️ Arquitetura do Fluxo

```text
Detecção de Rede
      ↓
Nmap Scan
      ↓
DD-WRT ARP via SSH
      ↓
Correlação Multi-Fonte
      ↓
Classificação
      ↓
Score de Risco
      ↓
Histórico + JSON/CSV
      ↓
InfluxDB
