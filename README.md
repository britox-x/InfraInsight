# InfraInsight

InfraInsight é uma plataforma de monitoramento, observabilidade e análise contextual de redes locais (domésticas e SOHO), desenvolvida para descoberta inteligente de dispositivos, classificação automatizada, análise de risco, persistência histórica e visualização operacional.

O projeto evoluiu de um scanner de rede para uma solução de telemetria de infraestrutura com foco em visibilidade, segurança doméstica e portfólio técnico em automação/SOC.

---

# 🎯 Objetivo

Fornecer uma visão prática e inteligente da rede local por meio de:

- Descoberta automática de dispositivos
- Correlação entre múltiplas fontes
- Classificação contextual
- Score de risco por ambiente
- Histórico persistente
- Dashboard local
- Relatórios automatizados

---

# 🚀 Principais Funcionalidades

## 🔎 Descoberta e Coleta
- Detecção automática da sub-rede local
- Descoberta de gateway
- Varredura ativa via Nmap (`-sn`, ARP Ping)
- Identificação de IPs ativos
- Resolução de hostname
- MAC Address + Vendor Lookup
- Coleta complementar via DD-WRT (`/proc/net/arp` por SSH)

---

## 🧠 Classificação Inteligente
Classificação contextual baseada em hostname, fabricante, persistência e topologia:

- Roteador principal
- Switch / Infraestrutura
- Computador conhecido
- Linux / Desktop
- IoT / Smart Device
- Dispositivo privado / MAC randomizado
- Desconhecido

---

# ⚠️ Análise de Risco
Cada dispositivo e cada scan recebem score contextual baseado em:

- Fabricante
- Hostname
- MAC privado/randomizado
- Persistência histórica
- Frequência
- Tipo de dispositivo
- Contexto topológico
- Mudanças no ambiente

### Escala:
- **0–2:** Baixo risco  
- **3–5:** Médio risco  
- **6–10:** Alto risco  

---

# 📊 Métricas Geradas por Scan
- Total de IPs ativos
- Uso percentual da sub-rede
- Risco médio
- Dispositivos desconhecidos
- MACs randomizados
- Novos dispositivos
- Recomendação operacional
- Ambiente
- Gateway
- Wi-Fi / Ethernet

---

# 🗄️ Persistência e Histórico
## Armazenamento atual:
### SQLite (padrão v2+)
- Histórico consolidado de scans
- Evolução temporal
- Métricas por execução

## Estrutura principal:
```text
Tabela: scans
- timestamp
- ambiente
- wifi
- subrede
- gateway
- ips_ativos
- uso
- risco_medio
- desconhecidos
- mac_randomizados
- novos_dispositivos
- recomendacao
- dispositivos
