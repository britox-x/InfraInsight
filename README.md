# InfraInsight

Sistema de monitoramento de rede local com coleta, análise e armazenamento de dados.

## 🔍 Funcionalidades

- Varredura automática da rede local (/24)
- Detecção de dispositivos ativos via Nmap
- Identificação de hostname e fabricante
- Classificação de dispositivos (roteador, celular, computador, etc)
- Cálculo de uso da rede (%)
- Geração de recomendações
- Exportação de dados para JSON e CSV
- Integração com banco de dados InfluxDB

## ⚙️ Tecnologias

- Python
- Nmap
- InfluxDB
- Docker

## 📊 Métricas coletadas

- IPs ativos
- Uso da rede (%)
- Tipo de dispositivos

## 🧠 Lógica

O sistema realiza:

1. Descoberta da rede automaticamente
2. Varredura com Nmap
3. Tratamento e limpeza dos dados
4. Classificação dos dispositivos
5. Cálculo de utilização da rede
6. Armazenamento local e envio para InfluxDB

## 📁 Saídas

- `dados.json` → histórico estruturado
- `dados.csv` → análise tabular

## 🚀 Possíveis melhorias

- Identificação mais precisa de dispositivos
- Dashboard em tempo real
- Sistema de alertas
- Monitoramento contínuo

## 👨‍💻 Autor

Matheus Brito
