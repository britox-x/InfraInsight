#!/bin/bash
# Script seguro para iniciar o bot - garante apenas uma instância

echo "🔍 Verificando instâncias do bot..."

# Matar processos existentes
echo "🛑 Matando processos antigos..."
sudo pkill -f telegram_bot_completo.py 2>/dev/null
sleep 2

# Parar serviço se estiver rodando
echo "🛑 Parando serviço..."
sudo systemctl stop infrainsight-bot 2>/dev/null
sleep 2

# Iniciar serviço
echo "🚀 Iniciando serviço..."
sudo systemctl start infrainsight-bot

# Verificar status
sleep 2
sudo systemctl status infrainsight-bot

echo ""
echo "✅ Bot iniciado!"
echo "📱 Envie /ping no Telegram para testar"
