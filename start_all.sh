#!/bin/bash
echo "🚀 Iniciando InfraInsight..."

cd /home/matheus/InfraInsight

# Ativar ambiente virtual
source venv/bin/activate

# 1. Iniciar Dashboard
if ! pgrep -f "dashboard/app.py" > /dev/null; then
    cd dashboard
    nohup python app.py > dashboard.log 2>&1 &
    cd ..
    echo "✅ Dashboard iniciado (porta 5000)"
else
    echo "⚠️ Dashboard já está rodando"
fi

# 2. Iniciar Bot Telegram (se não estiver rodando)
if ! pgrep -f "telegram_bot_completo.py" > /dev/null; then
    nohup python core/telegram_bot_completo.py > telegram_bot.log 2>&1 &
    echo "✅ Bot Telegram iniciado"
else
    echo "⚠️ Bot Telegram já está rodando"
fi

echo ""
echo "=========================================="
echo "📊 Dashboard: http://192.168.1.73:5000"
echo "🤖 Bot: @Infrainsight_bot"
echo "🔐 Login: admin / admin123"
echo "=========================================="
