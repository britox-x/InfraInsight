#!/bin/bash
echo "🚀 Iniciando InfraInsight..."

cd /home/matheus/InfraInsight

# Matar processos antigos
pkill -9 -f "app.py" 2>/dev/null
pkill -9 -f "telegram_bot_completo" 2>/dev/null
sleep 2

# Dashboard
cd dashboard
nohup /home/matheus/InfraInsight/venv/bin/python app.py > dashboard.log 2>&1 &
echo "✅ Dashboard iniciado (PID: $!)"
cd ..

# Bot
nohup /home/matheus/InfraInsight/venv/bin/python core/telegram_bot_completo.py > telegram_bot.log 2>&1 &
echo "✅ Bot Telegram iniciado (PID: $!)"

sleep 2
echo ""
echo "📊 Dashboard: http://192.168.1.73:5000"
echo "🤖 Bot: @Infrainsight_bot"
echo "🔐 Login: admin / admin123"
echo ""
echo "Processos rodando:"
ps aux | grep -E "app.py|telegram_bot_completo" | grep -v grep
