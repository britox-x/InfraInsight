#!/bin/bash
echo "🚀 Iniciando InfraInsight..."

cd /home/matheus/InfraInsight

# Matar processos antigos FORÇADAMENTE
pkill -9 -f "dashboard/app.py" 2>/dev/null
pkill -9 -f "telegram_bot_completo" 2>/dev/null
pkill -9 -f "python.*app" 2>/dev/null
sleep 2

# Ativar venv
source venv/bin/activate

# Dashboard
cd dashboard
nohup python app.py > dashboard.log 2>&1 &
DASH_PID=$!
echo "✅ Dashboard iniciado (PID: $DASH_PID)"
cd ..

# Bot Telegram
nohup python core/telegram_bot_completo.py > telegram_bot.log 2>&1 &
BOT_PID=$!
echo "✅ Bot Telegram iniciado (PID: $BOT_PID)"

sleep 3
echo ""
echo "📊 Dashboard: http://192.168.1.73:5000"
echo "🤖 Bot: @Infrainsight_bot"
echo ""
echo "Processos rodando:"
ps aux | grep -E "app.py|telegram_bot" | grep -v grep | grep -v "grep"
