#!/bin/bash
cd /home/matheus/InfraInsight
source venv/bin/activate

# Matar processos antigos
pkill -f "app.py" 2>/dev/null
pkill -f "telegram_bot_completo" 2>/dev/null
sleep 1

# Dashboard
cd dashboard
nohup python app.py > dashboard.log 2>&1 &
cd ..

# Bot
nohup python core/telegram_bot_completo.py > telegram_bot.log 2>&1 &

sleep 2
echo "✅ InfraInsight rodando!"
echo "📊 Dashboard: http://192.168.1.73:5000"
echo "🤖 Bot: @Infrainsight_bot"
