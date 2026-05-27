#!/bin/bash
# Iniciar todos os serviços do InfraInsight

cd /home/matheus/InfraInsight

# Ativar ambiente virtual
source venv/bin/activate

# Iniciar dashboard (se não estiver rodando)
if ! pgrep -f "python app.py" > /dev/null; then
    cd dashboard
    nohup python app.py > dashboard.log 2>&1 &
    echo "✅ Dashboard iniciado (porta 5000)"
    cd ..
else
    echo "⚠️ Dashboard já está rodando"
fi

# Iniciar bot do Telegram (se não estiver rodando)
if ! pgrep -f "telegram_bot_completo" > /dev/null; then
    nohup python core/telegram_bot_completo.py > telegram_bot.log 2>&1 &
    echo "✅ Bot Telegram iniciado"
else
    echo "⚠️ Bot Telegram já está rodando"
fi

echo ""
echo "📊 Dashboard: http://localhost:5000"
echo "🤖 Bot Telegram: @Infrainsight_bot"
echo ""
echo "Para ver logs:"
echo "  Dashboard: tail -f dashboard/dashboard.log"
echo "  Bot: tail -f telegram_bot.log"
