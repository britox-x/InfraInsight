#!/bin/bash
echo "📊 STATUS INFRAINSIGHT"
echo "======================"

# Dashboard
if pgrep -f "app.py" > /dev/null; then
    PID=$(pgrep -f "app.py" | head -1)
    echo "✅ Dashboard: Rodando (PID: $PID)"
else
    echo "❌ Dashboard: Parado"
fi

# Bot Telegram
if pgrep -f "telegram_bot_completo" > /dev/null; then
    PID=$(pgrep -f "telegram_bot_completo" | head -1)
    echo "✅ Bot Telegram: Rodando (PID: $PID)"
else
    echo "❌ Bot Telegram: Parado"
fi

echo ""
echo "🔗 Dashboard: http://192.168.1.73:5000"
echo "🤖 Bot: @Infrainsight_bot"
