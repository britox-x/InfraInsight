#!/bin/bash
echo "🛑 Parando InfraInsight..."

# Parar Dashboard
pkill -9 -f "app.py" 2>/dev/null
echo "✅ Dashboard parado"

# Parar Bot Telegram
pkill -9 -f "telegram_bot_completo" 2>/dev/null
echo "✅ Bot Telegram parado"

echo "✅ Todos os serviços parados"
