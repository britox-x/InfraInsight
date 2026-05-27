#!/bin/bash
echo "🛑 Parando InfraInsight..."

# Parar Dashboard
pkill -f "dashboard/app.py"
echo "✅ Dashboard parado"

# Parar Bot Telegram
pkill -f "telegram_bot_completo.py"
echo "✅ Bot Telegram parado"

echo "✅ Todos os serviços parados"
