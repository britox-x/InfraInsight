#!/bin/bash
# Monitora se o bot está rodando

if ! systemctl is-active --quiet infrainsight-bot; then
    echo "❌ Bot caiu! Reiniciando..."
    sudo systemctl restart infrainsight-bot
    # Enviar alerta via Telegram (usando o próprio bot)
    cd /home/matheus/InfraInsight
    python3 -c "from core.telegram_bot import enviar_telegram; enviar_telegram('⚠️ Bot reiniciado automaticamente!')"
fi
