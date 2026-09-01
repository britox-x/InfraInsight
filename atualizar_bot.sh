#!/bin/bash
echo "🔄 Atualizando o bot..."

# Parar o serviço
sudo systemctl stop infrainsight-bot

# Fazer backup do código
cp core/telegram_bot_completo.py core/telegram_bot_completo.py.bak

# Baixar atualizações (se usar git)
git pull

# Reiniciar
sudo systemctl start infrainsight-bot
sudo systemctl status infrainsight-bot

echo "✅ Bot atualizado!"
