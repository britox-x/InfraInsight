#!/bin/bash
echo "🔧 Corrigindo scanner.py - Removendo aviso do Telegram..."

# Fazer backup
cp scanner.py scanner.py.bak_telegram

# Comentar as linhas relacionadas ao telegram_bot_completo
sed -i '/telegram_bot_completo/s/^/# /' scanner.py
sed -i '/iniciar_em_background/s/^/# /' scanner.py
sed -i '/⚠️ Módulo telegram_bot_completo não encontrado/s/^/# /' scanner.py

# Remover a tentativa de importação
sed -i '/from core.telegram_bot_completo import/s/^/# /' scanner.py

echo "✅ Correção aplicada!"
echo ""
echo "Para testar: python scanner.py"
