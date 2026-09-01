#!/bin/bash
# Restore do sistema InfraInsight

set -e

if [ -z "$1" ]; then
    echo "❌ Uso: ./scripts/restore.sh <arquivo_backup.tar.gz>"
    exit 1
fi

BACKUP_FILE=$1

if [ ! -f "$BACKUP_FILE" ]; then
    echo "❌ Arquivo não encontrado: $BACKUP_FILE"
    exit 1
fi

echo "🔄 Restaurando backup: $BACKUP_FILE"

# Parar serviços
if [ -f "stop_all.sh" ]; then
    ./stop_all.sh
fi

# Extrair backup
TEMP_DIR=$(mktemp -d)
tar -xzf "$BACKUP_FILE" -C "$TEMP_DIR"

# Restaurar banco de dados
if [ -f "$TEMP_DIR"/*/infrainsight.db ]; then
    cp "$TEMP_DIR"/*/infrainsight.db storage/
    echo "✅ Banco de dados restaurado"
fi

# Restaurar configurações
if [ -f "$TEMP_DIR"/*/config.json ]; then
    cp "$TEMP_DIR"/*/config.json .
    echo "✅ Configurações restauradas"
fi

# Restaurar histórico
if [ -f "$TEMP_DIR"/*/historico_scans.json ]; then
    cp "$TEMP_DIR"/*/historico_scans.json storage/
    echo "✅ Histórico restaurado"
fi

rm -rf "$TEMP_DIR"

# Reiniciar serviços
if [ -f "start_all.sh" ]; then
    ./start_all.sh
fi

echo "✅ Restore concluído!"
