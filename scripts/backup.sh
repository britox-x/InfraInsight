#!/bin/bash
set -e

BACKUP_DIR="backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="infrainsight_backup_${TIMESTAMP}"
BACKUP_PATH="${BACKUP_DIR}/${BACKUP_NAME}"

echo "🔄 Iniciando backup do InfraInsight..."

mkdir -p ${BACKUP_DIR}
mkdir -p ${BACKUP_PATH}

if [ -f "storage/infrainsight.db" ]; then
    cp storage/infrainsight.db ${BACKUP_PATH}/
    echo "✅ Banco de dados copiado"
fi

if [ -f "config.json" ]; then
    cp config.json ${BACKUP_PATH}/
    echo "✅ Configurações copiadas"
fi

if [ -f ".env" ]; then
    cp .env ${BACKUP_PATH}/
    echo "✅ Variáveis de ambiente copiadas"
fi

cd ${BACKUP_DIR}
tar -czf "${BACKUP_NAME}.tar.gz" ${BACKUP_NAME}
rm -rf ${BACKUP_NAME}
cd ..

echo "✅ Backup concluído: ${BACKUP_PATH}.tar.gz"
