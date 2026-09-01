#!/bin/bash
set -e

echo "🚀 Iniciando deploy do InfraInsight..."

if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 não encontrado"
    exit 1
fi

if ! command -v nmap &> /dev/null; then
    echo "⚠️ Nmap não encontrado. Instalando..."
    sudo apt-get update && sudo apt-get install -y nmap
fi

python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

if [ ! -f ".env" ]; then
    cp .env.example .env
    echo "⚠️ Configure o arquivo .env com suas credenciais"
fi

echo "✅ Deploy concluído!"
echo ""
echo "Para iniciar: ./start_all.sh"
