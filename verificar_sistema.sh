#!/bin/bash
# Script de verificação completa do InfraInsight

echo "🔍 VERIFICANDO INFRAINSIGHT"
echo "==========================="
echo ""

# 1. Verificar ambiente
echo "📦 1. Ambiente Python:"
source venv/bin/activate
python --version
echo ""

# 2. Verificar dependências
echo "📚 2. Dependências principais:"
pip list --format=columns | grep -E "flask|nmap|reportlab|matplotlib|pytest"
echo ""

# 3. Verificar arquivos core
echo "📁 3. Arquivos core:"
ls -1 core/*.py | wc -l | xargs echo "  Total de arquivos:"
echo ""

# 4. Verificar banco de dados
echo "🗄️ 4. Banco de dados:"
if [ -f "storage/infrainsight.db" ]; then
    SIZE=$(du -h storage/infrainsight.db | cut -f1)
    echo "  ✅ Banco existe ($SIZE)"
else
    echo "  ❌ Banco não encontrado"
fi
echo ""

# 5. Verificar testes
echo "🧪 5. Testes:"
pytest tests/ -v --tb=short 2>/dev/null | grep -E "passed|failed|skipped" | tail -1
echo ""

# 6. Verificar dashboard
echo "🌐 6. Dashboard:"
if pgrep -f "dashboard/app.py" > /dev/null; then
    echo "  ✅ Dashboard rodando (PID: $(pgrep -f dashboard/app.py))"
else
    echo "  ❌ Dashboard parado"
fi
echo ""

# 7. Verificar scanner
echo "🔍 7. Scanner:"
if pgrep -f "scanner.py" > /dev/null; then
    echo "  ✅ Scanner rodando (PID: $(pgrep -f scanner.py))"
else
    echo "  ❌ Scanner parado"
fi
echo ""

# 8. Verificar backups
echo "💾 8. Backups:"
BACKUPS=$(ls -1 backups/*.tar.gz 2>/dev/null | wc -l)
echo "  Total de backups: $BACKUPS"
echo ""

echo "✅ Verificação concluída!"
