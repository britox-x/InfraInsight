#!/bin/bash
echo "🧪 TESTE COMPLETO FINAL"
echo "======================="
echo ""

source venv/bin/activate

echo "1️⃣ Extraindo dados do JSON..."
python -c "
from gerar_relatorio import extract_scan_data
d, h = extract_scan_data()
print(f'  ✅ {len(d)} dispositivos, {len(h)} histórico')
" 2>/dev/null || echo "  ❌ Falhou"

echo ""
echo "2️⃣ Gerando PDF com dados reais..."
python gerar_relatorio.py

echo ""
echo "3️⃣ Verificando PDF..."
ls -lh reports/*.pdf 2>/dev/null | tail -1

echo ""
echo "4️⃣ Testes unitários..."
pytest tests/unit/ -v --tb=short 2>/dev/null | grep -E "PASSED|FAILED|SKIPPED" | tail -3

echo ""
echo "✅ TESTE COMPLETO CONCLUÍDO!"
