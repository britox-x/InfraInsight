#!/bin/bash
# Script completo de testes

echo "🧪 Executando todos os testes do InfraInsight"
echo "============================================="
echo ""

source venv/bin/activate

echo "📝 Testes Básicos..."
pytest tests/unit/test_basic.py -v --tb=short

echo ""
echo "📝 Testes do Classificador..."
pytest tests/unit/test_classifier.py -v --tb=short

echo ""
echo "📝 Testes do InfraScore..."
pytest tests/unit/test_infrascore.py -v --tb=short

echo ""
echo "📝 Testes do Scanner..."
pytest tests/unit/test_scanner.py -v --tb=short

echo ""
echo "📝 Testes de Integração..."
pytest tests/integration/test_real_classifier.py -v --tb=short

echo ""
echo "📊 Relatório de cobertura..."
pytest tests/ --cov=core --cov-report=term --cov-report=html -v --tb=short \
    --ignore=tests/unit/test_imports.py 2>/dev/null || true

echo ""
echo "✅ Testes concluídos!"
echo "📊 Relatório HTML: htmlcov/index.html"
