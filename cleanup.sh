#!/bin/bash
# cleanup.sh - Limpar arquivos antigos do InfraInsight
# Executar semanalmente para manter o sistema leve

echo "🧹 Iniciando limpeza de arquivos antigos..."
echo "📅 Data: $(date)"
echo ""

# Limpar relatórios PDF com mais de 60 dias (2 meses)
DELETED=0
for f in reports/*.pdf; do
    if [ -f "$f" ]; then
        if find "$f" -mtime +60 -type f | grep -q .; then
            rm "$f"
            echo "  ❌ Removido: $(basename $f)"
            ((DELETED++))
        fi
    fi
done
echo "✅ PDFs removidos: $DELETED"

# Limpar gráficos com mais de 60 dias (2 meses)
DELETED=0
for f in reports/graficos/*.png; do
    if [ -f "$f" ]; then
        if find "$f" -mtime +60 -type f | grep -q .; then
            rm "$f"
            echo "  ❌ Removido: $(basename $f)"
            ((DELETED++))
        fi
    fi
done
echo "✅ Gráficos removidos: $DELETED"

# Limpar CSVs com mais de 30 dias (1 mês)
DELETED=0
for f in exports/*.csv; do
    if [ -f "$f" ]; then
        if find "$f" -mtime +30 -type f | grep -q .; then
            rm "$f"
            echo "  ❌ Removido: $(basename $f)"
            ((DELETED++))
        fi
    fi
done
echo "✅ CSVs removidos: $DELETED"

# Limpar logs com mais de 60 dias (2 meses)
DELETED=0
for f in logs/*.log; do
    if [ -f "$f" ]; then
        if find "$f" -mtime +60 -type f | grep -q .; then
            rm "$f"
            echo "  ❌ Removido: $(basename $f)"
            ((DELETED++))
        fi
    fi
done
echo "✅ Logs removidos: $DELETED"

# Manter apenas últimos 100 scans no JSON (não apagar tudo)
if [ -f storage/historico_scans.json ]; then
    # Contar linhas aproximadas
    LINES=$(wc -l < storage/historico_scans.json)
    if [ $LINES -gt 500 ]; then
        tail -n 100 storage/historico_scans.json > storage/historico_scans.tmp
        mv storage/historico_scans.tmp storage/historico_scans.json
        echo "✅ Histórico JSON reduzido para últimas 100 entradas"
    fi
fi

echo ""
echo "🎉 Limpeza concluída!"
echo "📊 Mantidos: PDFs e gráficos com menos de 60 dias, CSVs com menos de 30 dias"
