def analisar_evolucao(scans_anteriores, scans_atuais):
    """Analisa evolução da rede"""
    if len(scans_anteriores) < 2:
        return {"mensagem": "Dados insuficientes para análise de evolução"}
    
    risco_anterior = scans_anteriores[-2].get('risco_medio', 0)
    risco_atual = scans_atuais.get('risco_medio', 0)
    
    if risco_atual < risco_anterior:
        tendencia = "✅ Melhorando"
    elif risco_atual > risco_anterior:
        tendencia = "⚠️ Piorando"
    else:
        tendencia = "➡️ Estável"
    
    return {
        "tendencia": tendencia,
        "risco_anterior": risco_anterior,
        "risco_atual": risco_atual,
        "diferenca": round(risco_atual - risco_anterior, 1)
    }
