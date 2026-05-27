def analisar_canais_wifi(redes_wifi):
    """Analisa saturação dos canais Wi-Fi"""
    canais = {}
    for rede in redes_wifi:
        canal = rede.get('channel', '?')
        if canal != '?' and canal.isdigit():
            canal = int(canal)
            canais[canal] = canais.get(canal, 0) + 1
    
    congestionados = [c for c, qtd in canais.items() if qtd > 5]
    
    resultado = {
        "canais": canais,
        "congestionados": congestionados,
        "total_redes": len(redes_wifi),
        "recomendacao": "Canal congestionado. Considere alterar o canal do roteador." if congestionados else "Boa distribuição de canais."
    }
    return resultado
