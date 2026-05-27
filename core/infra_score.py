def calcular_infra_score(scan_data):
    score = 0
    if any(23 in d.get('open_ports', []) for d in scan_data.get('dispositivos', [])):
        score += 3
    if any(554 in d.get('open_ports', []) for d in scan_data.get('dispositivos', [])):
        score += 1
    return min(score, 10)
