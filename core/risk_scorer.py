# core/risk_scorer.py

from datetime import datetime, timedelta
import random

def calcular_risco_avancado(device, historical_devices=None):
    """
    Calcula score de risco baseado em múltiplos fatores
    
    Args:
        device: dict com informações do dispositivo atual
        historical_devices: lista de dispositivos históricos para análise comportamental
    
    Returns:
        tuple: (score, detalhes)
    """
    score = 0
    details = []
    
    # 1. MAC randomizado (+1 para dispositivos móveis legítimos, +3 para outros)
    vendor = device.get('vendor', '').lower()
    mac = device.get('mac', '')
    
    if 'privado' in vendor or 'randomizado' in vendor:
        # Verificar se é dispositivo móvel comum (Android/iOS)
        if mac and mac.startswith(('46:', '4e:', '2a:', '6a:', '8a:', '9a:')):
            score += 1  # Menos risco para mobile legítimo
            details.append("MAC randomizado (comum em celulares)")
        else:
            score += 3  # Mais risco para randomização suspeita
            details.append("MAC randomizado suspeito")




    
    # 2. Dispositivo novo na rede (+2 se não existia antes)
    if historical_devices:
        mac_found = any(
            d.get('mac') == device.get('mac') 
            for d in historical_devices
        )
        if not mac_found:
            score += 2
            details.append("Dispositivo novo na rede")
    
    # 3. Portas suspeitas abertas (+1 a +3)
    open_ports = device.get('open_ports', [])
    suspicious_ports = {
        22: "SSH aberto",
        23: "Telnet (inseguro)",
        445: "SMB (risco ransomware)",
        3389: "RDP (força bruta)",
        5900: "VNC (potencial inseguro)",
        8080: "Proxy/Admin exposto",
        3306: "MySQL exposto",
        5432: "PostgreSQL exposto",
        27017: "MongoDB exposto"
    }
    
    for port in open_ports:
        if port in suspicious_ports:
            score += 2
            details.append(f"Porta {port} - {suspicious_ports[port]}")
    
    # 4. Fabricante raro (+1)
    rare_vendors = ['espressif', 'tuya', 'wemos', 'unknown']
    if any(v in device.get('vendor', '').lower() for v in rare_vendors):
        score += 1
        details.append("Fabricante incomum/dispositivo IoT")
    
    # 5. Hostname estranho (+1)
    strange_hostnames = ['localhost', 'unknown', 'android-', 'xiaomi-']
    hostname = device.get('hostname', '').lower()
    if any(hostname.startswith(sh) for sh in strange_hostnames) or len(hostname) < 3:
        score += 1
        details.append("Hostname suspeito ou genérico")
    
    # 6. Mudança de comportamento (+2 se histórico indica mudança)
    if historical_devices:
        prev_device = next(
            (d for d in historical_devices if d.get('mac') == device.get('mac')), 
            None
        )
        if prev_device:
            # Mudou de tipo?
            if prev_device.get('tipo') != device.get('tipo'):
                score += 2
                details.append("Mudança de comportamento/função")
            
            # Novas portas abertas?
            prev_ports = set(prev_device.get('open_ports', []))
            current_ports = set(device.get('open_ports', []))
            new_ports = current_ports - prev_ports
            if new_ports:
                score += len(new_ports)
                details.append(f"Novas portas abertas: {', '.join(map(str, new_ports))}")
    
    # 7. Dispositivo desconhecido (+2)
    if device.get('tipo') == 'desconhecido':
        score += 2
        details.append("Tipo de dispositivo desconhecido")
    
    # 8. Limitar score máximo a 10
    score = min(score, 10)
    
    # Bônus: dispositivos conhecidos baixam o risco
    if device.get('tipo') in ['computador_conhecido', 'roteador']:
        score = max(score - 1, 0)
    
    return score, details


def classificar_severidade(score):
    """Classifica a severidade baseada no score"""
    if score <= 2:
        return "Baixo", "success"
    elif score <= 5:
        return "Médio", "warning"
    elif score <= 7:
        return "Alto", "danger"
    else:
        return "Crítico", "critical"


def gerar_recomendacoes(score, details, device):
    """Gera recomendações específicas baseadas no risco"""
    recomendacoes = []
    
    if score >= 7:
        recomendacoes.append("⚠️ INVESTIGAR IMEDIATAMENTE - Alto risco detectado")
    
    if "MAC randomizado" in details:
        recomendacoes.append("Dispositivo com MAC randomizado - pode ser técnica de evasão")
    
    if "Dispositivo novo na rede" in details:
        recomendacoes.append("Novo dispositivo detectado - verificar autorização")
    
    ports_mentioned = [d for d in details if "Porta" in d]
    if ports_mentioned:
        recomendacoes.append(f"Portas potencialmente inseguras abertas: {', '.join(ports_mentioned)}")
        recomendacoes.append("Revisar regras de firewall e exposição desnecessária")
    
    if device.get('tipo') == 'desconhecido':
        recomendacoes.append("Dispositivo não identificado - investigar manualmente")
    
    if "Mudança de comportamento" in details:
        recomendacoes.append("Comportamento anômalo - possível comprometimento")
    
    if not recomendacoes and score < 3:
        recomendacoes.append("✅ Dispositivo parece seguro - manter monitoramento")
    
    # 9. Dispositivos móveis têm tolerância maior
    if device.get('tipo', '').startswith('mobile/'):
        if score >= 3:
            score = max(score - 1, 1)  # Reduz em 1, mínimo 1
            details.append("Dispositivo móvel - risco ajustado")

    return recomendacoes
