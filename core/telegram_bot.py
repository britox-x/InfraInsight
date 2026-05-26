import requests
import json
import os

CONFIG_PATH = "config.json"

def _get_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'r') as f:
            return json.load(f)
    return {}

def enviar_telegram(mensagem):
    cfg = _get_config()
    token = cfg.get("telegram_token", "")
    chat_id = cfg.get("telegram_chat_id", "")
    if not token or not chat_id:
        return False
    try:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        r = requests.post(url, json={"chat_id": chat_id, "text": mensagem, "parse_mode": "HTML"}, timeout=10)
        return r.status_code == 200
    except:
        return False

def alerta_novo(disp):
    msg = f"🚨 NOVO DISPOSITIVO\nIP: {disp.get('ip')}\nTipo: {disp.get('tipo')}\nRisco: {disp.get('risco')}/10"
    return enviar_telegram(msg)

def alerta_porta(ip, porta, servico):
    msg = f"⚠️ PORTA PERIGOSA\nIP: {ip}\nPorta: {porta} ({servico})"
    return enviar_telegram(msg)

def alerta_resumo(dados):
    msg = f"📊 SCAN FINALIZADO\nIPs: {dados.get('ips_ativos',0)}\nRisco: {dados.get('risco_medio',0)}/10"
    return enviar_telegram(msg)
