#!/usr/bin/env python3
import requests
import json
import os
import time
import threading
import subprocess
import sqlite3
from datetime import datetime

CONFIG_PATH = "config.json"

def _get_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'r') as f:
            return json.load(f)
    return {}

def enviar_mensagem(chat_id, texto, parse_mode='HTML'):
    cfg = _get_config()
    token = cfg.get("telegram_token", "")
    if not token:
        return False
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    try:
        r = requests.post(url, json={'chat_id': chat_id, 'text': texto, 'parse_mode': parse_mode}, timeout=10)
        return r.status_code == 200
    except:
        return False

def enviar_pdf(chat_id, caminho_pdf):
    cfg = _get_config()
    token = cfg.get("telegram_token", "")
    if not token or not os.path.exists(caminho_pdf):
        return False
    url = f"https://api.telegram.org/bot{token}/sendDocument"
    try:
        with open(caminho_pdf, 'rb') as f:
            files = {'document': f}
            data = {'chat_id': chat_id, 'caption': 'Relatorio InfraInsight'}
            r = requests.post(url, files=files, data=data, timeout=30)
        return r.status_code == 200
    except:
        return False

def encontrar_ultimo_pdf():
    reports_dir = "reports"
    if not os.path.exists(reports_dir):
        return None
    pdfs = [f for f in os.listdir(reports_dir) if f.endswith('.pdf')]
    if not pdfs:
        return None
    pdfs.sort(reverse=True)
    return os.path.join(reports_dir, pdfs[0])

def obter_ultimo_scan():
    try:
        db_path = "storage/infrainsight.db"
        if not os.path.exists(db_path):
            return None
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT timestamp, ips_ativos, risco_medio FROM scans ORDER BY id DESC LIMIT 1")
        result = cursor.fetchone()
        conn.close()
        if result:
            return {'timestamp': result[0][:19], 'dispositivos': result[1], 'risco': result[2]}
        return None
    except:
        return None

def obter_dashboard_url():
    import subprocess
    import socket
    try:
        # Tentar obter IP real
        result = subprocess.run(['hostname', '-I'], capture_output=True, text=True)
        ip = result.stdout.strip().split()[0]
        return f"http://{ip}:5000"
    except:
        return f"http://{socket.gethostname()}.local:5000"

def executar_scan():
    try:
        import subprocess
        # Usar o python do venv diretamente
        resultado = subprocess.run(
            ['/home/matheus/InfraInsight/venv/bin/python', '/home/matheus/InfraInsight/scanner.py'],
            capture_output=True,
            text=True,
            timeout=180,
            cwd='/home/matheus/InfraInsight'
        )
        print(f"[BOT] Scan return code: {resultado.returncode}")
        if resultado.returncode != 0:
            print(f"[BOT] Erro: {resultado.stderr[:200]}")
        return resultado.returncode == 0
    except subprocess.TimeoutExpired:
        print("[BOT] Scan timeout")
        return False
    except Exception as e:
        print(f"[BOT] Erro: {e}")
        return False



def processar_comando(texto, chat_id):
    texto = texto.lower().strip()
    print(f"Comando: {texto}")
    
    if texto == '/start':
        msg = "🔒 INFRAINSIGHT BOT\n\nComandos: /status, /scan, /report, /dashboard, /help"
        enviar_mensagem(chat_id, msg)
    
    elif texto == '/help':
        msg = """🤖 INFRAINSIGHT BOT - COMANDOS

📊 Informações
/status - Status atual da rede
/scan - Executar novo scan
/report - Baixar último relatório PDF
/dashboard - Link do dashboard

❓ Ajuda
/help - Mostrar esta ajuda"""
        enviar_mensagem(chat_id, msg)
    
    elif texto == '/status':
        scan = obter_ultimo_scan()
        if scan:
            msg = f"📊 STATUS\nData: {scan['timestamp']}\nDispositivos: {scan['dispositivos']}\nRisco: {scan['risco']}/10"
        else:
            msg = "Nenhum scan. Use /scan"
        enviar_mensagem(chat_id, msg)
    
    elif texto == '/scan':
        enviar_mensagem(chat_id, "🔍 Iniciando scan... (30-60 segundos)")
        def scan_thread():
            if executar_scan():
                scan = obter_ultimo_scan()
                if scan:
                    enviar_mensagem(chat_id, f"✅ SCAN CONCLUIDO!\nDispositivos: {scan['dispositivos']}\nRisco: {scan['risco']}/10")
                else:
                    enviar_mensagem(chat_id, "✅ Scan concluido!")
            else:
                enviar_mensagem(chat_id, "❌ Erro no scan")
        threading.Thread(target=scan_thread, daemon=True).start()
    
    elif texto == '/dashboard':
        url = obter_dashboard_url()
        enviar_mensagem(chat_id, f"📊 Dashboard: {url}")
    
    elif texto == '/report':
        enviar_mensagem(chat_id, "📄 Buscando relatorio...")
        pdf = encontrar_ultimo_pdf()
        if pdf:
            enviar_pdf(chat_id, pdf)
        else:
            enviar_mensagem(chat_id, "❌ Nenhum relatorio. Execute /scan")
    
    elif texto == '/ip':
        import subprocess
        try:
            result = subprocess.run(['hostname', '-I'], capture_output=True, text=True)
            ip = result.stdout.strip().split()[0]
            enviar_mensagem(chat_id, f"🌐 IP: {ip}\nDashboard: http://{ip}:5000")
        except:
            enviar_mensagem(chat_id, "❌ Erro ao obter IP")
    
    else:
        enviar_mensagem(chat_id, f"❌ Comando '{texto}' nao reconhecido. Use /help")

def iniciar_bot():
    print("="*50)
    print("Bot Telegram INFRAINSIGHT ativo!")
    print("Comandos: /status, /scan, /report, /dashboard, /help")
    print("="*50)
    last_id = 0
    while True:
        try:
            cfg = _get_config()
            token = cfg.get("telegram_token", "")
            if not token:
                time.sleep(10)
                continue
            url = f"https://api.telegram.org/bot{token}/getUpdates"
            r = requests.get(url, params={'timeout': 30, 'offset': last_id + 1}, timeout=35)
            data = r.json()
            if data.get('ok'):
                for u in data.get('result', []):
                    last_id = u['update_id']
                    if 'message' in u and 'text' in u['message']:
                        processar_comando(u['message']['text'], u['message']['chat']['id'])
            time.sleep(1)
        except Exception as e:
            print(f"Erro: {e}")
            time.sleep(5)

if __name__ == "__main__":
    iniciar_bot()
