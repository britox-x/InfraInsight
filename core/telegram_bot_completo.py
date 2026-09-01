#!/usr/bin/env python3
import requests
import json
import os
import sys
import time
import threading
import subprocess
import sqlite3
import re
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.wifi_scanner import scan_wifi_completo, listar_interfaces_wifi

CONFIG_PATH = "config.json"

def _get_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'r') as f:
            return json.load(f)
    return {}

def enviar_mensagem(chat_id, texto, parse_mode='Markdown'):
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
        result = subprocess.run(['hostname', '-I'], capture_output=True, text=True)
        ip = result.stdout.strip().split()[0]
        return f"http://{ip}:5000"
    except:
        return f"http://{socket.gethostname()}.local:5000"

def executar_scan():
    try:
        resultado = subprocess.run(
            ['/home/matheus/InfraInsight/venv/bin/python', '/home/matheus/InfraInsight/scanner.py'],
            capture_output=True, text=True, timeout=180, cwd='/home/matheus/InfraInsight'
        )
        print(f"[BOT] Scan return code: {resultado.returncode}")
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
        msg = """
🔒 *INFRAINSIGHT - Monitor da sua rede*

Olá! Vou te ajudar a cuidar da sua rede de forma simples.

*O que você quer fazer?*

🔍 *Ver rede agora* → /scan
📊 *Status atual* → /status  
📄 *Relatório completo* → /report
🌐 *Redes Wi-Fi* → /wifi
❓ *Ajuda* → /help

*Dica:* O /scan pode levar 30 segundos. Aguarde!
        """
        enviar_mensagem(chat_id, msg)
    
    elif texto == '/help':
        msg = """
🤖 *INFRAINSIGHT - AJUDA*

*Comandos disponíveis:*

📊 *Informações*
/status - Ver saúde da rede
/scan - Escanear dispositivos agora
/report - Baixar relatório completo
/dashboard - Link para painel admin

📡 *Wi-Fi*
/wifi - Ver redes próximas

🆕 *Novos comandos*
/ping - Ver se o bot está vivo
/uptime - Tempo de atividade do sistema
/ip - Ver IPs do servidor
/info - Informações do sistema

❓ *Ajuda*
/help - Mostrar esta ajuda
/start - Mensagem inicial
        """
        enviar_mensagem(chat_id, msg)
    
    # NOVOS COMANDOS
    elif texto == '/ping':
        enviar_mensagem(chat_id, "🏓 *Pong!* Bot está vivo e respondendo!")
    
    elif texto == '/uptime':
        try:
            result = subprocess.run(['uptime'], capture_output=True, text=True)
            uptime_text = result.stdout.strip()
            # Extrair apenas o tempo
            match = re.search(r'up\s+(.*?),\s+\d+ users', uptime_text)
            if match:
                uptime_text = match.group(1)
            # Também pegar a carga
            load_match = re.search(r'load average:\s+(.*?)$', result.stdout.strip())
            load_text = load_match.group(1) if load_match else ""
            
            msg = f"⏱️ *Tempo de atividade:*\n```\n{uptime_text}\n```"
            if load_text:
                msg += f"\n📊 *Carga do sistema:*\n```\n{load_text}\n```"
            enviar_mensagem(chat_id, msg)
        except Exception as e:
            enviar_mensagem(chat_id, f"❌ Erro ao obter uptime: {str(e)}")
    
    elif texto == '/ip':
        try:
            result = subprocess.run(['hostname', '-I'], capture_output=True, text=True)
            ips = result.stdout.strip().split()
            
            # Também pegar IP da interface principal
            result2 = subprocess.run(['ip', 'route', 'get', '1'], capture_output=True, text=True)
            main_ip = ""
            match = re.search(r'src\s+([\d.]+)', result2.stdout)
            if match:
                main_ip = match.group(1)
            
            if ips:
                msg = "🌐 *IPs do servidor:*\n"
                for ip in ips:
                    if ip == main_ip:
                        msg += f"• `{ip}` ⭐ *(principal)*\n"
                    else:
                        msg += f"• `{ip}`\n"
                
                # Adicionar informações de rede
                result3 = subprocess.run(['ip', 'route', '|', 'grep', 'default'], 
                                       shell=True, capture_output=True, text=True)
                gateway = ""
                match = re.search(r'via\s+([\d.]+)', result3.stdout)
                if match:
                    gateway = match.group(1)
                    msg += f"\n🚪 *Gateway:* `{gateway}`"
                
                enviar_mensagem(chat_id, msg)
            else:
                enviar_mensagem(chat_id, "❌ Nenhum IP encontrado.")
        except Exception as e:
            enviar_mensagem(chat_id, f"❌ Erro ao obter IPs: {str(e)}")
    
    elif texto == '/info':
        try:
            import platform
            msg = "💻 *Informações do Sistema*\n\n"
            msg += f"🐧 *Sistema:* {platform.system()} {platform.release()}\n"
            msg += f"🖥️ *Arquitetura:* {platform.machine()}\n"
            msg += f"🐍 *Python:* {platform.python_version()}\n"
            
            # Espaço em disco
            disk = subprocess.run(['df', '-h', '/'], capture_output=True, text=True)
            disk_lines = disk.stdout.strip().split('\n')
            if len(disk_lines) > 1:
                disk_info = disk_lines[1].split()
                msg += f"💾 *Disco:* {disk_info[3]} livre de {disk_info[1]}\n"
            
            # Memória
            mem = subprocess.run(['free', '-h'], capture_output=True, text=True)
            mem_lines = mem.stdout.strip().split('\n')
            if len(mem_lines) > 1:
                mem_info = mem_lines[1].split()
                msg += f"🧠 *Memória:* {mem_info[2]} usado de {mem_info[1]}"
            
            enviar_mensagem(chat_id, msg)
        except Exception as e:
            enviar_mensagem(chat_id, f"❌ Erro: {str(e)}")
    
    elif texto == '/status':
        scan = obter_ultimo_scan()
        if scan:
            if scan['risco'] <= 2:
                status_emoji = "✅"
                status_texto = "Tudo seguro!"
            elif scan['risco'] <= 5:
                status_emoji = "⚠️"
                status_texto = "Alguns cuidados necessários"
            else:
                status_emoji = "🔴"
                status_texto = "Risco detectado!"
            
            msg = f"""
{status_emoji} *SAÚDE DA SUA REDE*

📡 *Dispositivos conectados:* {scan['dispositivos']}
📊 *Nível de segurança:* {status_texto}
⚠️ *Risco:* {scan['risco']}/10

📱 *Para detalhes:* /report
            """
        else:
            msg = "❌ *Ainda não fiz nenhum scan.*\n\nDigite /scan para começar!"
        enviar_mensagem(chat_id, msg)
    
    elif texto == '/scan':
        enviar_mensagem(chat_id, "🔍 *Iniciando verificação da rede...*\n\nAguarde! ⏳")
        def scan_thread():
            if executar_scan():
                scan = obter_ultimo_scan()
                if scan:
                    msg = f"""
✅ *VERIFICAÇÃO CONCLUÍDA!*

📡 *Encontrei {scan['dispositivos']} dispositivos*
📊 *Nível de segurança:* {scan['risco']}/10

📄 *Relatório completo:* /report
                    """
                    enviar_mensagem(chat_id, msg)
                else:
                    enviar_mensagem(chat_id, "✅ Verificação concluída!")
            else:
                enviar_mensagem(chat_id, "❌ *Ops!* Não consegui fazer a verificação.")
        threading.Thread(target=scan_thread, daemon=True).start()
    
    elif texto == '/dashboard':
        url = obter_dashboard_url()
        enviar_mensagem(chat_id, f"📊 *Dashboard:* {url}")
    
    elif texto == '/report':
        enviar_mensagem(chat_id, "📄 *Buscando relatório...*")
        pdf = encontrar_ultimo_pdf()
        if pdf:
            enviar_pdf(chat_id, pdf)
        else:
            enviar_mensagem(chat_id, "❌ *Nenhum relatório.* Execute /scan primeiro.")
    
    elif texto == '/wifi':
        enviar_mensagem(chat_id, "📡 *Procurando redes Wi-Fi...*")
        def wifi_thread():
            try:
                interfaces = listar_interfaces_wifi()
                if not interfaces:
                    enviar_mensagem(chat_id, "❌ *Nenhuma interface Wi-Fi encontrada.*")
                    return
                redes = scan_wifi_completo(interfaces[0])
                if not redes:
                    enviar_mensagem(chat_id, "📡 *Nenhuma rede Wi-Fi encontrada.*")
                    return
                msg = "*📡 REDES WI-FI ENCONTRADAS*\n\n"
                for rede in redes[:15]:
                    icone = "🔒" if rede.get('encrypted', True) else "🌐"
                    ssid = rede.get('ssid', 'Rede Oculta')[:30]
                    sinal_texto = rede.get('sinal_texto', '📶 Desconhecido')
                    seguranca = rede.get('encryption_type', 'Desconhecida')
                    msg += f"{icone} *{ssid}*\n   {sinal_texto}\n   🔐 {seguranca}\n\n"
                enviar_mensagem(chat_id, msg)
            except Exception as e:
                enviar_mensagem(chat_id, f"❌ *Erro:* {str(e)[:100]}")
        threading.Thread(target=wifi_thread, daemon=True).start()
    
    else:
        enviar_mensagem(chat_id, f"❌ *Comando '{texto}' não reconhecido.* Use /help")

def iniciar_bot():
    print("="*50)
    print("Bot Telegram INFRAINSIGHT ativo!")
    print("Comandos: /status, /scan, /report, /dashboard, /wifi, /help")
    print("Novos: /ping, /uptime, /ip, /info")
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
