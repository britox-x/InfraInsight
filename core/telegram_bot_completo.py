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
import html
from datetime import datetime
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCANNER_PATH = os.path.join(BASE_DIR, 'scanner.py')
DB_PATH = os.path.join(BASE_DIR, 'storage', 'infrainsight.db')
load_dotenv(os.path.join(BASE_DIR, '.env'))

from core.infra_score import formatar_infra_score
from core.wifi_scanner import scan_wifi_completo, listar_interfaces_wifi
from core.persistence import obter_eventos_recentes

CONFIG_PATH = "config.json"

def _get_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'r') as f:
            return json.load(f)
    return {}

def _get_telegram_token():
    return os.getenv("INFRA_TELEGRAM_TOKEN", "").strip()


def _get_telegram_allowed_users():
    configured_users = os.getenv("INFRA_TELEGRAM_ALLOWED_USERS", "")
    entries = configured_users.split(",")
    if not configured_users.strip() or any(not entry.strip() for entry in entries):
        raise ValueError(
            "Configure INFRA_TELEGRAM_ALLOWED_USERS com IDs numéricos "
            "de usuários autorizados."
        )

    users = set()
    for entry in entries:
        user_id = entry.strip()
        if not re.fullmatch(r"[0-9]+", user_id) or int(user_id) <= 0:
            raise ValueError(
                "INFRA_TELEGRAM_ALLOWED_USERS deve conter apenas IDs "
                "numéricos positivos separados por vírgula."
            )
        users.add(int(user_id))
    return users


def _processar_atualizacao(update, authorized_users):
    message = update.get("message")
    if not isinstance(message, dict):
        return

    sender = message.get("from")
    chat = message.get("chat")
    if not isinstance(sender, dict) or not isinstance(chat, dict):
        return

    sender_id = sender.get("id")
    if (
        not isinstance(sender_id, int)
        or isinstance(sender_id, bool)
        or sender_id not in authorized_users
    ):
        return

    text = message.get("text")
    chat_id = chat.get("id")
    if isinstance(text, str) and isinstance(chat_id, int):
        processar_comando(text, chat_id)


def enviar_mensagem(chat_id, texto, parse_mode='Markdown'):
    token = _get_telegram_token()
    if not token:
        return False
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    try:
        r = requests.post(url, json={'chat_id': chat_id, 'text': texto, 'parse_mode': parse_mode}, timeout=10)
        return r.status_code == 200
    except:
        return False

def enviar_pdf(chat_id, caminho_pdf):
    token = _get_telegram_token()
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
    reports_dir = os.path.join(BASE_DIR, 'reports')
    if not os.path.exists(reports_dir):
        return None
    pdfs = [f for f in os.listdir(reports_dir) if f.endswith('.pdf')]
    if not pdfs:
        return None
    pdfs.sort(reverse=True)
    return os.path.join(reports_dir, pdfs[0])

def obter_ultimo_scan():
    if not os.path.exists(DB_PATH):
        return None
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        result = conn.execute(
            "SELECT id, timestamp, ips_ativos, infra_score, "
            "infra_score_cobertura, score_formula "
            "FROM scans ORDER BY id DESC LIMIT 1"
        ).fetchone()
    if not result:
        return None
    return {
        "id": result["id"],
        "timestamp": result["timestamp"][:19] if result["timestamp"] else "—",
        "dispositivos": result["ips_ativos"],
        "infra_score": result["infra_score"],
        "infra_score_cobertura": result["infra_score_cobertura"],
        "score_formula": result["score_formula"],
        "score_texto": formatar_score_status(result),
    }


def formatar_score_status(scan):
    return formatar_infra_score(
        scan["infra_score"], scan["infra_score_cobertura"]
    )


def _formatar_horario_evento(timestamp):
    try:
        return datetime.fromisoformat(timestamp).strftime("%d/%m %H:%M")
    except (TypeError, ValueError):
        return str(timestamp or "—")


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
            [sys.executable, SCANNER_PATH],
            capture_output=True, text=True, timeout=180, cwd=BASE_DIR
        )
        print(f"[BOT] Scan return code: {resultado.returncode}")
        if resultado.stdout:
            print(f"[BOT] Scan output:\n{resultado.stdout}")
        if resultado.returncode != 0 and resultado.stderr:
            print(f"[BOT] Scan error:\n{resultado.stderr}")
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
🕒 *Movimentações recentes* → /eventos
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
/eventos - Ver entradas e saídas recentes
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
            if scan["infra_score"] is None:
                status_emoji = "⚪"
                status_texto = "InfraScore indisponível"
            elif scan["infra_score"] <= 2:
                status_emoji = "✅"
                status_texto = "Tudo seguro!"
            elif scan["infra_score"] <= 5:
                status_emoji = "⚠️"
                status_texto = "Alguns cuidados necessários"
            else:
                status_emoji = "🔴"
                status_texto = "Risco detectado!"
            
            msg = f"""
{status_emoji} *SAÚDE DA SUA REDE*

📡 *Dispositivos conectados:* {scan['dispositivos']}
🆔 *Scan:* #{scan['id']}
📊 *Nível de segurança:* {status_texto}
⚠️ *InfraScore:* {scan['score_texto']}

📱 *Para detalhes:* /report
            """
        else:
            msg = "❌ *Ainda não fiz nenhum scan.*\n\nDigite /scan para começar!"
        enviar_mensagem(chat_id, msg)

    elif texto == '/eventos':
        events = obter_eventos_recentes(limite=10, db_path=DB_PATH)
        if not events:
            enviar_mensagem(
                chat_id, "🕒 Nenhuma movimentação registrada ainda."
            )
        else:
            lines = ["🕒 <b>Últimas movimentações na rede</b>", ""]
            for event in events:
                entered = event["event"] == "ENTROU"
                marker = "🟢" if entered else "🔴"
                label = "Entrou" if entered else "Saiu"
                name = (
                    event.get("device_name")
                    or event.get("mac_address")
                    or "Dispositivo sem identificação"
                )
                ip_address = event.get("ip_address") or "IP desconhecido"
                randomized_suffix = (
                    " · 🎲 MAC possivelmente rotativo"
                    if event.get("mac_randomizado")
                    else ""
                )
                lines.append(
                    f"{marker} <code>{html.escape(_formatar_horario_evento(event.get('timestamp')))}</code> "
                    f"<b>{label}</b> · {html.escape(str(name)[:48])} "
                    f"({html.escape(str(ip_address)[:45])})"
                    f"{randomized_suffix}"
                )
            enviar_mensagem(chat_id, "\n".join(lines), parse_mode="HTML")
    
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
        try:
            from gerar_relatorio import gerar_relatorio
            pdf = gerar_relatorio()
        except Exception as e:
            print(f"[BOT] Erro ao gerar relatório: {e}")
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
    if not _get_telegram_token():
        raise ValueError("Configure INFRA_TELEGRAM_TOKEN no arquivo .env.")
    authorized_users = _get_telegram_allowed_users()

    print("="*50)
    print("Bot Telegram INFRAINSIGHT ativo!")
    print("Comandos: /status, /scan, /eventos, /report, /dashboard, /wifi, /help")
    print("Novos: /ping, /uptime, /ip, /info")
    print(f"[BOT] Acesso restrito a {len(authorized_users)} usuário(s) autorizado(s).")
    print("="*50)
    last_id = 0
    while True:
        try:
            token = _get_telegram_token()
            if not token:
                time.sleep(10)
                continue
            url = f"https://api.telegram.org/bot{token}/getUpdates"
            r = requests.get(url, params={'timeout': 30, 'offset': last_id + 1}, timeout=35)
            data = r.json()
            if data.get('ok'):
                for u in data.get('result', []):
                    last_id = u['update_id']
                    _processar_atualizacao(u, authorized_users)
            time.sleep(1)
        except Exception as e:
            print(f"Erro: {e}")
            time.sleep(5)

if __name__ == "__main__":
    iniciar_bot()
