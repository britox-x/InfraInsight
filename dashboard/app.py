#!/usr/bin/env python3
import hashlib
import json
import os
import sqlite3
import sys
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

from core.infra_score import (
    ADMIN_PORTS,
    calcular_infra_score,
    pontuar_vulnerabilidades,
)
import core.persistence as persistence

app = Flask(__name__)
app.secret_key = os.urandom(24)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'storage', 'infrainsight.db'))
USERS_DB = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'storage', 'users.db'))

persistence.DB_NAME = DB_PATH
persistence.init_database()

def init_users_db():
    os.makedirs(os.path.dirname(USERS_DB), exist_ok=True)
    conn = sqlite3.connect(USERS_DB)
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)')
    c.execute("SELECT * FROM users WHERE username = 'admin'")
    if not c.fetchone():
        h = hashlib.sha256('admin123'.encode()).hexdigest()
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", ('admin', h))
        conn.commit()
        print("✅ Usuario: admin / admin123")
    conn.close()

class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect(USERS_DB)
    c = conn.cursor()
    c.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
    u = c.fetchone()
    conn.close()
    return User(u[0], u[1]) if u else None

def verificar_login(username, password):
    h = hashlib.sha256(password.encode()).hexdigest()
    conn = sqlite3.connect(USERS_DB)
    c = conn.cursor()
    c.execute("SELECT id, username FROM users WHERE username = ? AND password = ?", (username, h))
    u = c.fetchone()
    conn.close()
    return u

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def calcular_infra_score(scan_data):
    motivos = []
    for d in scan_data.get('dispositivos', []):
        ports = d.get('open_ports', [])
        if isinstance(ports, str):
            try:
                ports = json.loads(ports)
            except (TypeError, ValueError):
                ports = []
        if 23 in ports:
            motivos.append(f"Telnet em {d.get('ip')}")
        if 554 in ports:
            motivos.append(f"RTSP em {d.get('ip')}")
        if set(ports) & ADMIN_PORTS:
            motivos.append(f"Porta administrativa em {d.get('ip')}")
        if set(ports) & {80, 443} and str(d.get('tipo', '')).lower() in {
            'gateway',
            'roteador',
            'router',
        }:
            motivos.append(f"HTTP/HTTPS no gateway {d.get('ip')}")
    total = scan_data.get('ips_ativos', 0)
    unknown = scan_data.get('desconhecidos', 0)
    if total > 0 and unknown / total > 0.3:
        motivos.append(f"{unknown}/{total} desconhecidos")
    software_risk = pontuar_vulnerabilidades(scan_data)
    if software_risk:
        motivos.append(f"CVEs conhecidas em software exposto (+{software_risk})")
    score = calcular_infra_score(scan_data)
    if score <= 2:
        status, cor = "✅ Saudável", "success"
    elif score <= 5:
        status, cor = "⚠️ Atenção", "warning"
    else:
        status, cor = "🔴 Risco Elevado", "danger"
    return {"score": score, "status": status, "cor": cor, "motivos": motivos}

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u = verificar_login(request.form.get('username'), request.form.get('password'))
        if u:
            login_user(User(u[0], u[1]))
            flash('Bem-vindo!', 'success')
            return redirect(url_for('index'))
        flash('Usuário ou senha inválidos', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    conn = get_db()
    total_scans = conn.execute("SELECT COUNT(*) as count FROM scans").fetchone()["count"]
    latest_scan = conn.execute("SELECT id, timestamp, ambiente, ips_ativos, uso, risco_medio, desconhecidos, mac_randomizados, recomendacao FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    if not latest_scan:
        latest_scan = {'id': 0, 'timestamp': datetime.now().isoformat(), 'ambiente': 'N/A', 'ips_ativos': 0, 'uso': 0, 'risco_medio': 0, 'desconhecidos': 0, 'mac_randomizados': 0, 'recomendacao': 'Nenhum scan'}
    else:
        latest_scan = dict(latest_scan)
    devices = []
    tipos_count = {}
    if latest_scan['id'] > 0:
        devices = conn.execute("SELECT ip, nome, mac, fabricante, tipo, risk_score, severity, open_ports FROM dispositivos WHERE scan_id = ? ORDER BY risk_score DESC", (latest_scan['id'],)).fetchall()
        for d in devices:
            t = d['tipo']
            tipos_count[t] = tipos_count.get(t, 0) + 1
    scan_data = {'dispositivos': [dict(d) for d in devices], 'ips_ativos': latest_scan.get('ips_ativos', 0), 'desconhecidos': latest_scan.get('desconhecidos', 0)}
    software_inventory = conn.execute("""
        SELECT a.hostname, a.mac_address, e.ip_address, e.port, e.protocol,
               e.service_name, s.product, s.version, s.cpe, s.confidence,
               s.cpe_source, s.cve_status, s.cve_status_reason,
               GROUP_CONCAT(c.cve_id, ', ') AS cve_ids
        FROM endpoints e
        JOIN assets a ON a.id = e.asset_id
        JOIN software_instances s ON s.endpoint_id = e.id
        LEFT JOIN cve_findings c ON c.software_instance_id = s.id
        WHERE e.active = 1
        GROUP BY s.id
        ORDER BY s.product, s.version, e.ip_address, e.port
    """).fetchall()
    vulnerability_rows = conn.execute("""
        SELECT DISTINCT c.software_instance_id, c.cve_id, c.severity
        FROM cve_findings c
        JOIN software_instances s ON s.id = c.software_instance_id
        JOIN endpoints e ON e.id = s.endpoint_id
        WHERE e.active = 1
    """).fetchall()
    scan_data['software_vulnerabilities'] = [dict(row) for row in vulnerability_rows]
    infra_score = calcular_infra_score(scan_data)
    recent_raw = conn.execute("SELECT timestamp, ips_ativos, uso, risco_medio, desconhecidos, mac_randomizados FROM scans ORDER BY id DESC LIMIT 10").fetchall()
    recent_scans = [{"timestamp": r["timestamp"], "ips_ativos": r["ips_ativos"], "uso": r["uso"], "risco_medio": r["risco_medio"], "desconhecidos": r["desconhecidos"], "mac_randomizados": r["mac_randomizados"]} for r in recent_raw]
    evolucao_raw = conn.execute("SELECT timestamp, risco_medio, ips_ativos FROM scans ORDER BY id DESC LIMIT 10").fetchall()
    evolucao = [{"timestamp": r["timestamp"], "risco_medio": r["risco_medio"], "ips_ativos": r["ips_ativos"]} for r in evolucao_raw]
    conn.close()
    return render_template("index.html", total_scans=total_scans, latest_scan=latest_scan, devices=devices, software_inventory=software_inventory, tipos_count=tipos_count, infra_score=infra_score, recent_scans=recent_scans, evolucao=evolucao, now=datetime.now(), username=current_user.username)

@app.route('/history')
@login_required
def history():
    conn = get_db()
    scans = conn.execute("""
        SELECT id, timestamp, ips_ativos, uso, risco_medio, 
               desconhecidos, mac_randomizados, recomendacao
        FROM scans
        ORDER BY id DESC
    """).fetchall()
    conn.close()
    return render_template("history.html", scans=scans, username=current_user.username)

if __name__ == "__main__":
    init_users_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
