#!/usr/bin/env python3
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import sys
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from dotenv import load_dotenv
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv(os.path.join(PROJECT_ROOT, ".env"))
APP_ENV = os.getenv("INFRA_ENV", "production").strip().lower()

from core.infra_score import (
    ADMIN_PORTS,
    decompor_infra_score,
    score_minimo_observado,
)
from core.classifier import formatar_hostname, mac_localmente_administrado
import core.persistence as persistence

app = Flask(__name__)
app.secret_key = (
    os.getenv("INFRA_SECRET_KEY")
    or os.getenv("INFRA_DASHBOARD_SECRET_KEY")
    or secrets.token_hex(32)
)

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
    try:
        c = conn.cursor()
        c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)')
        c.execute("SELECT 1 FROM users WHERE username = 'admin'")
        if not c.fetchone() and APP_ENV == "dev":
            password_hash = generate_password_hash("admin123")
            c.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                ("admin", password_hash),
            )
            conn.commit()
            print("✅ Usuário de desenvolvimento criado: admin / admin123")
    finally:
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
    if not isinstance(username, str) or not isinstance(password, str):
        return None
    conn = sqlite3.connect(USERS_DB)
    try:
        c = conn.cursor()
        c.execute(
            "SELECT id, username, password FROM users WHERE username = ?",
            (username,),
        )
        user = c.fetchone()
        if user is None:
            return None

        user_id, stored_username, stored_password = user
        if re.fullmatch(r"[0-9a-fA-F]{64}", stored_password or ""):
            legacy_hash = hashlib.sha256(password.encode()).hexdigest()
            if not hmac.compare_digest(legacy_hash, stored_password.lower()):
                return None
            c.execute(
                "UPDATE users SET password = ? WHERE id = ?",
                (generate_password_hash(password), user_id),
            )
            conn.commit()
        elif not check_password_hash(stored_password, password):
            return None
        return user_id, stored_username
    finally:
        conn.close()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _anexar_software_a_dispositivos(conn, devices):
    devices_by_ip = {device["ip"]: device for device in devices}
    for device in devices:
        device["software"] = []
        device["cve_ids"] = []
        device["cve_statuses"] = []

    rows = conn.execute("""
        SELECT e.ip_address, s.product, s.version, s.cve_status,
               GROUP_CONCAT(DISTINCT c.cve_id) AS cve_ids
        FROM endpoints e
        JOIN software_instances s ON s.endpoint_id = e.id
        LEFT JOIN cve_findings c ON c.software_instance_id = s.id
        WHERE e.active = 1
        GROUP BY s.id
        ORDER BY s.product, s.version
    """).fetchall()

    for row in rows:
        device = devices_by_ip.get(row["ip_address"])
        if device is None:
            continue
        device["software"].append(
            {
                "product": row["product"],
                "version": row["version"],
                "cve_status": row["cve_status"],
            }
        )
        if row["cve_ids"]:
            device["cve_ids"].extend(row["cve_ids"].split(","))
        device["cve_statuses"].append(row["cve_status"])

    for device in devices:
        device["cve_ids"] = sorted(set(device["cve_ids"]))
        device["cve_consultada"] = bool(device["software"]) and all(
            status in {"verified", "verified_cached"}
            for status in device["cve_statuses"]
        )
        device["fabricante_display"] = (
            "MAC local (possível randomização)"
            if mac_localmente_administrado(device.get("mac"))
            else device.get("fabricante") or "Desconhecido"
        )
        device["nome_display"] = formatar_hostname(device.get("nome"))


def _env_ativo(name):
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


def calcular_infra_score(scan_data, scan_metadata=None):
    motivos = []
    metadata = scan_metadata or {}
    scan_services_enabled = bool(
        metadata.get("scan_services", _env_ativo("INFRA_SCAN_SERVICES"))
    )
    cve_lookup_enabled = bool(
        metadata.get("cve_lookup", _env_ativo("INFRA_CVE_LOOKUP"))
    )
    software_devices = [
        device
        for device in scan_data.get("dispositivos", [])
        if device.get("software")
    ]
    cve_coverage_complete = bool(software_devices) and all(
        device.get("cve_consultada") for device in software_devices
    )
    if metadata.get("cve_coverage_complete") is not None:
        cve_coverage_complete = bool(metadata["cve_coverage_complete"])
    classification_observed = metadata.get(
        "classifier_version", "v2"
    ) != "v1"
    components = metadata.get("components") or decompor_infra_score(
        scan_data,
        scan_services=scan_services_enabled,
        cve_lookup=cve_lookup_enabled,
        cve_coverage_complete=cve_coverage_complete,
        classification_observed=classification_observed,
    )["components"]
    observed_components = [
        component for component in components
        if component.get("status") == "observado"
    ]
    observed_by_key = {
        component.get("key"): component for component in observed_components
    }
    observed_keys = set(observed_by_key)
    for device in scan_data.get("dispositivos", []):
        ports = device.get("open_ports", [])
        if isinstance(ports, str):
            try:
                ports = json.loads(ports)
            except (TypeError, ValueError):
                ports = []
        ports = set(ports)
        if "T" in observed_keys and 23 in ports:
            motivos.append(f"Telnet em {device.get('ip')}")
        if "Q" in observed_keys and 554 in ports:
            motivos.append(f"RTSP em {device.get('ip')}")
        if "A" in observed_keys and ports & ADMIN_PORTS:
            motivos.append(f"Porta administrativa em {device.get('ip')}")
        if "H" in observed_keys and 80 in ports and 443 not in ports and str(
            device.get("tipo", "")
        ).lower() in {"gateway", "roteador", "router"}:
            motivos.append(f"HTTP sem HTTPS no gateway {device.get('ip')}")
    if "U" in observed_keys and observed_by_key["U"].get("value"):
        motivos.append(
            f"{scan_data.get('desconhecidos', 0)}/"
            f"{scan_data.get('ips_ativos', 0)} desconhecidos"
        )
    software_risk = observed_by_key.get("S", {}).get("value", 0)
    if "S" in observed_keys and software_risk:
        motivos.append(f"CVEs conhecidas em software exposto (+{software_risk})")
    score = score_minimo_observado(components)
    coverage_complete = len(observed_components) == len(components)
    if not scan_services_enabled or not coverage_complete:
        status, cor = "⚠️ Cobertura parcial", "warning"
        if not scan_services_enabled:
            motivos.append(
                "Detecção de serviços desativada: portas e software não foram verificados."
            )
        if scan_services_enabled and not cve_lookup_enabled:
            motivos.append(
                "Consulta ao NVD desativada: CVEs não foram consultadas."
            )
        elif scan_services_enabled and not cve_coverage_complete:
            motivos.append(
                "Não há consulta CVE verificada para todo o software identificado; "
                "componentes sem verificação não entram no score."
            )
        if score is None:
            motivos.append("Dados observados insuficientes para calcular o score.")
    elif not cve_lookup_enabled:
        status, cor = "⚠️ Cobertura parcial", "warning"
        motivos.append(
            "Consulta ao NVD desativada: serviços foram verificados, mas CVEs não foram consultadas."
        )
    elif score <= 2:
        status, cor = "✅ Saudável", "success"
    elif score <= 5:
        status, cor = "⚠️ Atenção", "warning"
    else:
        status, cor = "🔴 Risco Elevado", "danger"
    return {
        "score": score,
        "status": status,
        "cor": cor,
        "motivos": motivos,
        "componentes": components,
        "cobertura_completa": coverage_complete,
    }

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
    eventos = persistence.obter_eventos_recentes(limite=10, db_path=DB_PATH)
    total_scans = conn.execute("SELECT COUNT(*) as count FROM scans").fetchone()["count"]
    latest_scan = conn.execute(
        "SELECT * FROM scans ORDER BY id DESC LIMIT 1"
    ).fetchone()
    if not latest_scan:
        latest_scan = {
            'id': 0, 'timestamp': datetime.now().isoformat(),
            'ambiente': 'N/A', 'ips_ativos': 0, 'uso': 0,
            'risco_medio': 0, 'desconhecidos': 0,
            'mac_randomizados': 0, 'recomendacao': 'Nenhum scan',
            'modo': 'rapido', 'scan_services': 0, 'cve_lookup': 0,
            'snmp_enabled': 0,
            'classifier_version': 'v1',
            'formula_version': 'normalizada-7-v1',
            'duracao_s': None, 'componentes_json': None,
        }
    else:
        latest_scan = dict(latest_scan)
    try:
        scan_snapshot = json.loads(latest_scan.get("data_json") or "{}")
    except (TypeError, ValueError):
        scan_snapshot = {}
    snmp_devices = {
        device.get("ip"): device.get("snmp_info")
        for device in scan_snapshot.get("dispositivos", [])
        if isinstance(device, dict) and device.get("snmp_info")
    }
    devices = []
    new_devices = []
    has_previous_scan = False
    tipos_count = {}
    scan_services_enabled = bool(latest_scan.get("scan_services", False))
    cve_lookup_enabled = bool(latest_scan.get("cve_lookup", False))
    if latest_scan['id'] > 0:
        previous_scan = conn.execute(
            "SELECT id FROM scans WHERE id < ? ORDER BY id DESC LIMIT 1",
            (latest_scan['id'],),
        ).fetchone()
        has_previous_scan = previous_scan is not None
        previous_macs = set()
        if previous_scan:
            previous_macs = {
                str(row["mac"]).strip().casefold()
                for row in conn.execute(
                    "SELECT mac FROM dispositivos "
                    "WHERE scan_id = ? AND mac IS NOT NULL AND TRIM(mac) != ''",
                    (previous_scan["id"],),
                ).fetchall()
            }
        devices = [
            dict(row)
            for row in conn.execute(
                "SELECT ip, nome, mac, fabricante, tipo, risk_score, severity, "
                "open_ports, classificacao_evidencia, classificacao_confianca "
                "FROM dispositivos WHERE scan_id = ? ORDER BY risk_score DESC",
                (latest_scan['id'],),
            ).fetchall()
        ]
        for device in devices:
            device["snmp_info"] = snmp_devices.get(device["ip"])
            try:
                device["classificacao_evidencia"] = json.loads(
                    device.get("classificacao_evidencia") or "[]"
                )
            except (TypeError, ValueError):
                device["classificacao_evidencia"] = []
            if not device["classificacao_evidencia"]:
                device["classificacao_evidencia"] = [
                    "Evidência não registrada (scan legado)"
                ]
            mac = str(device.get("mac") or "").strip().casefold()
            if mac and mac not in previous_macs:
                    new_devices.append(device)
        _anexar_software_a_dispositivos(conn, devices)
        for d in devices:
            t = d['tipo']
            tipos_count[t] = tipos_count.get(t, 0) + 1
    scan_data = {'dispositivos': [dict(d) for d in devices], 'ips_ativos': latest_scan.get('ips_ativos', 0), 'desconhecidos': latest_scan.get('desconhecidos', 0)}
    vulnerability_rows = conn.execute("""
        SELECT DISTINCT c.software_instance_id, c.cve_id, c.severity
        FROM cve_findings c
        JOIN software_instances s ON s.id = c.software_instance_id
        JOIN endpoints e ON e.id = s.endpoint_id
        WHERE e.active = 1
    """).fetchall()
    scan_data['software_vulnerabilities'] = [dict(row) for row in vulnerability_rows]
    try:
        saved_components = json.loads(
            latest_scan.get("componentes_json") or "[]"
        )
    except (TypeError, ValueError):
        saved_components = []
    scan_metadata = {
        "scan_services": scan_services_enabled,
        "cve_lookup": cve_lookup_enabled,
        "classifier_version": latest_scan.get("classifier_version", "v1"),
        "formula_version": latest_scan.get(
            "formula_version", "normalizada-7-v1"
        ),
        "components": saved_components,
        "cve_coverage_complete": None,
    }
    scan_metadata["cve_coverage_complete"] = scan_snapshot.get(
        "cve_coverage_complete", False
    )
    infra_score = calcular_infra_score(scan_data, scan_metadata)
    recent_raw = conn.execute("SELECT timestamp, ips_ativos, uso, risco_medio, desconhecidos, mac_randomizados FROM scans ORDER BY id DESC LIMIT 10").fetchall()
    recent_scans = [{"timestamp": r["timestamp"], "ips_ativos": r["ips_ativos"], "uso": r["uso"], "risco_medio": r["risco_medio"], "desconhecidos": r["desconhecidos"], "mac_randomizados": r["mac_randomizados"]} for r in recent_raw]
    evolucao_raw = conn.execute(
        "SELECT timestamp, risco_medio, ips_ativos, modo "
        "FROM scans ORDER BY id DESC LIMIT 10"
    ).fetchall()
    evolucao = [
        {
            "timestamp": r["timestamp"], "risco_medio": r["risco_medio"],
            "ips_ativos": r["ips_ativos"], "modo": r["modo"],
        }
        for r in evolucao_raw
    ]
    conn.close()
    return render_template(
        "index.html", total_scans=total_scans, latest_scan=latest_scan,
        devices=devices, tipos_count=tipos_count, infra_score=infra_score,
        recent_scans=recent_scans, evolucao=evolucao,
        eventos=eventos,
        new_devices=new_devices, has_previous_scan=has_previous_scan,
        scan_services_enabled=scan_services_enabled,
        cve_lookup_enabled=cve_lookup_enabled, now=datetime.now(),
        username=current_user.username,
    )


@app.route('/api/eventos')
@login_required
def api_eventos():
    raw_limit = request.args.get("limite", "50")
    try:
        limit = int(raw_limit)
    except ValueError:
        return jsonify({"error": "O parâmetro limite deve ser um inteiro entre 1 e 200."}), 400
    if not 1 <= limit <= 200:
        return jsonify({"error": "O parâmetro limite deve estar entre 1 e 200."}), 400

    events = persistence.obter_eventos_recentes(
        limite=limit,
        rede=request.args.get("rede") or None,
        db_path=DB_PATH,
    )
    return jsonify(events)


@app.route('/history')
@login_required
def history():
    conn = get_db()
    scans = conn.execute("""
        SELECT id, timestamp, ips_ativos, uso, risco_medio,
               desconhecidos, mac_randomizados, recomendacao, modo,
               classifier_version, formula_version, scan_services, cve_lookup,
               snmp_enabled
        FROM scans
        ORDER BY id DESC
    """).fetchall()
    conn.close()
    return render_template("history.html", scans=scans, username=current_user.username)

if __name__ == "__main__":
    init_users_db()
    app.run(debug=APP_ENV == "dev", host='0.0.0.0', port=5000)
