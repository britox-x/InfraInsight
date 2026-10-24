import pytest
import sqlite3
import hashlib
import re
from werkzeug.security import check_password_hash

import dashboard.app as dashboard
import core.persistence as persistence
from dashboard.app import (
    _anexar_software_a_dispositivos,
    calcular_infra_score,
    mac_localmente_administrado,
)


def test_calcular_infra_score_retorna_score_e_motivos(monkeypatch):
    monkeypatch.setenv("INFRA_SCAN_SERVICES", "true")
    monkeypatch.setenv("INFRA_CVE_LOOKUP", "true")
    resultado = calcular_infra_score(
        {
            "dispositivos": [
                {
                    "ip": "192.168.1.10",
                    "open_ports": [23],
                    "software": [{"product": "OpenSSH"}],
                    "cve_consultada": True,
                },
            ],
        }
    )

    assert resultado["score"] == pytest.approx(20 / 7)
    assert resultado["status"] == "⚠️ Atenção"
    assert "Telnet em 192.168.1.10" in resultado["motivos"]


def test_software_e_cves_sao_agregados_ao_dispositivo_por_ip():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE endpoints (id TEXT, ip_address TEXT, active INTEGER);
        CREATE TABLE software_instances (
            id TEXT, endpoint_id TEXT, product TEXT, version TEXT,
            cve_status TEXT
        );
        CREATE TABLE cve_findings (software_instance_id TEXT, cve_id TEXT);
        INSERT INTO endpoints VALUES ('endpoint-1', '192.168.1.10', 1);
        INSERT INTO endpoints VALUES ('endpoint-2', '192.168.1.20', 1);
        INSERT INTO software_instances VALUES ('software-1', 'endpoint-1', 'nginx', '1.24', 'verified');
        INSERT INTO software_instances VALUES ('software-2', 'endpoint-2', 'OpenSSH', '9.0', 'unavailable');
        INSERT INTO cve_findings VALUES ('software-1', 'CVE-2024-12345');
    """)
    devices = [
        {"ip": "192.168.1.10"},
        {"ip": "192.168.1.20"},
        {"ip": "192.168.1.30"},
    ]

    _anexar_software_a_dispositivos(conn, devices)

    assert devices[0]["software"] == [
        {"product": "nginx", "version": "1.24", "cve_status": "verified"}
    ]
    assert devices[0]["cve_ids"] == ["CVE-2024-12345"]
    assert devices[1]["software"] == [
        {"product": "OpenSSH", "version": "9.0", "cve_status": "unavailable"}
    ]
    assert devices[1]["cve_ids"] == []
    assert devices[2]["software"] == []
    assert devices[2]["cve_ids"] == []
    conn.close()


def test_infrascore_sinaliza_cobertura_parcial(monkeypatch):
    monkeypatch.setenv("INFRA_SCAN_SERVICES", "false")
    monkeypatch.setenv("INFRA_CVE_LOOKUP", "false")

    resultado = calcular_infra_score({"dispositivos": []})

    assert resultado["status"] == "⚠️ Cobertura parcial"
    assert any("não foram verificados" in motivo for motivo in resultado["motivos"])


def test_infrascore_sinaliza_nvd_desativado(monkeypatch):
    monkeypatch.setenv("INFRA_SCAN_SERVICES", "true")
    monkeypatch.setenv("INFRA_CVE_LOOKUP", "false")

    resultado = calcular_infra_score({"dispositivos": []})

    assert resultado["status"] == "⚠️ Cobertura parcial"
    assert any("NVD desativada" in motivo for motivo in resultado["motivos"])


def test_infrascore_nao_marca_saude_sem_consulta_cve_verificada(monkeypatch):
    monkeypatch.setenv("INFRA_SCAN_SERVICES", "true")
    monkeypatch.setenv("INFRA_CVE_LOOKUP", "true")

    resultado = calcular_infra_score(
        {
            "dispositivos": [
                {
                    "software": [{"product": "OpenSSH"}],
                    "cve_consultada": False,
                }
            ]
        }
    )

    assert resultado["status"] == "⚠️ Cobertura parcial"
    assert any("consulta CVE verificada" in motivo for motivo in resultado["motivos"])


@pytest.mark.parametrize(
    ("mac", "expected"),
    [
        ("02:11:22:33:44:55", True),
        ("00:11:22:33:44:55", False),
        ("invalid", False),
        (None, False),
    ],
)
def test_mac_localmente_administrado(mac, expected):
    assert mac_localmente_administrado(mac) is expected


def test_login_migra_hash_sha256_legado(monkeypatch, tmp_path):
    users_db = tmp_path / "users.db"
    conn = sqlite3.connect(users_db)
    conn.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)"
    )
    legacy_hash = hashlib.sha256(b"admin123").hexdigest()
    conn.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        ("admin", legacy_hash),
    )
    conn.commit()
    conn.close()
    monkeypatch.setattr(dashboard, "USERS_DB", str(users_db))

    assert dashboard.verificar_login("admin", "wrong-password") is None
    assert dashboard.verificar_login("admin", "admin123") == (1, "admin")

    conn = sqlite3.connect(users_db)
    stored_hash = conn.execute(
        "SELECT password FROM users WHERE username = 'admin'"
    ).fetchone()[0]
    conn.close()
    assert stored_hash != legacy_hash
    assert check_password_hash(stored_hash, "admin123")


@pytest.mark.parametrize(
    ("classifier_version", "unknown_display"),
    [("v2-conservador", b"1 / 1"), ("v1", b"N/D")],
)
def test_dashboard_exibe_contexto_e_componentes_salvos(
    monkeypatch, tmp_path, classifier_version, unknown_display
):
    from core.infra_score import decompor_infra_score

    db_path = tmp_path / "dashboard.db"
    monkeypatch.setattr(dashboard, "DB_PATH", str(db_path))
    monkeypatch.setattr(persistence, "DB_NAME", str(db_path))
    monkeypatch.setattr(
        dashboard.login_manager,
        "_user_callback",
        lambda user_id: dashboard.User(user_id, "tester"),
    )
    persistence.init_database()
    scan = {
        "ips_ativos": 1,
        "desconhecidos": 1,
        "scan_services": False,
        "cve_lookup": False,
        "snmp_enabled": True,
        "classifier_version": classifier_version,
        "formula_version": "normalizada-7-v1",
        "cve_coverage_complete": False,
        "dispositivos": [{
            "ip": "192.0.2.10",
            "tipo": "desconhecido",
            "open_ports": [],
            "services": [],
            "snmp_info": {
                "object_id": "1.3.6.1.4.1.9.1",
                "description": "Cisco Router",
                "location": "Lab",
            },
        }],
    }
    scan["componentes"] = decompor_infra_score(
        scan,
        scan_services=False,
        cve_lookup=False,
        cve_coverage_complete=False,
        classification_observed=classifier_version != "v1",
    )["components"]
    persistence.salvar_scan(scan)

    client = dashboard.app.test_client()
    with client.session_transaction() as session:
        session["_user_id"] = "1"
        session["_fresh"] = True
    response = client.get("/")

    assert response.status_code == 200
    assert b"Descoberta r\xc3\xa1pida (ARP)" in response.data
    assert b"+ SNMP" in response.data
    assert b"Cisco Router" in response.data
    assert b"INFRA SCORE OBSERVADO (M\xc3\x8dNIMO)" in response.data
    assert b"U \xc2\xb7 Dispositivos desconhecidos" in response.data
    if classifier_version != "v1":
        assert b"1,4/10" in response.data
    assert b"Evid\xc3\xaancias observadas" in response.data
    assert b"Nenhuma movimenta\xc3\xa7\xc3\xa3o registrada ainda." in response.data
    assert re.search(
        rb"Desconhecidos</h3>\s*<div class=\"value\">\s*"
        + re.escape(unknown_display)
        + rb"\s*</div>",
        response.data,
    )
    assert b"N\xc3\xa3o verificado neste scan" in response.data


def test_dashboard_compara_macs_com_scan_imediatamente_anterior(
    monkeypatch, tmp_path
):
    db_path = tmp_path / "new-devices.db"
    monkeypatch.setattr(dashboard, "DB_PATH", str(db_path))
    monkeypatch.setattr(persistence, "DB_NAME", str(db_path))
    monkeypatch.setattr(
        dashboard.login_manager,
        "_user_callback",
        lambda user_id: dashboard.User(user_id, "tester"),
    )
    persistence.init_database()
    persistence.salvar_scan({
        "dispositivos": [
            {"ip": "192.0.2.10", "mac": "AA:BB:CC:DD:EE:01"},
            {"ip": "192.0.2.11", "mac": ""},
        ],
    })
    persistence.salvar_scan({
        "dispositivos": [
            {"ip": "192.0.2.20", "mac": "aa:bb:cc:dd:ee:01"},
            {
                "ip": "192.0.2.21",
                "mac": "AA:BB:CC:DD:EE:02",
                "hostname": "novo-host",
            },
            {"ip": "192.0.2.22", "mac": ""},
        ],
    })

    client = dashboard.app.test_client()
    with client.session_transaction() as session:
        session["_user_id"] = "1"
        session["_fresh"] = True
    response = client.get("/")

    assert response.status_code == 200
    assert b"Poss\xc3\xadveis novos dispositivos" in response.data
    assert b"192.0.2.21" in response.data
    assert b"AA:BB:CC:DD:EE:02" in response.data
    assert re.search(
        rb"Poss\xc3\xadveis novos dispositivos</h3>\s*"
        rb"<div class=\"value\">1</div>",
        response.data,
    )
    assert b"MACs randomizados podem aparecer como novos" in response.data


def test_dashboard_exibe_timeline_e_api_de_eventos_requer_login(
    monkeypatch, tmp_path
):
    db_path = tmp_path / "dashboard-events.db"
    monkeypatch.setattr(dashboard, "DB_PATH", str(db_path))
    monkeypatch.setattr(persistence, "DB_NAME", str(db_path))
    monkeypatch.setattr(
        dashboard.login_manager,
        "_user_callback",
        lambda user_id: dashboard.User(user_id, "tester"),
    )
    persistence.init_database()
    device_a = {
        "ip": "192.0.2.10",
        "mac": "00:11:22:33:44:55",
        "hostname": "baseline-host",
    }
    device_b = {
        "ip": "192.0.2.11",
        "mac": "00:11:22:33:44:66",
        "hostname": "<script>alert(1)</script>",
    }
    device_c = {
        "ip": "192.0.2.12",
        "mac": "02:11:22:33:44:77",
        "hostname": "",
    }
    persistence.salvar_scan({
        "timestamp": "2026-01-01T12:00:00",
        "rede": "192.0.2.0/24",
        "presence_scan_complete": True,
        "dispositivos": [device_a],
    })
    persistence.salvar_scan({
        "timestamp": "2026-01-01T12:05:00",
        "rede": "192.0.2.0/24",
        "presence_scan_complete": True,
        "dispositivos": [device_a, device_b],
    })
    persistence.salvar_scan({
        "timestamp": "2026-01-01T12:10:00",
        "rede": "192.0.2.0/24",
        "presence_scan_complete": True,
        "dispositivos": [device_a, device_b, device_c],
    })

    client = dashboard.app.test_client()
    assert client.get("/api/eventos").status_code == 302
    with client.session_transaction() as session:
        session["_user_id"] = "1"
        session["_fresh"] = True

    api_response = client.get("/api/eventos?limite=2&rede=192.0.2.0/24")
    dashboard_response = client.get("/")
    invalid_limit = client.get("/api/eventos?limite=201")

    assert api_response.status_code == 200
    assert api_response.get_json()[0]["device_name"] is None
    assert api_response.get_json()[0]["mac_randomizado"] == 1
    assert api_response.get_json()[1]["device_name"] == device_b["hostname"]
    assert api_response.get_json()[0]["rede"] == "192.0.2.0/24"
    assert dashboard_response.status_code == 200
    assert b"Movimenta\xc3\xa7\xc3\xa3o recente" in dashboard_response.data
    assert device_c["mac"].encode() in dashboard_response.data
    assert b"&lt;script&gt;alert(1)&lt;/script&gt;" in dashboard_response.data
    assert b"<script>alert(1)</script>" not in dashboard_response.data
    assert b"poss\xc3\xadvel randomiza\xc3\xa7\xc3\xa3o" in dashboard_response.data
    assert invalid_limit.status_code == 400
    assert invalid_limit.get_json()["error"]


@pytest.mark.parametrize(
    ("environment", "should_create_admin"),
    [("dev", True), ("production", False)],
)
def test_admin_padrao_so_e_criado_em_dev(
    monkeypatch, tmp_path, environment, should_create_admin
):
    users_db = tmp_path / "users.db"
    monkeypatch.setattr(dashboard, "USERS_DB", str(users_db))
    monkeypatch.setattr(dashboard, "APP_ENV", environment)

    dashboard.init_users_db()

    conn = sqlite3.connect(users_db)
    user = conn.execute(
        "SELECT username, password FROM users WHERE username = 'admin'"
    ).fetchone()
    conn.close()
    assert (user is not None) is should_create_admin
    if user:
        assert check_password_hash(user[1], "admin123")
