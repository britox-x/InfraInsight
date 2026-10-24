import sqlite3

import pytest

import core.persistence as persistence


def _save_scan(devices, timestamp, network="192.0.2.0/24", complete=True):
    return persistence.salvar_scan({
        "timestamp": timestamp,
        "rede": network,
        "presence_scan_complete": complete,
        "dispositivos": devices,
    })


def _device(ip, mac, hostname):
    return {"ip": ip, "mac": mac, "hostname": hostname}


def test_eventos_de_entrada_e_saida_aguardam_dois_scans_ausentes(
    monkeypatch, tmp_path
):
    db_path = tmp_path / "presence.db"
    monkeypatch.setattr(persistence, "DB_NAME", str(db_path))

    device_a = _device("192.0.2.10", "00:11:22:33:44:55", "host-a")
    device_b = _device("192.0.2.11", "00:11:22:33:44:66", "host-b")
    _save_scan([device_a], "2026-01-01T12:00:00")
    _save_scan(
        [device_a, device_b],
        "2026-01-01T12:05:00",
    )
    _save_scan([device_b], "2026-01-01T12:10:00")

    with sqlite3.connect(db_path) as conn:
        events_after_first_miss = conn.execute(
            "SELECT event, device_name FROM device_events ORDER BY id"
        ).fetchall()

    assert events_after_first_miss == [("ENTROU", "host-b")]

    _save_scan([device_b], "2026-01-01T12:15:00")

    with sqlite3.connect(db_path) as conn:
        events = conn.execute(
            "SELECT event, device_name, timestamp, source "
            "FROM device_events ORDER BY id"
        ).fetchall()

    assert events == [
        ("ENTROU", "host-b", "2026-01-01T12:05:00", "SCAN"),
        ("SAIU", "host-a", "2026-01-01T12:15:00", "SCAN"),
    ]


def test_mac_estavel_e_retorno_antes_do_segundo_scan_nao_criam_eventos(
    monkeypatch, tmp_path
):
    db_path = tmp_path / "presence-return.db"
    monkeypatch.setattr(persistence, "DB_NAME", str(db_path))

    _save_scan(
        [_device("192.0.2.10", "00:11:22:33:44:55", "host-a")],
        "2026-01-01T12:00:00",
    )
    _save_scan([], "2026-01-01T12:05:00")
    _save_scan(
        [_device("192.0.2.20", "00:11:22:33:44:55", "host-a")],
        "2026-01-01T12:10:00",
    )

    with sqlite3.connect(db_path) as conn:
        events = conn.execute("SELECT event FROM device_events").fetchall()
        presence = conn.execute(
            "SELECT ip_address, missed_scans, is_present FROM device_presence"
        ).fetchall()

    assert events == []
    assert presence == [("192.0.2.20", 0, 1)]


def test_primeiro_scan_vazio_inicializa_baseline_e_scan_incompleto_e_ignorado(
    monkeypatch, tmp_path
):
    db_path = tmp_path / "presence-baseline.db"
    monkeypatch.setattr(persistence, "DB_NAME", str(db_path))

    _save_scan([], "2026-01-01T12:00:00")
    _save_scan(
        [_device("192.0.2.10", "00:11:22:33:44:55", "host-a")],
        "2026-01-01T12:05:00",
        complete=False,
    )
    _save_scan(
        [_device("192.0.2.10", "00:11:22:33:44:55", "host-a")],
        "2026-01-01T12:10:00",
    )

    with sqlite3.connect(db_path) as conn:
        events = conn.execute("SELECT event FROM device_events").fetchall()
        network_state = conn.execute(
            "SELECT initialized_at, last_scan_at "
            "FROM device_presence_networks"
        ).fetchall()

    assert events == [("ENTROU",)]
    assert network_state == [
        ("2026-01-01T12:00:00", "2026-01-01T12:10:00")
    ]


def test_scan_incompleto_nao_conta_como_ausencia(monkeypatch, tmp_path):
    db_path = tmp_path / "presence-incomplete.db"
    monkeypatch.setattr(persistence, "DB_NAME", str(db_path))

    device = _device("192.0.2.10", "00:11:22:33:44:55", "host-a")
    _save_scan([device], "2026-01-01T12:00:00")
    _save_scan([], "2026-01-01T12:05:00")
    _save_scan([], "2026-01-01T12:10:00", complete=False)
    _save_scan([], "2026-01-01T12:15:00")

    with sqlite3.connect(db_path) as conn:
        events = conn.execute(
            "SELECT event, timestamp FROM device_events"
        ).fetchall()
        presence = conn.execute(
            "SELECT missed_scans, is_present FROM device_presence"
        ).fetchall()

    assert events == [("SAIU", "2026-01-01T12:15:00")]
    assert presence == [(2, 0)]


def test_consulta_eventos_recentes_filtra_por_rede_e_valida_limite(
    monkeypatch, tmp_path
):
    db_path = tmp_path / "presence-query.db"
    monkeypatch.setattr(persistence, "DB_NAME", str(db_path))

    device_a = _device("192.0.2.10", "00:11:22:33:44:55", "host-a")
    device_b = _device("198.51.100.10", "00:11:22:33:44:66", "host-b")
    _save_scan([device_a], "2026-01-01T12:00:00")
    _save_scan(
        [device_a, _device("192.0.2.11", "00:11:22:33:44:77", "host-c")],
        "2026-01-01T12:05:00",
    )
    _save_scan(
        [device_b],
        "2026-01-01T12:06:00",
        network="198.51.100.0/24",
    )
    _save_scan(
        [device_b, _device("198.51.100.11", "00:11:22:33:44:88", "host-d")],
        "2026-01-01T12:10:00",
        network="198.51.100.0/24",
    )

    events = persistence.obter_eventos_recentes(
        limite=1,
        rede="192.0.2.0/24",
        db_path=str(db_path),
    )

    assert len(events) == 1
    assert events[0]["device_name"] == "host-c"
    assert events[0]["rede"] == "192.0.2.0/24"
    assert events[0]["source"] == "SCAN"
    with pytest.raises(ValueError, match="entre 1 e 200"):
        persistence.obter_eventos_recentes(limite=201, db_path=str(db_path))


def test_eventos_e_consulta_mantem_flag_de_mac_local(monkeypatch, tmp_path):
    db_path = tmp_path / "presence-randomized.db"
    monkeypatch.setattr(persistence, "DB_NAME", str(db_path))

    _save_scan(
        [_device("192.0.2.10", "00:11:22:33:44:55", "baseline")],
        "2026-01-01T12:00:00",
    )
    _save_scan(
        [
            _device("192.0.2.10", "00:11:22:33:44:55", "baseline"),
            _device("192.0.2.20", "d2:4f:00:11:22:33", ""),
        ],
        "2026-01-01T12:05:00",
    )
    _save_scan([], "2026-01-01T12:10:00")
    _save_scan([], "2026-01-01T12:15:00")
    events = persistence.obter_eventos_recentes(db_path=str(db_path))

    randomized_events = [
        event for event in events
        if event["mac_address"] == "d2:4f:00:11:22:33"
    ]
    assert {event["event"] for event in randomized_events} == {"ENTROU", "SAIU"}
    assert all(event["mac_randomizado"] == 1 for event in randomized_events)
    assert next(
        event for event in randomized_events if event["event"] == "ENTROU"
    )["device_name"] is None


def test_migracao_marca_eventos_legados_com_mac_local(monkeypatch, tmp_path):
    db_path = tmp_path / "presence-legacy.db"
    monkeypatch.setattr(persistence, "DB_NAME", str(db_path))
    _save_scan(
        [_device("192.0.2.10", "00:11:22:33:44:55", "baseline")],
        "2026-01-01T12:00:00",
    )
    _save_scan(
        [
            _device("192.0.2.10", "00:11:22:33:44:55", "baseline"),
            _device("192.0.2.20", "02:4f:00:11:22:33", "randomized"),
        ],
        "2026-01-01T12:05:00",
    )

    with sqlite3.connect(db_path) as conn:
        conn.execute("ALTER TABLE device_events DROP COLUMN mac_randomizado")

    persistence.iniciar_banco()
    events = persistence.obter_eventos_recentes(db_path=str(db_path))

    assert events[0]["mac_randomizado"] == 1
