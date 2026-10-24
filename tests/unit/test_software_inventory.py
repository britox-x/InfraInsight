import csv
import json
import logging
import sqlite3

import pytest
import requests

from core.cve_client import NvdClient, enriquecer_servicos_com_cves
from core.exporter import exportar_software_csv
from core.fingerprint.cpe_mapper import mapear_cpe
from core.fingerprint.nmap_parser import parsear_servicos_nmap
from core.infra_score import calcular_infra_score, decompor_infra_score
import core.persistence as persistence


def test_nmap_parser_normalizes_open_services_and_cpe():
    host = {
        "tcp": {
            443: {
                "state": "open",
                "name": "https",
                "product": "nginx",
                "version": "1.24.0",
                "conf": "10",
            },
            80: {
                "state": "closed",
                "product": "Apache httpd",
                "version": "2.4",
            },
        },
        "udp": {
            161: {
                "state": "open",
                "name": "snmp",
                "product": "Unknown Service",
                "version": "1",
                "cpe": "cpe:/a:example:snmpd:1",
                "conf": "101",
            }
        },
    }

    services = parsear_servicos_nmap(host)

    assert [service["port"] for service in services] == [443, 161]
    assert services[0]["cpe"] == "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"
    assert services[0]["cpe_source"] == "inferred"
    assert services[0]["confidence"] == 100
    assert services[1]["cpe"] == "cpe:/a:example:snmpd:1"
    assert services[1]["cpe_source"] == "nmap"
    assert services[1]["confidence"] is None


def test_cpe_mapper_does_not_guess_unknown_products_or_versions():
    assert mapear_cpe("OpenSSH", "9.6p1") == (
        "cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*"
    )
    assert mapear_cpe("unknown daemon", "1.2") is None
    assert mapear_cpe("nginx", "version unknown") is None


def test_nvd_client_parses_cvss_sends_key_and_caches(tmp_path):
    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "totalResults": 1,
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2024-12345",
                            "descriptions": [
                                {"lang": "en", "value": "Example issue"}
                            ],
                            "metrics": {
                                "cvssMetricV31": [
                                    {
                                        "cvssData": {
                                            "baseSeverity": "HIGH",
                                            "baseScore": 8.1,
                                        }
                                    }
                                ]
                            },
                        }
                    }
                ],
            }

    class Session:
        def __init__(self):
            self.calls = []

        def get(self, url, **kwargs):
            self.calls.append((url, kwargs))
            return Response()

    session = Session()
    client = NvdClient(
        api_key="test-key", session=session, db_path=str(tmp_path / "cve.db")
    )
    results = client.buscar_por_cpe(
        "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"
    )
    cached_results, cache_status = client.consultar_por_cpe(
        "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"
    )

    assert results == [
        {
            "cve_id": "CVE-2024-12345",
            "severity": "HIGH",
            "cvss_score": 8.1,
            "description": "Example issue",
        }
    ]
    assert session.calls[0][1]["headers"] == {"apiKey": "test-key"}
    assert session.calls[0][1]["params"]["cpeName"].startswith("cpe:2.3:")
    assert len(session.calls) == 1
    assert cached_results == results
    assert cache_status == "verified_cached"


def test_cache_evita_chamada_http_na_segunda_consulta(tmp_path):
    class Session:
        def __init__(self):
            self.calls = 0

        def get(self, url, **kwargs):
            self.calls += 1

            class Response:
                def raise_for_status(self):
                    return None

                def json(self):
                    return {"totalResults": 0, "vulnerabilities": []}

            return Response()

    session = Session()
    client = NvdClient(
        session=session, db_path=str(tmp_path / "cache-integration.db")
    )
    cpe = "cpe:/a:nginx:1.18.0"

    first_results = client.buscar_por_cpe(cpe)
    second_results = client.buscar_por_cpe(cpe)

    assert first_results == second_results == []
    assert session.calls == 1


def test_cve_enrichment_queries_each_cpe_once():
    class Client:
        min_confidence = 70

        def __init__(self):
            self.calls = []

        def consultar_por_cpe(self, cpe):
            self.calls.append(cpe)
            return (
                [{"cve_id": "CVE-2024-12345", "severity": "HIGH"}],
                "verified",
            )

    client = Client()
    services = [
        {
            "product": "nginx",
            "cpe": "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*",
            "cpe_source": "nmap",
            "confidence": 45,
        },
        {
            "product": "nginx",
            "cpe": "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*",
            "cpe_source": "nmap",
            "confidence": 45,
        },
    ]

    enriched = enriquecer_servicos_com_cves(services, client)

    assert len(client.calls) == 1
    assert all(
        item["cves"][0]["cve_id"] == "CVE-2024-12345" for item in enriched
    )
    assert all(item["cve_status"] == "verified" for item in enriched)


def test_cve_lookup_skips_low_confidence_inferred_but_queries_nmap_cpe(
    tmp_path,
):
    class Session:
        def __init__(self):
            self.calls = []

        def get(self, url, **kwargs):
            self.calls.append(kwargs)

            class Response:
                def raise_for_status(self):
                    return None

                def json(self):
                    return {"totalResults": 0, "vulnerabilities": []}

            return Response()

    session = Session()
    client = NvdClient(session=session, db_path=str(tmp_path / "threshold.db"))
    cpe = "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"
    services = [
        {
            "cpe": cpe,
            "cpe_source": "inferred",
            "confidence": 45,
        },
        {
            "cpe": cpe,
            "cpe_source": "nmap",
            "confidence": 45,
        },
    ]

    enriched = enriquecer_servicos_com_cves(services, client)

    assert len(session.calls) == 1
    assert enriched[0]["cve_status"] == "skipped_low_confidence"
    assert enriched[1]["cve_status"] == "verified"


def test_nvd_429_uses_expired_cache(tmp_path, caplog):
    class RateLimitedSession:
        def __init__(self):
            self.calls = 0

        def get(self, url, **kwargs):
            self.calls += 1
            response = requests.Response()
            response.status_code = 429
            raise requests.HTTPError("429 rate limit", response=response)

    session = RateLimitedSession()
    client = NvdClient(
        session=session,
        db_path=str(tmp_path / "expired.db"),
        ttl_hours=48,
    )
    cpe = "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"
    payload = {
        "totalResults": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-12345",
                    "metrics": {},
                    "descriptions": [],
                }
            }
        ],
    }
    client._write_cache(cpe, payload)
    with sqlite3.connect(client.db_path) as conn:
        conn.execute(
            "UPDATE cve_cache SET expires_at = ? WHERE cpe = ?",
            ("2000-01-01T00:00:00+00:00", cpe),
        )
        expiration_before = conn.execute(
            "SELECT expires_at FROM cve_cache WHERE cpe = ?", (cpe,)
        ).fetchone()[0]

    with caplog.at_level(logging.WARNING, logger="core.cve_client"):
        results, status = client.consultar_por_cpe(cpe)
        second_results, second_status = client.consultar_por_cpe(cpe)
    with sqlite3.connect(client.db_path) as conn:
        expiration_after = conn.execute(
            "SELECT expires_at FROM cve_cache WHERE cpe = ?", (cpe,)
        ).fetchone()[0]

    assert status == "verified_stale_cache"
    assert results[0]["cve_id"] == "CVE-2024-12345"
    assert second_status == "verified_stale_cache"
    assert second_results == results
    assert session.calls == 2
    assert expiration_after == expiration_before
    assert "cache expirado" in caplog.text


def test_nvd_failure_without_cache_is_recorded_and_does_not_abort(tmp_path):
    class FailingSession:
        def get(self, url, **kwargs):
            raise requests.Timeout("timeout")

    client = NvdClient(
        session=FailingSession(), db_path=str(tmp_path / "unavailable.db")
    )
    result = enriquecer_servicos_com_cves(
        [
            {
                "cpe": "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*",
                "cpe_source": "nmap",
                "confidence": 45,
            }
        ],
        client,
    )

    assert result[0]["cve_status"] == "unavailable"
    assert result[0]["cves"] == []
    assert "Timeout" in result[0]["cve_status_reason"]


def test_infra_score_adds_unique_cve_severity_weights():
    scan_data = {
        "dispositivos": [
            {
                "open_ports": [23],
                "services": [
                    {
                        "cves": [
                            {"cve_id": "CVE-2024-1", "severity": "CRITICAL"},
                            {"cve_id": "CVE-2024-2", "severity": "HIGH"},
                            {"cve_id": "CVE-2024-1", "severity": "CRITICAL"},
                            {"cve_id": "CVE-2024-3", "severity": "LOW"},
                        ]
                    }
                ],
            }
        ]
    }

    assert calcular_infra_score(scan_data) == pytest.approx(50 / 7)
    assert calcular_infra_score(
        {"dispositivos": [{"open_ports": [23]}]}
    ) == pytest.approx(20 / 7)
    assert calcular_infra_score(
        {
            "dispositivos": [
                {
                    "ip": "192.0.2.1",
                    "services": [
                        {
                            "port": 443,
                            "protocol": "tcp",
                            "cves": [
                                {
                                    "cve_id": "CVE-2024-1",
                                    "severity": "HIGH",
                                }
                            ],
                        }
                    ],
                },
                {
                    "ip": "192.0.2.2",
                    "services": [
                        {
                            "port": 443,
                            "protocol": "tcp",
                            "cves": [
                                {
                                    "cve_id": "CVE-2024-1",
                                    "severity": "HIGH",
                                }
                            ],
                        }
                    ],
                },
            ]
        }
    ) == pytest.approx(30 / 7)


def test_infra_score_regression_and_maximum():
    assert calcular_infra_score(
        telnet=1,
        rtsp=0,
        unknown=0,
        gateway_http=0,
        admin_ports=0,
    ) == pytest.approx(2.86, abs=0.01)
    assert (
        calcular_infra_score(
            telnet=1,
            rtsp=1,
            unknown=5,
            gateway_http=1,
            admin_ports=3,
            cve_criticas=10,
            cve_altas=10,
            cve_medias=10,
        )
        == 10.0
    )


def test_score_parcial_so_inclui_componentes_observados():
    resultado = decompor_infra_score(
        {
            "ips_ativos": 5,
            "desconhecidos": 4,
            "dispositivos": [{"ip": "192.0.2.10", "open_ports": []}],
        },
        scan_services=False,
        cve_lookup=False,
        cve_coverage_complete=False,
    )

    assert resultado["score"] == pytest.approx(10 / 7)
    assert resultado["components"][0]["status"] == "não verificado"
    assert resultado["components"][2]["display_value"] == "4/5 (80%); fator 1"
    assert resultado["components"][2]["contribution"] == 1
    assert resultado["complete"] is False


def test_componente_cve_nao_multiplica_duas_vezes_o_peso():
    resultado = decompor_infra_score(
        {
            "ips_ativos": 1,
            "desconhecidos": 0,
            "dispositivos": [{
                "ip": "192.0.2.10",
                "open_ports": [],
                "services": [{
                    "port": 443,
                    "protocol": "tcp",
                    "cves": [{
                        "cve_id": "CVE-2024-12345",
                        "severity": "CRITICAL",
                    }],
                }],
            }],
        },
        scan_services=True,
        cve_lookup=True,
        cve_coverage_complete=True,
    )

    score_component = resultado["components"][-1]
    assert score_component["value"] == 3
    assert score_component["contribution"] == 3


def test_scan_salva_metadados_e_migracao_e_idempotente(monkeypatch, tmp_path):
    db_path = tmp_path / "scan.db"
    monkeypatch.setattr(persistence, "DB_NAME", str(db_path))
    persistence.iniciar_banco()
    scan_id = persistence.salvar_scan({
        "timestamp": "2026-01-01T12:00:00",
        "ips_ativos": 1,
        "desconhecidos": 1,
        "modo": "servicos",
        "scan_services": True,
        "snmp_enabled": True,
        "cve_lookup": True,
        "classifier_version": "v2-conservador",
        "formula_version": "normalizada-7-v1",
        "duracao_s": 12.5,
        "componentes": [{"key": "T", "status": "observado"}],
        "dispositivos": [{
            "ip": "192.0.2.10",
            "tipo": "desconhecido",
            "snmp_info": {"description": "Cisco Router"},
            "classificacao_evidencia": ["Porta aberta: 23"],
            "classificacao_confianca": 5,
        }],
    })
    persistence.iniciar_banco()

    with sqlite3.connect(db_path) as conn:
        scan = conn.execute(
            "SELECT modo, scan_services, snmp_enabled, cve_lookup, classifier_version, "
            "formula_version, duracao_s, componentes_json, data_json "
            "FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone()
        device = conn.execute(
            "SELECT classificacao_evidencia, classificacao_confianca "
            "FROM dispositivos WHERE scan_id = ?",
            (scan_id,),
        ).fetchone()

    assert scan[:7] == (
        "servicos", 1, 1, 1, "v2-conservador", "normalizada-7-v1", 12.5
    )
    assert json.loads(scan[7]) == [{"key": "T", "status": "observado"}]
    assert json.loads(scan[8])["dispositivos"][0]["snmp_info"] == {
        "description": "Cisco Router"
    }
    assert json.loads(device[0]) == ["Porta aberta: 23"]
    assert device[1] == 5


def test_salvar_scan_persiste_dispositivos_em_lote(monkeypatch, tmp_path):
    db_path = tmp_path / "batch.db"
    monkeypatch.setattr(persistence, "DB_NAME", str(db_path))
    devices = [
        {
            "ip": f"192.0.2.{index}",
            "mac": f"00:11:22:33:44:{index:02x}",
            "hostname": f"host-{index}",
            "tipo": "computador_windows",
            "open_ports": [22],
            "classificacao_evidencia": ["Porta aberta: 22"],
        }
        for index in range(1, 4)
    ]

    scan_id = persistence.salvar_scan({"dispositivos": devices})

    with sqlite3.connect(db_path) as conn:
        saved_devices = conn.execute(
            "SELECT ip, mac, nome FROM dispositivos "
            "WHERE scan_id = ? ORDER BY ip",
            (scan_id,),
        ).fetchall()
        saved_risk_rows = conn.execute(
            "SELECT COUNT(*) FROM risk_history WHERE scan_id = ?",
            (scan_id,),
        ).fetchone()[0]

    assert saved_devices == [
        ("192.0.2.1", "00:11:22:33:44:01", "host-1"),
        ("192.0.2.2", "00:11:22:33:44:02", "host-2"),
        ("192.0.2.3", "00:11:22:33:44:03", "host-3"),
    ]
    assert saved_risk_rows == len(devices)


def test_salvar_scan_reverte_todos_os_registros_em_erro(
    monkeypatch, tmp_path
):
    db_path = tmp_path / "rollback.db"
    monkeypatch.setattr(persistence, "DB_NAME", str(db_path))
    persistence.init_database()

    def fail_saving_services(*args, **kwargs):
        raise RuntimeError("falha simulada")

    monkeypatch.setattr(persistence, "_salvar_servicos", fail_saving_services)
    with pytest.raises(RuntimeError, match="falha simulada"):
        persistence.salvar_scan({
            "dispositivos": [{
                "ip": "192.0.2.10",
                "mac": "00:11:22:33:44:55",
            }],
        })

    with sqlite3.connect(db_path) as conn:
        counts = tuple(
            conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("scans", "dispositivos", "risk_history")
        )

    assert counts == (0, 0, 0)


def test_migracao_preserva_scans_legados_com_defaults_conservadores(
    monkeypatch, tmp_path
):
    db_path = tmp_path / "legacy.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE scans (
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                ambiente TEXT,
                ips_ativos INTEGER,
                uso REAL,
                risco_medio REAL,
                desconhecidos INTEGER,
                mac_randomizados INTEGER,
                recomendacao TEXT,
                data_json TEXT
            )
        """)
        conn.execute(
            "INSERT INTO scans (id, timestamp, ips_ativos, desconhecidos) "
            "VALUES (37, '2025-01-01T12:00:00', 5, 0)"
        )
    monkeypatch.setattr(persistence, "DB_NAME", str(db_path))

    persistence.iniciar_banco()
    persistence.iniciar_banco()

    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT id, ips_ativos, desconhecidos, modo, scan_services, "
            "snmp_enabled, cve_lookup, classifier_version, formula_version, "
            "duracao_s "
            "FROM scans WHERE id = 37"
        ).fetchone()
    assert row == (
        37, 5, 0, "rapido", 0, 0, 0, "v1", "normalizada-7-v1", None
    )


def test_pdf_inclui_contexto_e_decomposicao(monkeypatch, tmp_path):
    from reports import pdf_report

    monkeypatch.setattr(pdf_report, "GRAFICOS_OK", False)
    monkeypatch.setattr(pdf_report, "PASTA_REPORTS", str(tmp_path))
    output = tmp_path / "scan.pdf"
    generated = pdf_report.gerar_pdf(
        dispositivos=[{
            "ip": "192.0.2.10",
            "tipo": "desconhecido",
            "risco": 1,
        }],
        nome_arquivo=str(output),
        contexto_scan={
            "id": 7,
            "modo": "Rápido (ARP)",
            "duracao_s": 4.5,
            "classifier_version": "v2-conservador",
            "formula_version": "normalizada-7-v1",
            "componentes": [{
                "key": "U",
                "name": "Dispositivos desconhecidos",
                "weight": 1,
                "status": "observado",
                "value": 1,
                "contribution": 1,
                "display_value": "1/1 (100%); fator 1",
            }],
        },
    )

    assert generated == str(output)
    assert output.is_file()
    assert output.stat().st_size > 0


def test_pdf_inventario_omite_risco_e_sinaliza_mac_local():
    from reportlab.platypus import Table
    from reports import pdf_report

    items = pdf_report._tabela_dispositivos(
        [{
            "ip": "192.0.2.13",
            "hostname": "_gateway.local",
            "mac": "02:11:22:33:44:55",
            "fabricante": "Desconhecido",
            "tipo": "gateway",
            "risco": 0,
        }],
        pdf_report._estilos(),
    )
    table = next(item for item in items if isinstance(item, Table))

    assert table._cellvalues[0] == [
        "IP", "Hostname", "MAC", "Fabricante", "Tipo"
    ]
    assert table._cellvalues[1][1] == "gateway"
    assert table._cellvalues[1][2] == "02:11:22:33:44:55"
    assert (
        table._cellvalues[1][3].getPlainText()
        == "MAC local (possível randomização)"
    )
    assert len(table._cellvalues[1]) == 5


def test_pdf_le_componentes_canonicos_e_preserva_mac_ausente(
    monkeypatch, tmp_path
):
    from gerar_relatorio import extract_scan_data

    db_path = tmp_path / "report.db"
    monkeypatch.setattr("gerar_relatorio.DB_PATH", str(db_path))
    scan_data = {
        "ips_ativos": 1,
        "desconhecidos": 1,
        "classifier_version": "v2-conservador",
        "dispositivos": [{
            "ip": "192.0.2.13",
            "tipo": "desconhecido",
            "mac": "",
        }],
        "componentes": [{
            "key": "U",
            "status": "não verificado",
            "weight": 1,
            "display_value": "—",
        }],
    }
    canonical_components = [{
        "key": "U",
        "status": "observado",
        "weight": 1,
        "value": 1,
        "contribution": 1,
        "display_value": "1/1 (100%); fator 1",
    }]
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "CREATE TABLE scans (id INTEGER PRIMARY KEY, timestamp TEXT, "
            "data_json TEXT, componentes_json TEXT)"
        )
        conn.execute(
            "INSERT INTO scans VALUES (?, ?, ?, ?)",
            (
                39,
                "2026-10-24T01:00:00",
                json.dumps(scan_data),
                json.dumps(canonical_components),
            ),
        )

    devices, _, context = extract_scan_data(39)

    assert devices[0]["ip"] == "192.0.2.13"
    assert devices[0]["mac"] == ""
    assert context["componentes"] == canonical_components
    assert context["score_observado"] == pytest.approx(10 / 7)
    assert context["componentes_observados"] == ["U"]


def test_scan_port_configuration_has_100_valid_defaults():
    from core.scan_config import TOP_100_PORTS, obter_portas_scan

    assert len(TOP_100_PORTS) == 100
    assert len(set(TOP_100_PORTS)) == 100
    assert obter_portas_scan("8443") == (8443,)
    with pytest.raises(ValueError):
        obter_portas_scan("0")


def test_software_export_includes_asset_product_and_cves(tmp_path):
    output = tmp_path / "software.csv"
    exportar_software_csv(
        [
            {
                "ip": "192.0.2.10",
                "mac": "02:00:00:00:00:10",
                "services": [
                    {
                        "port": 443,
                        "protocol": "tcp",
                        "service": "https",
                        "product": "nginx",
                        "version": "1.24.0",
                        "cpe": "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*",
                        "confidence": 100,
                        "cves": [{"cve_id": "CVE-2024-12345"}],
                    }
                ],
            }
        ],
        str(output),
    )

    with output.open(encoding="utf-8", newline="") as file:
        row = next(csv.DictReader(file))
    assert row["Ativo"] == "02:00:00:00:00:10"
    assert row["Produto"] == "nginx"
    assert row["Versão"] == "1.24.0"
    assert row["CVEs"] == "CVE-2024-12345"


def _save_endpoint_scan(
    ip_address,
    product,
    version,
    cpe_source=None,
    cve_status=None,
    cve_status_reason=None,
):
    return persistence.salvar_scan(
        {
            "dispositivos": [
                {
                    "ip": ip_address,
                    "mac": "00:11:22:33:44:55",
                    "hostname": "edge.local",
                    "services": [
                        {
                            "port": 443,
                            "protocol": "tcp",
                            "service": "https",
                            "product": product,
                            "version": version,
                            "cpe": f"cpe:2.3:a:example:{product}:{version}:*:*:*:*:*:*:*",
                            "confidence": 100,
                            "cpe_source": cpe_source,
                            "cve_status": cve_status,
                            "cve_status_reason": cve_status_reason,
                        }
                    ],
                }
            ]
        }
    )


def test_product_change_retires_previous_endpoint(monkeypatch, tmp_path):
    monkeypatch.setattr(
        persistence, "DB_NAME", str(tmp_path / "product-change.db")
    )

    _save_endpoint_scan("192.0.2.10", "nginx", "1.18.0")
    _save_endpoint_scan("192.0.2.10", "apache", "2.4.62")

    inventory = persistence.obter_inventario_software()

    assert len(inventory) == 1
    assert inventory[0]["product"] == "apache"
    assert inventory[0]["ip_address"] == "192.0.2.10"


def test_ip_change_creates_new_endpoint_for_same_asset(monkeypatch, tmp_path):
    monkeypatch.setattr(persistence, "DB_NAME", str(tmp_path / "ip-change.db"))

    _save_endpoint_scan("192.0.2.10", "nginx", "1.18.0")
    previous_asset = persistence.obter_inventario_software()[0]["asset_id"]
    _save_endpoint_scan("192.0.2.11", "nginx", "1.18.0")

    inventory = persistence.obter_inventario_software()

    assert len(inventory) == 1
    assert inventory[0]["asset_id"] == previous_asset
    assert inventory[0]["ip_address"] == "192.0.2.11"


def test_cve_status_and_cpe_source_persist_through_inventory_api(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(persistence, "DB_NAME", str(tmp_path / "status.db"))

    _save_endpoint_scan(
        "192.0.2.10",
        "nginx",
        "1.18.0",
        cpe_source="inferred",
        cve_status="skipped_low_confidence",
        cve_status_reason="Fingerprint abaixo do limiar (45 < 70).",
    )

    inventory = persistence.obter_inventario_software()

    assert inventory[0]["cpe_source"] == "inferred"
    assert inventory[0]["cve_status"] == "skipped_low_confidence"
    assert "45 < 70" in inventory[0]["cve_status_reason"]


def test_unknown_hostnames_fall_back_to_distinct_ip_identities(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(persistence, "DB_NAME", str(tmp_path / "unknown.db"))

    persistence.salvar_scan(
        {
            "dispositivos": [
                {
                    "ip": "192.0.2.20",
                    "hostname": "desconhecido",
                    "mac": "",
                    "services": [],
                },
                {
                    "ip": "192.0.2.21",
                    "hostname": "desconhecido",
                    "mac": "",
                    "services": [],
                },
            ]
        }
    )

    conn = sqlite3.connect(persistence.DB_NAME)
    try:
        asset_count = conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
    finally:
        conn.close()
    assert asset_count == 2


def test_unidentified_service_evidence_is_kept(monkeypatch, tmp_path):
    database_path = tmp_path / "evidence.db"
    monkeypatch.setattr(persistence, "DB_NAME", str(database_path))

    persistence.salvar_scan(
        {
            "dispositivos": [
                {
                    "ip": "192.0.2.30",
                    "hostname": "",
                    "mac": "",
                    "services": [
                        {
                            "port": 8080,
                            "protocol": "tcp",
                            "service": "http-alt",
                            "product": None,
                            "evidence": '{"name":"http-alt","state":"open"}',
                        }
                    ],
                }
            ]
        }
    )

    conn = sqlite3.connect(database_path)
    try:
        evidence = conn.execute(
            "SELECT evidence_type, software_instance_id, raw_value "
            "FROM evidence"
        ).fetchone()
    finally:
        conn.close()
    assert evidence == (
        "nmap_service",
        None,
        '{"name":"http-alt","state":"open"}',
    )
