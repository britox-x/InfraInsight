import sqlite3

import pytest

import core.persistence as persistence
import core.telegram_bot_completo as telegram_bot
import dashboard.app as dashboard
from scripts.backfill_infra_score import apply_backfill, plan_backfill
from scripts.comparar_infrascore import compare_scores
from reports.pdf_report import formatar_score_pdf


def _observed_components():
    return [{
        "key": "U",
        "name": "Dispositivos desconhecidos",
        "weight": 1,
        "status": "observado",
        "value": 1,
        "contribution": 1,
        "display_value": "1/1 (100%); fator 1",
    }]


def test_salvar_scan_persiste_score_e_risco_medio_ausente(
    monkeypatch, tmp_path
):
    db_path = tmp_path / "scan.db"
    monkeypatch.setattr(persistence, "DB_NAME", str(db_path))
    persistence.iniciar_banco()

    scan_id = persistence.salvar_scan({
        "timestamp": "2026-10-27T18:00:00",
        "ips_ativos": 1,
        "risco_medio": None,
        "infra_score": 10 / 7,
        "infra_score_cobertura": 0.1,
        "score_formula": "normalizada-7-v1",
        "formula_version": "normalizada-7-v1",
        "componentes": _observed_components(),
        "dispositivos": [],
    })

    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT risco_medio, infra_score, infra_score_cobertura, "
            "score_formula FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone()
    assert row[0] is None
    assert row[1] == pytest.approx(10 / 7)
    assert row[2:] == (0.1, "normalizada-7-v1")


def test_bot_busca_infrascore_e_scan_id_persistidos(monkeypatch, tmp_path):
    db_path = tmp_path / "bot-status.db"
    monkeypatch.setattr(persistence, "DB_NAME", str(db_path))
    monkeypatch.setattr(telegram_bot, "DB_PATH", str(db_path))
    persistence.iniciar_banco()
    persistence.salvar_scan({
        "timestamp": "2026-10-27T18:00:00",
        "ips_ativos": 7,
        "infra_score": 1.42857,
        "infra_score_cobertura": 0.1,
        "score_formula": "normalizada-7-v1",
        "dispositivos": [],
    })

    scan = telegram_bot.obter_ultimo_scan()

    assert scan["id"] == 1
    assert scan["score_texto"] == "≥ 1,4/10 (cobertura 10%)"


def test_backfill_dry_run_nao_grava_e_so_planeja_formula_conhecida(
    monkeypatch, tmp_path
):
    db_path = tmp_path / "backfill.db"
    monkeypatch.setattr(persistence, "DB_NAME", str(db_path))
    persistence.iniciar_banco()
    persistence.salvar_scan({
        "formula_version": "normalizada-7-v1",
        "componentes": _observed_components(),
        "dispositivos": [],
    })
    persistence.salvar_scan({
        "classifier_version": "v1",
        "componentes": [],
        "dispositivos": [],
    })

    plan = plan_backfill(str(db_path))
    assert [item["reason"] for item in plan] == [
        "pronto para backfill",
        "fórmula ausente; componentes não salvos",
    ]
    assert apply_backfill(str(db_path), plan) == 1
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            "SELECT infra_score, infra_score_cobertura, score_formula "
            "FROM scans ORDER BY id"
        ).fetchall()
    assert rows[0][0] == pytest.approx(10 / 7)
    assert rows[0][1] == pytest.approx(0.1)
    assert rows[0][2] == "normalizada-7-v1"
    assert rows[1] == (None, None, None)


def test_comparador_usa_formatadores_reais_das_tres_superficies(
    monkeypatch, tmp_path
):
    db_path = tmp_path / "compare.db"
    monkeypatch.setattr(persistence, "DB_NAME", str(db_path))
    persistence.iniciar_banco()
    persistence.salvar_scan({
        "infra_score": 10 / 7,
        "infra_score_cobertura": 0.1,
        "score_formula": "normalizada-7-v1",
        "dispositivos": [],
    })
    persistence.salvar_scan({
        "infra_score": None,
        "infra_score_cobertura": None,
        "dispositivos": [],
    })

    rows = compare_scores(str(db_path))

    assert [row["scan_id"] for row in rows] == [1, 2]
    assert rows[0]["bot"] == rows[0]["dashboard"] == rows[0]["pdf"] == (
        "≥ 1,4/10 (cobertura 10%)"
    )
    assert rows[1]["bot"] == rows[1]["dashboard"] == rows[1]["pdf"] == "—"
    assert all(row["equal"] for row in rows)


def test_bot_dashboard_e_pdf_formatam_o_mesmo_registro():
    scan = {"infra_score": 10 / 7, "infra_score_cobertura": 0.1}

    assert telegram_bot.formatar_score_status(scan) == (
        dashboard.formatar_score_dashboard(scan)
    )
    assert dashboard.formatar_score_dashboard(scan) == formatar_score_pdf(scan)
