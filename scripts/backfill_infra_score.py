#!/usr/bin/env python3
"""Dry-run-first backfill of persisted InfraScore values for historical scans."""

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.infra_score import cobertura_infra_score, score_minimo_observado

SUPPORTED_FORMULAS = {"normalizada-7-v1"}


def _json_object(value: str | None) -> dict[str, Any]:
    if not value:
        return {}
    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        raise ValueError("data_json não contém um objeto")
    return parsed


def _json_components(value: str | None) -> list[dict[str, Any]]:
    if not value:
        return []
    parsed = json.loads(value)
    if not isinstance(parsed, list):
        raise ValueError("componentes_json não contém uma lista")
    return parsed


def plan_backfill(db_path: str) -> list[dict[str, Any]]:
    """Calcula candidatos sem alterar o banco."""
    path = Path(db_path)
    if not path.is_file():
        raise FileNotFoundError(f"Banco não encontrado: {path}")
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(scans)")
        }
        required = {
            "id", "infra_score", "infra_score_cobertura", "score_formula",
            "componentes_json", "data_json",
        }
        missing = required - columns
        if missing:
            raise RuntimeError(
                "Migração ausente; faltam colunas: "
                + ", ".join(sorted(missing))
            )
        rows = conn.execute(
            "SELECT id, infra_score, score_formula, formula_version, "
            "componentes_json, data_json FROM scans ORDER BY id"
        ).fetchall()
        plan = []
        for row in rows:
            item = {"id": row["id"], "score": None, "coverage": None,
                    "formula": None, "reason": None}
            if row["infra_score"] is not None:
                item["reason"] = "já possui infra_score"
                plan.append(item)
                continue
            try:
                data = _json_object(row["data_json"])
                components = _json_components(row["componentes_json"])
            except (TypeError, ValueError, json.JSONDecodeError) as error:
                item["reason"] = f"dados salvos inválidos: {error}"
                plan.append(item)
                continue
            if not components:
                components = data.get("componentes", [])
            if not isinstance(components, list):
                item["reason"] = "componentes salvos não são uma lista"
                plan.append(item)
                continue
            formula = (
                row["score_formula"]
                or data.get("score_formula")
                or data.get("formula_version")
            )
            item["formula"] = formula
            if not formula:
                item["reason"] = "fórmula ausente"
                if not components:
                    item["reason"] += "; componentes não salvos"
            elif formula not in SUPPORTED_FORMULAS:
                item["reason"] = (
                    f"fórmula não suportada: {formula}"
                )
            elif not components:
                item["reason"] = "componentes não salvos"
            else:
                score = score_minimo_observado(components)
                if score is None:
                    item["reason"] = "componentes observados insuficientes"
                else:
                    item["score"] = score
                    item["coverage"] = cobertura_infra_score(components)
                    item["reason"] = "pronto para backfill"
            plan.append(item)
        return plan
    finally:
        conn.close()


def apply_backfill(db_path: str, plan: list[dict[str, Any]]) -> int:
    """Persiste somente os itens calculáveis do plano já revisado."""
    conn = sqlite3.connect(db_path)
    try:
        updated = 0
        for item in plan:
            if item["reason"] != "pronto para backfill":
                continue
            cursor = conn.execute(
                "UPDATE scans SET infra_score = ?, "
                "infra_score_cobertura = ?, score_formula = ? "
                "WHERE id = ? AND infra_score IS NULL",
                (
                    item["score"], item["coverage"], item["formula"],
                    item["id"],
                ),
            )
            updated += cursor.rowcount
        conn.commit()
        return updated
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--db",
        default=str(PROJECT_ROOT / "storage" / "infrainsight.db"),
        help="SQLite database path (default: storage/infrainsight.db)",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Persist calculable rows; default is read-only dry-run.",
    )
    args = parser.parse_args()
    plan = plan_backfill(args.db)
    ready = [item for item in plan if item["reason"] == "pronto para backfill"]
    unresolved = [item for item in plan if item["score"] is None]
    print(
        f"Scans: {len(plan)}; calculáveis: {len(ready)}; "
        f"NULL/sem alteração: {len(unresolved)}."
    )
    for item in unresolved:
        print(f"  Scan #{item['id']}: {item['reason']}.")
    if args.apply:
        print(f"Scans atualizados: {apply_backfill(args.db, plan)}")
    else:
        print("Dry-run: nenhuma alteração foi gravada.")


if __name__ == "__main__":
    main()
