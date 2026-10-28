#!/usr/bin/env python3
"""Compare the persisted InfraScore text used by bot, dashboard, and PDF."""

import argparse
import sqlite3
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.telegram_bot_completo import formatar_score_status
from dashboard.app import formatar_score_dashboard
from reports.pdf_report import formatar_score_pdf


def compare_scores(db_path: str, limit: int = 50) -> list[dict[str, object]]:
    path = Path(db_path)
    if not path.is_file():
        raise FileNotFoundError(f"Banco não encontrado: {path}")
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(scans)")
        }
        required = {"id", "infra_score", "infra_score_cobertura"}
        missing = required - columns
        if missing:
            raise RuntimeError(
                "Migração ausente; faltam colunas: "
                + ", ".join(sorted(missing))
            )
        rows = conn.execute(
            "SELECT id, infra_score, infra_score_cobertura FROM scans "
            "ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        results = []
        for row in reversed(rows):
            scan = dict(row)
            bot_text = formatar_score_status(scan)
            dashboard_text = formatar_score_dashboard(scan)
            pdf_text = formatar_score_pdf(scan)
            results.append({
                "scan_id": row["id"],
                "bot": bot_text,
                "dashboard": dashboard_text,
                "pdf": pdf_text,
                "equal": bot_text == dashboard_text == pdf_text,
            })
        return results
    finally:
        conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--db",
        default=str(PROJECT_ROOT / "storage" / "infrainsight.db"),
        help="SQLite database path (default: storage/infrainsight.db)",
    )
    parser.add_argument("--limit", type=int, default=50)
    args = parser.parse_args()
    if args.limit < 1:
        parser.error("--limit deve ser positivo")
    results = compare_scores(args.db, args.limit)
    print("scan_id | texto do bot | texto do dashboard | texto do PDF | iguais")
    for row in results:
        print(
            f"{row['scan_id']} | {row['bot']} | {row['dashboard']} | "
            f"{row['pdf']} | {'SIM' if row['equal'] else 'NÃO'}"
        )
    print(f"Resultado: {len(results)} scans comparados.")
    if not all(row["equal"] for row in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
