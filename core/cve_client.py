"""Cliente da API CVE 2.0 do NVD com cache SQLite e limiar de confiança."""

from collections.abc import Iterable, Mapping
from contextlib import closing
from datetime import datetime, timedelta, timezone
import json
import logging
import os
import sqlite3
from typing import Any

import requests

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_PAGE_SIZE = 2000
_DEFAULT_CACHE_TTL_HOURS = 48
_DEFAULT_MIN_CONFIDENCE = 70
_LOGGER = logging.getLogger(__name__)


def _severity_and_score(
    metrics: Mapping[str, Any],
) -> tuple[str | None, float | None]:
    for metric_name in (
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ):
        entries = metrics.get(metric_name)
        if not isinstance(entries, list) or not entries:
            continue
        data = entries[0].get("cvssData", {})
        if not isinstance(data, Mapping):
            continue
        severity = data.get("baseSeverity") or entries[0].get("baseSeverity")
        score = data.get("baseScore")
        try:
            numeric_score = float(score) if score is not None else None
        except (TypeError, ValueError):
            numeric_score = None
        if not severity and numeric_score is not None:
            severity = (
                "CRITICAL"
                if numeric_score >= 9
                else (
                    "HIGH"
                    if numeric_score >= 7
                    else "MEDIUM" if numeric_score >= 4 else "LOW"
                )
            )
        return str(severity).upper() if severity else None, numeric_score
    return None, None


def _parse_nvd_payload(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    vulnerabilities = payload.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        raise ValueError("Resposta inválida da API NVD: vulnerabilities.")

    results = []
    for item in vulnerabilities:
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        severity, cvss_score = _severity_and_score(cve.get("metrics", {}))
        descriptions = cve.get("descriptions", [])
        description = next(
            (
                entry.get("value", "")
                for entry in descriptions
                if entry.get("lang") == "en"
            ),
            "",
        )
        results.append(
            {
                "cve_id": cve_id,
                "severity": severity,
                "cvss_score": cvss_score,
                "description": description,
            }
        )
    return results


class NvdClient:
    """Consulta CVEs por CPE, guarda respostas e reaproveita cache expirado."""

    def __init__(
        self,
        api_key: str | None = None,
        session: requests.Session | None = None,
        timeout: float = 20,
        db_path: str | None = None,
        ttl_hours: float | None = None,
        min_confidence: int | None = None,
    ) -> None:
        self.api_key = api_key
        self.session = session or requests.Session()
        self.timeout = timeout
        self.db_path = db_path or os.getenv(
            "INFRA_DB_PATH", "storage/infrainsight.db"
        )
        raw_ttl = (
            ttl_hours
            if ttl_hours is not None
            else os.getenv(
                "INFRA_CVE_CACHE_TTL_HOURS",
                str(_DEFAULT_CACHE_TTL_HOURS),
            )
        )
        try:
            self.ttl_hours = float(raw_ttl)
        except (TypeError, ValueError) as error:
            raise ValueError(
                "INFRA_CVE_CACHE_TTL_HOURS deve ser numérico."
            ) from error
        if self.ttl_hours <= 0:
            raise ValueError(
                "INFRA_CVE_CACHE_TTL_HOURS deve ser maior que zero."
            )

        raw_confidence = (
            min_confidence
            if min_confidence is not None
            else os.getenv(
                "INFRA_CVE_MIN_CONFIDENCE",
                str(_DEFAULT_MIN_CONFIDENCE),
            )
        )
        try:
            self.min_confidence = int(raw_confidence)
        except (TypeError, ValueError) as error:
            raise ValueError(
                "INFRA_CVE_MIN_CONFIDENCE deve ser um inteiro entre 0 e 100."
            ) from error
        if not 0 <= self.min_confidence <= 100:
            raise ValueError(
                "INFRA_CVE_MIN_CONFIDENCE deve ser um inteiro entre 0 e 100."
            )

    def _connect(self) -> sqlite3.Connection:
        parent = os.path.dirname(os.path.abspath(self.db_path))
        os.makedirs(parent, exist_ok=True)
        conn = sqlite3.connect(self.db_path, timeout=self.timeout)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cve_cache (
                cpe TEXT PRIMARY KEY,
                payload TEXT NOT NULL,
                fetched_at TIMESTAMP NOT NULL,
                expires_at TIMESTAMP NOT NULL
            )
            """)
        return conn

    def _read_cache(self, cpe: str) -> tuple[dict[str, Any], bool] | None:
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT payload, expires_at FROM cve_cache WHERE cpe = ?",
                (cpe,),
            ).fetchone()
        if row is None:
            return None

        try:
            payload = json.loads(row[0])
            expires_at = datetime.fromisoformat(row[1])
        except (json.JSONDecodeError, TypeError, ValueError) as error:
            _LOGGER.warning(
                "Entrada de cache CVE inválida para %s: %s", cpe, error
            )
            return None
        if not isinstance(payload, dict):
            _LOGGER.warning("Payload de cache CVE inválido para %s.", cpe)
            return None
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        fresh = expires_at > datetime.now(timezone.utc)
        return payload, fresh

    def _write_cache(self, cpe: str, payload: Mapping[str, Any]) -> None:
        fetched_at = datetime.now(timezone.utc)
        expires_at = fetched_at + timedelta(hours=self.ttl_hours)
        with closing(self._connect()) as conn:
            with conn:
                conn.execute(
                    """
                    INSERT INTO cve_cache (cpe, payload, fetched_at, expires_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(cpe) DO UPDATE SET
                        payload = excluded.payload,
                        fetched_at = excluded.fetched_at,
                        expires_at = excluded.expires_at
                    """,
                    (
                        cpe,
                        json.dumps(payload, ensure_ascii=False),
                        fetched_at.isoformat(),
                        expires_at.isoformat(),
                    ),
                )

    def _fetch_payload(self, cpe: str) -> dict[str, Any]:
        vulnerabilities = []
        start_index = 0
        total_results: int | None = None
        headers = {"apiKey": self.api_key} if self.api_key else {}

        while total_results is None or start_index < total_results:
            response = self.session.get(
                NVD_CVE_URL,
                params={
                    "cpeName": cpe,
                    "startIndex": start_index,
                    "resultsPerPage": _PAGE_SIZE,
                },
                headers=headers,
                timeout=self.timeout,
            )
            response.raise_for_status()
            page = response.json()
            page_vulnerabilities = page.get("vulnerabilities", [])
            if not isinstance(page_vulnerabilities, list):
                raise ValueError(
                    "Resposta inválida da API NVD: vulnerabilities."
                )
            if total_results is None:
                total_results = int(
                    page.get("totalResults", len(page_vulnerabilities))
                )
            vulnerabilities.extend(page_vulnerabilities)
            if not page_vulnerabilities:
                break
            start_index += len(page_vulnerabilities)

        return {
            "totalResults": total_results or 0,
            "vulnerabilities": vulnerabilities,
        }

    def consultar_por_cpe(self, cpe: str) -> tuple[list[dict[str, Any]], str]:
        if not cpe.startswith("cpe:"):
            raise ValueError("O filtro NVD precisa ser um CPE válido.")

        cached = self._read_cache(cpe)
        if cached and cached[1]:
            return _parse_nvd_payload(cached[0]), "verified_cached"

        try:
            payload = self._fetch_payload(cpe)
        except requests.RequestException as error:
            if cached:
                _LOGGER.warning(
                    "NVD indisponível para %s; usando cache expirado: %s",
                    cpe,
                    error,
                )
                return _parse_nvd_payload(cached[0]), "verified_stale_cache"
            raise

        self._write_cache(cpe, payload)
        return _parse_nvd_payload(payload), "verified"

    def buscar_por_cpe(self, cpe: str) -> list[dict[str, Any]]:
        """Compatibilidade com consumidores que precisam somente da lista CVE."""
        return self.consultar_por_cpe(cpe)[0]


def deve_consultar_cve(
    software_instance: Mapping[str, Any],
    min_confidence: int = _DEFAULT_MIN_CONFIDENCE,
) -> bool:
    """CPE explícito do Nmap é consultado; CPE inferido precisa de confiança."""
    if software_instance.get("cpe_source") == "nmap":
        return bool(software_instance.get("cpe"))
    if not software_instance.get("cpe"):
        return False
    try:
        confidence = int(software_instance.get("confidence") or 0)
    except (TypeError, ValueError):
        return False
    return confidence >= min_confidence


def enriquecer_servicos_com_cves(
    services: Iterable[dict[str, Any]], client: NvdClient
) -> list[dict[str, Any]]:
    """Correlaciona CVEs e anota status inclusive quando a consulta é omitida."""
    cache: dict[str, tuple[list[dict[str, Any]], str]] = {}
    enriched: list[dict[str, Any]] = []
    for service in services:
        item = dict(service)
        cpe = item.get("cpe")
        if not cpe:
            item["cves"] = []
            item["cve_status"] = "not_available_no_cpe"
            item["cve_status_reason"] = "Nenhum CPE foi identificado."
            enriched.append(item)
            continue
        if not deve_consultar_cve(item, client.min_confidence):
            confidence = item.get("confidence")
            item["cves"] = []
            item["cve_status"] = "skipped_low_confidence"
            item["cve_status_reason"] = (
                f"Fingerprint abaixo do limiar "
                f"({confidence or 0} < {client.min_confidence})."
            )
            enriched.append(item)
            continue

        if cpe not in cache:
            try:
                cache[cpe] = client.consultar_por_cpe(cpe)
            except requests.RequestException as error:
                _LOGGER.warning("Consulta NVD falhou para %s: %s", cpe, error)
                item["cves"] = []
                item["cve_status"] = "unavailable"
                item["cve_status_reason"] = (
                    f"NVD indisponível: {type(error).__name__}."
                )
                enriched.append(item)
                continue
        item["cves"], item["cve_status"] = cache[cpe]
        item["cve_status_reason"] = None
        enriched.append(item)
    return enriched
