#!/usr/bin/env python3
import csv
import os
from datetime import datetime


def exportar_csv(dispositivos, nome_arquivo=None):
    if not nome_arquivo:
        os.makedirs("exports", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        nome_arquivo = f"exports/dispositivos_{timestamp}.csv"

    with open(nome_arquivo, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "IP",
                "Hostname",
                "MAC",
                "Fabricante",
                "Tipo",
                "Risco",
                "Severidade",
                "Portas",
            ]
        )
        for d in dispositivos:
            writer.writerow(
                [
                    d.get("ip", ""),
                    d.get("nome", ""),
                    d.get("mac", ""),
                    d.get("fabricante", ""),
                    d.get("tipo", ""),
                    d.get("risco", ""),
                    d.get("severity", ""),
                    ", ".join(map(str, d.get("open_ports", []))),
                ]
            )
    print(f"✅ CSV: {nome_arquivo}")
    return nome_arquivo


def exportar_software_csv(dispositivos, nome_arquivo=None):
    """Exporta uma linha por serviço observado, sem usar IP como identidade."""
    if not nome_arquivo:
        os.makedirs("exports", exist_ok=True)
        nome_arquivo = (
            f"exports/software_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )

    with open(nome_arquivo, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(
            [
                "Ativo",
                "IP",
                "Porta",
                "Protocolo",
                "Serviço",
                "Produto",
                "Versão",
                "CPE",
                "Confiança",
                "CVEs",
            ]
        )
        for device in dispositivos:
            asset = (
                device.get("mac")
                or device.get("hostname")
                or device.get("nome")
                or device.get("ip", "")
            )
            for service in device.get("services", []):
                cve_ids = [
                    cve.get("cve_id") or cve.get("id")
                    for cve in service.get("cves", [])
                    if cve.get("cve_id") or cve.get("id")
                ]
                writer.writerow(
                    [
                        asset,
                        device.get("ip", ""),
                        service.get("port", ""),
                        service.get("protocol", ""),
                        service.get("service", ""),
                        service.get("product", ""),
                        service.get("version", ""),
                        service.get("cpe", ""),
                        service.get("confidence", ""),
                        ", ".join(cve_ids),
                    ]
                )
    print(f"✅ CSV de software: {nome_arquivo}")
    return nome_arquivo
