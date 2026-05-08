import subprocess
import re


def coletar_arp_ddwrt(host="192.168.1.2"):
    try:
        comando = f"ssh root@{host} cat /proc/net/arp"
        resultado = subprocess.check_output(
            comando,
            shell=True,
            timeout=15
        ).decode()

        dispositivos = []

        for linha in resultado.splitlines()[1:]:
            partes = linha.split()

            if len(partes) >= 6:
                ip = partes[0]
                flags = partes[2]
                mac = partes[3].lower()
                interface = partes[5]

                if mac != "00:00:00:00:00:00":
                    dispositivos.append({
                        "ip": ip,
                        "mac": mac,
                        "flags": flags,
                        "interface": interface,
                        "fonte": "ddwrt"
                    })

        return dispositivos

    except Exception:
        return []
