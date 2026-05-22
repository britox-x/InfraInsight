import subprocess
import re

SSH_KEY = "/home/matheus/.ssh/id_rsa_ddwrt"


def executar_comando_ssh(host, comando):
    """
    Executa comando SSH no gateway informado.
    Compatível com DD-WRT / OpenWRT / routers Linux-based.
    """

    try:
        ssh_cmd = [
            "ssh",
            "-i", SSH_KEY,
            "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=5",
            "-o", "HostKeyAlgorithms=+ssh-rsa,ssh-dss",
            "-o", "PubkeyAcceptedAlgorithms=+ssh-rsa,ssh-dss",
            f"root@{host}",
            comando
        ]

        resultado = subprocess.check_output(
            ssh_cmd,
            stderr=subprocess.DEVNULL,
            timeout=8
        ).decode(errors="ignore")

        return resultado

    except Exception:
        return ""


def coletar_arp_ddwrt(host):
    """
    Coleta tabela ARP do roteador dinamicamente.
    """

    resultado = executar_comando_ssh(host, "cat /proc/net/arp")

    dispositivos = []

    if not resultado:
        return dispositivos

    for linha in resultado.splitlines()[1:]:
        partes = linha.split()

        if len(partes) >= 6:
            ip = partes[0]
            mac = partes[3].lower()
            interface = partes[5]

            if mac != "00:00:00:00:00:00":
                dispositivos.append({
                    "ip": ip,
                    "mac": mac,
                    "interface": interface,
                    "origem": "ddwrt_arp"
                })

    return dispositivos


def coletar_wifi_assoc(host):
    """
    Coleta clientes Wi-Fi conectados.
    Tenta DD-WRT primeiro, fallback OpenWRT.
    """

    resultado = executar_comando_ssh(host, "wl_atheros assoclist")

    if not resultado:
        resultado = executar_comando_ssh(host, "iw dev wlan0 station dump")

    dispositivos = []

    if not resultado:
        return dispositivos

    for linha in resultado.splitlines():
        match = re.search(r"([0-9A-Fa-f:]{17})", linha)

        if match:
            mac = match.group(1).lower()

            dispositivos.append({
                "mac": mac,
                "conexao": "wifi",
                "origem": "ddwrt_assoc"
            })

    return dispositivos
