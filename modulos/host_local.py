import socket
import uuid


def obter_mac_local():
    mac_num = uuid.getnode()
    mac = ':'.join(f'{(mac_num >> ele) & 0xff:02x}' for ele in range(40, -1, -8))
    return mac.lower()


def obter_ip_local():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Não precisa conectar de verdade, só força resolução da interface principal
        s.connect(("8.8.8.8", 80))

        ip = s.getsockname()[0]

        s.close()

        return ip

    except Exception:
        return ""


def obter_hostname_local():
    return socket.gethostname().lower()


def obter_host_local():
    return {
        "hostname": obter_hostname_local(),
        "ip": obter_ip_local(),
        "mac": obter_mac_local()
    }
