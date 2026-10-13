"""Mapeamento conservador de produtos de serviço para CPE 2.3."""

import re

_PRODUCTS = {
    "apache": ("apache", "http_server"),
    "apache httpd": ("apache", "http_server"),
    "dropbear": ("matt_johnston", "dropbear"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "microsoft httpapi": ("microsoft", "httpapi"),
    "microsoft iis": ("microsoft", "internet_information_services"),
    "nginx": ("nginx", "nginx"),
    "openssh": ("openbsd", "openssh"),
    "openssl": ("openssl", "openssl"),
    "samba": ("samba", "samba"),
    "vsftpd": ("vsftpd", "vsftpd"),
}
_VERSION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+_-]*$")


def mapear_cpe(produto: str, versao: str | None) -> str | None:
    """Retorna um CPE apenas para produtos e versões reconhecidos."""
    if not produto or not versao:
        return None

    vendor_product = _PRODUCTS.get(" ".join(produto.strip().lower().split()))
    version = versao.strip()
    if vendor_product is None or not _VERSION_RE.fullmatch(version):
        return None

    vendor, cpe_product = vendor_product
    return f"cpe:2.3:a:{vendor}:{cpe_product}:{version}:*:*:*:*:*:*:*"
