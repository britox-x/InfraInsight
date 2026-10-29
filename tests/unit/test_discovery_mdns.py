# tests/unit/test_discovery_mdns.py
from core.discovery_mdns import evidencias_mdns, melhor_evidencia


def _info(servicos=(), hostnames=(), props=None):
    return {
        "servicos": list(servicos),
        "hostnames": list(hostnames),
        "nomes": [],
        "propriedades": props or {},
    }


def test_iphone_nao_vira_android():
    # o código original testava 'phone' antes de 'iphone' e errava este caso
    e = melhor_evidencia(_info(hostnames=["iPhone-de-Maria.local."]))
    assert e["tipo"] == "mobile/ios"


def test_android_por_hostname_tem_confianca_baixa():
    e = melhor_evidencia(_info(hostnames=["Galaxy-S21.local."]))
    assert e["tipo"] == "mobile/android" and e["confianca"] == 3


def test_impressora_por_servico_ipp():
    e = melhor_evidencia(_info(servicos=["_ipp._tcp.local."]))
    assert e["tipo"] == "impressora"


def test_airplay_nao_e_celular():
    e = melhor_evidencia(_info(servicos=["_airplay._tcp.local."]))
    assert e["tipo"] == "smart_device" and e["confianca"] == 3


def test_airplay_com_modelo_apple_tv_sobe_para_smarttv():
    e = melhor_evidencia(
        _info(
            servicos=["_airplay._tcp.local."],
            props={"_airplay._tcp.local.": {"model": "AppleTV6,2"}},
        )
    )
    assert e["tipo"] == "smarttv" and e["confianca"] == 2


def test_chromecast_pelo_modelo():
    e = melhor_evidencia(
        _info(
            servicos=["_googlecast._tcp.local."],
            props={"_googlecast._tcp.local.": {"md": "Chromecast"}},
        )
    )
    assert e["tipo"] == "chromecast"


def test_sem_evidencia_devolve_none():
    assert melhor_evidencia(_info()) is None
    assert melhor_evidencia(None) is None
    assert melhor_evidencia(_info(hostnames=["matheus-550XCJ-550XCR.local."])) is None


def test_ordenado_do_mais_confiavel():
    ev = evidencias_mdns(
        _info(servicos=["_airplay._tcp.local.", "_ipp._tcp.local."])
    )
    confs = [x["confianca"] for x in ev]
    assert confs == sorted(confs)

