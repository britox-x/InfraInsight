import core.telegram_bot_completo as telegram_bot


def test_token_telegram_vem_do_ambiente(monkeypatch):
    from core import telegram_bot as alert_bot

    monkeypatch.setenv("INFRA_TELEGRAM_TOKEN", "rotated-test-token")

    assert telegram_bot._get_telegram_token() == "rotated-test-token"
    assert alert_bot._get_telegram_token() == "rotated-test-token"


def test_comando_eventos_envia_eventos_html_escapados(monkeypatch):
    messages = []
    monkeypatch.setattr(
        telegram_bot,
        "obter_eventos_recentes",
        lambda **kwargs: [
            {
                "event": "ENTROU",
                "device_name": "<novo-host>",
                "mac_address": "00:11:22:33:44:55",
                "ip_address": "192.0.2.10",
                "timestamp": "2026-01-01T12:05:00",
                "mac_randomizado": 1,
            }
        ],
    )
    monkeypatch.setattr(
        telegram_bot,
        "enviar_mensagem",
        lambda chat_id, text, **kwargs: messages.append(
            (chat_id, text, kwargs)
        ),
    )

    telegram_bot.processar_comando("/eventos", 123)

    assert len(messages) == 1
    chat_id, message, options = messages[0]
    assert chat_id == 123
    assert "<novo-host>" not in message
    assert "&lt;novo-host&gt;" in message
    assert "01/01 12:05" in message
    assert "MAC possivelmente rotativo" in message
    assert options == {"parse_mode": "HTML"}


def test_comando_eventos_informa_quando_nao_ha_registros(monkeypatch):
    messages = []
    monkeypatch.setattr(
        telegram_bot, "obter_eventos_recentes", lambda **kwargs: []
    )
    monkeypatch.setattr(
        telegram_bot,
        "enviar_mensagem",
        lambda chat_id, text, **kwargs: messages.append(text),
    )

    telegram_bot.processar_comando("/eventos", 123)

    assert messages == ["🕒 Nenhuma movimentação registrada ainda."]


def test_comando_eventos_faz_fallback_para_mac_sem_hostname(monkeypatch):
    messages = []
    monkeypatch.setattr(
        telegram_bot,
        "obter_eventos_recentes",
        lambda **kwargs: [{
            "event": "ENTROU",
            "device_name": None,
            "mac_address": "02:11:22:33:44:55",
            "ip_address": "192.0.2.10",
            "timestamp": "2026-01-01T12:05:00",
            "mac_randomizado": 1,
        }],
    )
    monkeypatch.setattr(
        telegram_bot,
        "enviar_mensagem",
        lambda chat_id, text, **kwargs: messages.append(text),
    )

    telegram_bot.processar_comando("/eventos", 123)

    assert "02:11:22:33:44:55" in messages[0]
    assert "MAC possivelmente rotativo" in messages[0]
