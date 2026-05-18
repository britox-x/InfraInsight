import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def gerar_graficos(dados):
    os.makedirs("reports/graficos", exist_ok=True)

    # =========================
    # Distribuição por tipo
    # =========================
    tipos = {}

    for d in dados["dispositivos"]:
        tipo = d["tipo"]
        tipos[tipo] = tipos.get(tipo, 0) + 1

    plt.figure(figsize=(10, 10))

    plt.pie(
        tipos.values(),
        labels=tipos.keys(),
        autopct="%1.1f%%",
        startangle=90
    )

    plt.title("Distribuição por Tipo de Dispositivo")

    plt.tight_layout()

    plt.savefig(
        "reports/graficos/dispositivos_pizza.png",
        bbox_inches="tight",
        pad_inches=0.8
    )

    plt.close()

    # =========================
    # Risco por dispositivo
    # =========================
    ips = [d["ip"] for d in dados["dispositivos"]]
    riscos = [d["risco"] for d in dados["dispositivos"]]

    plt.figure(figsize=(12, 6))

    plt.bar(ips, riscos)

    plt.title("Risco por Dispositivo")
    plt.ylabel("Risco")
    plt.xlabel("IP")

    plt.tight_layout()

    plt.savefig(
        "reports/graficos/risco_barras.png",
        bbox_inches="tight",
        pad_inches=0.5
    )

    plt.close()
