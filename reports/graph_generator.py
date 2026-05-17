import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

def gerar_graficos(dados):
    os.makedirs("reports/graficos", exist_ok=True)

    # Tipos
    tipos = {}
    for d in dados["dispositivos"]:
        tipo = d["tipo"]
        tipos[tipo] = tipos.get(tipo, 0) + 1

    # Pizza
    plt.figure(figsize=(8, 8))
    plt.pie(tipos.values(), labels=tipos.keys(), autopct="%1.1f%%")
    plt.title("Distribuição por Tipo de Dispositivo")
    plt.savefig("reports/graficos/dispositivos_pizza.png")
    plt.close()

    # Risco
    ips = [d["ip"] for d in dados["dispositivos"]]
    riscos = [d["risco"] for d in dados["dispositivos"]]

    plt.figure(figsize=(10, 5))
    plt.bar(ips, riscos)
    plt.title("Risco por Dispositivo")
    plt.ylabel("Risco")
    plt.savefig("reports/graficos/risco_barras.png")
    plt.close()
