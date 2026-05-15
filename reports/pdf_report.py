from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from datetime import datetime
import os


def gerar_pdf(dados):
    os.makedirs("reports", exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    arquivo = f"reports/relatorio_{timestamp}.pdf"

    c = canvas.Canvas(arquivo, pagesize=A4)

    y = 800

    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y, "InfraInsight - Relatório de Rede")

    y -= 40
    c.setFont("Helvetica", 10)

    resumo = [
        f"Timestamp: {dados['timestamp']}",
        f"Ambiente: {dados['ambiente']}",
        f"Wi-Fi: {dados['wifi']}",
        f"Subrede: {dados['subrede']}",
        f"Gateway: {dados['gateway']}",
        f"IPs ativos: {dados['ips_ativos']}",
        f"Uso da rede: {dados['uso']}%",
        f"Risco médio: {dados['risco_medio']}/10",
        f"Dispositivos desconhecidos: {dados['desconhecidos']}",
        f"MACs randomizados: {dados['mac_randomizados']}",
        f"Novos dispositivos: {dados['novos_dispositivos']}",
        f"Recomendação: {dados['recomendacao']}",
    ]

    for linha in resumo:
        c.drawString(50, y, linha)
        y -= 18

    y -= 20
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Dispositivos detectados:")

    y -= 20
    c.setFont("Helvetica", 9)

    for d in dados["dispositivos"]:
        linha = (
            f"{d['ip']} | {d['fabricante']} | "
            f"{d['mac']} | {d['tipo']} | "
            f"Risco {d['risco']}/10"
        )

        if y < 50:
            c.showPage()
            y = 800
            c.setFont("Helvetica", 9)

        c.drawString(50, y, linha[:110])
        y -= 15

    c.save()

    print(f"PDF salvo em: {arquivo}")
