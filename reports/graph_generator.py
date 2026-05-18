"""
InfraInsight — graph_generator.py
Gera gráficos matplotlib e os salva como PNG em reports/graficos/
para serem embutidos nos relatórios PDF.
"""

import os
import matplotlib
matplotlib.use('Agg')  # backend sem interface gráfica
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from datetime import datetime

# Paleta visual do InfraInsight
CORES = {
    'gateway':           '#1D9E75',
    'computador_conhecido': '#378ADD',
    'switch_infra':      '#534AB7',
    'smarttv_streaming': '#EF9F27',
    'iot_rede':          '#D85A30',
    'camera':            '#A32D2D',
    'impressora':        '#0F6E56',
    'mac_randomizado':   '#888780',
    'desconhecido':      '#E24B4A',
}

RISCO_CORES = ['#1D9E75', '#378ADD', '#EF9F27', '#D85A30', '#E24B4A']
RISCO_LABELS = ['1', '2', '3', '4', '5']

FUNDO    = '#0D1117'
TEXTO    = '#E6EDF3'
GRADE    = '#21262D'
BORDA    = '#30363D'


def _estilo_escuro(fig, ax):
    """Aplica tema escuro consistente com a identidade InfraInsight."""
    fig.patch.set_facecolor(FUNDO)
    ax.set_facecolor(FUNDO)
    ax.tick_params(colors=TEXTO, labelsize=9)
    ax.spines['bottom'].set_color(BORDA)
    ax.spines['left'].set_color(BORDA)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.yaxis.label.set_color(TEXTO)
    ax.xaxis.label.set_color(TEXTO)
    ax.title.set_color(TEXTO)
    ax.yaxis.set_tick_params(color=BORDA)
    ax.xaxis.set_tick_params(color=BORDA)
    ax.set_axisbelow(True)
    ax.yaxis.grid(True, color=GRADE, linewidth=0.5)


def _pasta_graficos():
    pasta = os.path.join('reports', 'graficos')
    os.makedirs(pasta, exist_ok=True)
    return pasta


def gerar_pizza_tipos(dispositivos: list, timestamp: str) -> str:
    """
    Gráfico de pizza: distribuição por tipo de dispositivo.
    Retorna o caminho do arquivo PNG salvo.
    """
    contagem = {}
    for d in dispositivos:
        tipo = d.get('tipo', 'desconhecido')
        contagem[tipo] = contagem.get(tipo, 0) + 1

    if not contagem:
        return ''

    labels  = list(contagem.keys())
    valores = list(contagem.values())
    cores   = [CORES.get(t, '#888780') for t in labels]
    labels_formatados = [l.replace('_', ' ').title() for l in labels]

    fig, ax = plt.subplots(figsize=(6, 4.5))
    fig.patch.set_facecolor(FUNDO)
    ax.set_facecolor(FUNDO)

    wedges, texts, autotexts = ax.pie(
        valores,
        labels=None,
        colors=cores,
        autopct=lambda p: f'{p:.1f}%' if p > 4 else '',
        startangle=140,
        wedgeprops={'linewidth': 1.2, 'edgecolor': FUNDO},
        pctdistance=0.75,
    )
    for at in autotexts:
        at.set_color(TEXTO)
        at.set_fontsize(8)
        at.set_fontweight('bold')

    # Legenda lateral
    patches = [mpatches.Patch(color=cores[i], label=f'{labels_formatados[i]} ({valores[i]})')
               for i in range(len(labels))]
    leg = ax.legend(handles=patches, loc='center left', bbox_to_anchor=(1.0, 0.5),
                    fontsize=8, frameon=True)
    leg.get_frame().set_facecolor('#161B22')
    leg.get_frame().set_edgecolor(BORDA)
    for text in leg.get_texts():
        text.set_color(TEXTO)

    ax.set_title('Distribuição por tipo de dispositivo', color=TEXTO, fontsize=11,
                 pad=12, fontweight='bold')

    plt.tight_layout()
    caminho = os.path.join(_pasta_graficos(), f'pizza_tipos_{timestamp}.png')
    plt.savefig(caminho, dpi=150, bbox_inches='tight', facecolor=FUNDO)
    plt.close()
    return caminho


def gerar_barras_risco(dispositivos: list, timestamp: str) -> str:
    """
    Gráfico de barras: quantidade de dispositivos por nível de risco (1–5).
    Retorna o caminho do arquivo PNG salvo.
    """
    contagem = {i: 0 for i in range(1, 6)}
    for d in dispositivos:
        r = d.get('risco', 3)
        if isinstance(r, (int, float)):
            nivel = min(5, max(1, int(r)))
            contagem[nivel] += 1

    fig, ax = plt.subplots(figsize=(5.5, 3.5))
    _estilo_escuro(fig, ax)

    barras = ax.bar(
        RISCO_LABELS,
        [contagem[i] for i in range(1, 6)],
        color=RISCO_CORES,
        width=0.55,
        edgecolor=FUNDO,
        linewidth=1.2,
    )

    # Rótulo sobre cada barra
    for barra in barras:
        h = barra.get_height()
        if h > 0:
            ax.text(barra.get_x() + barra.get_width() / 2, h + 0.08,
                    str(int(h)), ha='center', va='bottom',
                    color=TEXTO, fontsize=9, fontweight='bold')

    ax.set_xlabel('Nível de risco', fontsize=9, color=TEXTO)
    ax.set_ylabel('Qtd. dispositivos', fontsize=9, color=TEXTO)
    ax.set_title('Dispositivos por nível de risco', color=TEXTO, fontsize=11,
                 pad=10, fontweight='bold')
    ax.set_ylim(0, max(contagem.values(), default=1) + 1.5)

    plt.tight_layout()
    caminho = os.path.join(_pasta_graficos(), f'barras_risco_{timestamp}.png')
    plt.savefig(caminho, dpi=150, bbox_inches='tight', facecolor=FUNDO)
    plt.close()
    return caminho


def gerar_evolucao_temporal(historico: list, timestamp: str) -> str:
    """
    Gráfico de linha: evolução do número de dispositivos detectados por scan.
    historico: lista de dicts com 'data' e 'total_dispositivos'
    Retorna o caminho do arquivo PNG salvo.
    """
    if not historico or len(historico) < 2:
        return ''

    datas  = [h.get('data', '')[:16] for h in historico]
    totais = [h.get('total_dispositivos', 0) for h in historico]

    fig, ax = plt.subplots(figsize=(7, 3.5))
    _estilo_escuro(fig, ax)

    ax.plot(range(len(datas)), totais,
            color='#378ADD', linewidth=2, marker='o',
            markersize=5, markerfacecolor='#378ADD', markeredgecolor=FUNDO)

    ax.fill_between(range(len(datas)), totais, alpha=0.15, color='#378ADD')

    # Rótulos no eixo X (últimos 8 para não poluir)
    step = max(1, len(datas) // 8)
    ax.set_xticks(range(0, len(datas), step))
    ax.set_xticklabels([datas[i] for i in range(0, len(datas), step)],
                       rotation=30, ha='right', fontsize=7, color=TEXTO)
    ax.set_ylabel('Total de dispositivos', fontsize=9, color=TEXTO)
    ax.set_title('Evolução de dispositivos detectados', color=TEXTO, fontsize=11,
                 pad=10, fontweight='bold')

    plt.tight_layout()
    caminho = os.path.join(_pasta_graficos(), f'evolucao_{timestamp}.png')
    plt.savefig(caminho, dpi=150, bbox_inches='tight', facecolor=FUNDO)
    plt.close()
    return caminho


def gerar_todos(dispositivos: list, historico: list, timestamp: str = None) -> dict:
    """
    Gera todos os gráficos de uma vez.
    Retorna dict com os caminhos dos PNGs gerados.
    """
    if not timestamp:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    return {
        'pizza':   gerar_pizza_tipos(dispositivos, timestamp),
        'barras':  gerar_barras_risco(dispositivos, timestamp),
        'evolucao': gerar_evolucao_temporal(historico, timestamp),
    }
