#!/usr/bin/env python3
# core/wifi_scanner.py - Scanner Wi-Fi com iwlist/aircrack-ng

import subprocess
import re
import os

def verificar_aircrack():
    """Verifica se aircrack-ng está instalado"""
    try:
        result = subprocess.run(['which', 'aircrack-ng'], capture_output=True, text=True)
        return result.returncode == 0
    except:
        return False

def listar_interfaces_wifi():
    """Lista interfaces Wi-Fi disponíveis"""
    try:
        result = subprocess.run(['iwconfig'], capture_output=True, text=True)
        interfaces = []
        for line in result.stdout.split('\n'):
            if 'IEEE 802.11' in line:
                intf = line.split()[0]
                interfaces.append(intf)
        return interfaces
    except:
        return []

def scan_wifi_com_iwlist(interface='wlo1'):
    """Scan Wi-Fi usando iwlist (mais simples, não requer modo monitor)"""
    try:
        print(f"   📡 Escaneando com {interface}...")
        
        result = subprocess.run(['sudo', 'iwlist', interface, 'scan'], 
                                capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            print(f"   ⚠️ Erro: {result.stderr[:100]}")
            return []
        
        # Verificar se tem resultado
        if "No scan results" in result.stdout:
            print("   ⚠️ Nenhum resultado de scan.")
            return []
        
        redes = []
        # Dividir por células
        cells = result.stdout.split('Cell ')
        
        for cell in cells[1:]:  # Pular primeiro item vazio
            # Extrair BSSID (MAC)
            bssid_match = re.search(r'Address: ([0-9A-F:]+)', cell, re.IGNORECASE)
            
            # Extrair ESSID (nome da rede)
            ssid_match = re.search(r'ESSID:"([^"]*)"', cell)
            
            # Extrair qualidade do sinal
            quality_match = re.search(r'Quality[=:]\s*(\d+)/(\d+)', cell)
            
            # Extrair canal
            channel_match = re.search(r'Channel:(\d+)', cell)
            
            # Verificar se é criptografada
            encrypted_match = re.search(r'Encryption key:(\w+)', cell)
            
            if bssid_match:
                ssid = ssid_match.group(1) if ssid_match else 'Oculta'
                # Ignorar redes ocultas sem nome
                if ssid or ssid == 'Oculta':
                    qualidade = None
                    if quality_match:
                        qualidade = f"{quality_match.group(1)}/{quality_match.group(2)}"
                    
                    # Calcular porcentagem de sinal
                    sinal_percent = None
                    if quality_match:
                        try:
                            sinal = int(quality_match.group(1)) / int(quality_match.group(2)) * 100
                            sinal_percent = f"{sinal:.0f}%"
                        except:
                            pass
                    
                    redes.append({
                        'bssid': bssid_match.group(1),
                        'ssid': ssid if ssid else 'Oculta',
                        'channel': channel_match.group(1) if channel_match else '?',
                        'quality': qualidade,
                        'sinal': sinal_percent,
                        'encrypted': encrypted_match.group(1) == 'on' if encrypted_match else True
                    })
        
        return redes
    except subprocess.TimeoutExpired:
        print(f"   ⏰ Timeout no scan Wi-Fi")
        return []
    except Exception as e:
        print(f"   ⚠️ Erro no scan Wi-Fi: {e}")
        return []

def scan_wifi_avancado(interface='wlo1', timeout=15):
    """Scan Wi-Fi avançado com aircrack (requer modo monitor)"""
    if not verificar_aircrack():
        return []
    
    redes = []
    try:
        # Verificar se pode iniciar modo monitor
        check = subprocess.run(['sudo', 'airmon-ng', 'start', interface], 
                               capture_output=True, text=True)
        
        if 'mon' in check.stdout:
            mon_interface = interface + 'mon'
            
            # Escanear
            process = subprocess.Popen(
                ['sudo', 'airodump-ng', mon_interface],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True
            )
            
            import time
            time.sleep(timeout)
            process.terminate()
            
            # Parar modo monitor
            subprocess.run(['sudo', 'airmon-ng', 'stop', mon_interface], 
                          capture_output=True)
            
    except Exception as e:
        print(f"   ⚠️ Scan avançado falhou: {e}")
    
    return redes

def scan_wifi_simples():
    """Scan Wi-Fi simplificado - tenta detectar automaticamente"""
    interfaces = listar_interfaces_wifi()
    
    if not interfaces:
        return []
    
    # Usar primeira interface Wi-Fi encontrada
    interface = interfaces[0]
    print(f"   📡 Usando interface: {interface}")
    
    return scan_wifi_com_iwlist(interface)

def scan_wifi_nmcli():
    """Scan Wi-Fi usando nmcli (NetworkManager) - alternativa mais rápida"""
    try:
        result = subprocess.run(['nmcli', 'device', 'wifi', 'list'], 
                                capture_output=True, text=True, timeout=15)
        
        if result.returncode != 0:
            return []
        
        redes = []
        lines = result.stdout.split('\n')[1:]  # Pular cabeçalho
        
        for line in lines:
            if line.strip():
                parts = line.split()
                if len(parts) >= 8:
                    redes.append({
                        'ssid': ' '.join(parts[7:]) if len(parts) > 7 else parts[7],
                        'bssid': parts[0] if len(parts) > 0 else '?',
                        'channel': parts[3] if len(parts) > 3 else '?',
                        'quality': f"{parts[1]}/{parts[2]}" if len(parts) > 2 else '?',
                        'encrypted': parts[5] != '--' if len(parts) > 5 else True
                    })
        
        return redes
    except Exception as e:
        return []

# Teste rápido
if __name__ == "__main__":
    print("="*50)
    print("🔍 Wi-Fi Scanner")
    print("="*50)
    
    interfaces = listar_interfaces_wifi()
    print(f"📡 Interfaces Wi-Fi: {interfaces}")
    
    if interfaces:
        print("\n📶 Redes Wi-Fi próximas:")
        redes = scan_wifi_simples()
        if redes:
            for rede in redes[:15]:
                encrypted = "🔒" if rede['encrypted'] else "🌐"
                print(f"   {encrypted} {rede['ssid']} - {rede['bssid']} (Canal {rede['channel']}) Sinal: {rede.get('sinal', 'N/A')}")
        else:
            print("   Nenhuma rede encontrada")
    else:
        print("❌ Nenhuma interface Wi-Fi encontrada")
