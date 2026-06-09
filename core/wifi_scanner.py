#!/usr/bin/env python3
# core/wifi_scanner.py - Scanner Wi-Fi

import subprocess
import re

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

def scan_wifi_simples():
    """Scan Wi-Fi simplificado"""
    interfaces = listar_interfaces_wifi()
    if not interfaces:
        return []
    
    interface = interfaces[0]
    print(f"   📡 Usando interface: {interface}")
    
# CERTIFIQUE-SE QUE ESTÁ ASSIM (sem TABs, apenas espaços)
    try:
        result = subprocess.run(['iwlist', interface, 'scan'],
                                capture_output=True, text=True, timeout=timeout)

        
        if result.returncode != 0:
            if "Device or resource busy" in result.stderr:
                print(f"   ⚠️ Interface ocupada, tentando novamente...")
                import time
                time.sleep(2)
                result = subprocess.run(['sudo', 'iwlist', interface, 'scan'], 
                                        capture_output=True, text=True, timeout=30)
                if result.returncode != 0:
                    return []
            else:
                return []
        
        if "No scan results" in result.stdout:
            return []
        
        redes = []
        cells = result.stdout.split('Cell ')
        
        for cell in cells[1:]:
            bssid_match = re.search(r'Address: ([0-9A-F:]+)', cell, re.IGNORECASE)
            ssid_match = re.search(r'ESSID:"([^"]*)"', cell)
            quality_match = re.search(r'Quality[=:]\s*(\d+)/(\d+)', cell)
            channel_match = re.search(r'Channel:(\d+)', cell)
            
            if bssid_match:
                ssid = ssid_match.group(1) if ssid_match else 'Oculta'
                qualidade = None
                sinal_percent = None
                if quality_match:
                    qualidade = f"{quality_match.group(1)}/{quality_match.group(2)}"
                    try:
                        sinal = int(quality_match.group(1)) / int(quality_match.group(2)) * 100
                        sinal_percent = f"{sinal:.0f}%"
                    except:
                        pass
                
                redes.append({
                    'bssid': bssid_match.group(1),
                    'ssid': ssid,
                    'channel': channel_match.group(1) if channel_match else '?',
                    'quality': qualidade,
                    'sinal': sinal_percent,
                    'encrypted': True
                })
        
        return redes
    except Exception as e:
        print(f"   ⚠️ Erro: {e}")
        return []

def scan_wifi_nmcli():
    """Scan Wi-Fi alternativo usando nmcli"""
    try:
        result = subprocess.run(['nmcli', '-t', '-f', 'SSID,BSSID,CHAN,SIGNAL', 'device', 'wifi', 'list'],
                                capture_output=True, text=True, timeout=15)
        
        if result.returncode != 0:
            return []
        
        redes = []
        for line in result.stdout.strip().split('\n'):
            if line and ':' in line:
                parts = line.split(':')
                if len(parts) >= 4:
                    redes.append({
                        'ssid': parts[0] if parts[0] else 'Oculta',
                        'bssid': parts[1] if len(parts) > 1 else '?',
                        'channel': parts[2] if len(parts) > 2 else '?',
                        'sinal': f"{parts[3]}%" if len(parts) > 3 and parts[3] else 'N/A',
                        'encrypted': True
                    })
        return redes
    except:
        return []

def scan_wifi_completo(interface=None, timeout=15):
    """
    Scan Wi-Fi completo com mais informações (sinal em texto, tipo de segurança)
    """
    if interface is None:
        interfaces = listar_interfaces_wifi()
        if not interfaces:
            return []
        interface = interfaces[0]
    
    print(f"   📡 Escaneando Wi-Fi em {interface}...")
    
    try:
        result = subprocess.run(['sudo', 'iwlist', interface, 'scan'], 
                                capture_output=True, text=True, timeout=timeout)
        
        if result.returncode != 0:
            return []
        
        if "No scan results" in result.stdout:
            return []
        
        redes = []
        cells = result.stdout.split('Cell ')
        
        for cell in cells[1:]:
            bssid_match = re.search(r'Address: ([0-9A-F:]+)', cell, re.IGNORECASE)
            ssid_match = re.search(r'ESSID:"([^"]*)"', cell)
            quality_match = re.search(r'Quality[=:]\s*(\d+)/(\d+)', cell)
            channel_match = re.search(r'Channel:(\d+)', cell)
            encryption_match = re.search(r'Encryption key:(\w+)', cell)
            
            if bssid_match:
                ssid = ssid_match.group(1) if ssid_match else 'Rede Oculta'
                qualidade = None
                sinal_percent = None
                
                if quality_match:
                    qualidade = f"{quality_match.group(1)}/{quality_match.group(2)}"
                    try:
                        sinal = int(quality_match.group(1)) / int(quality_match.group(2)) * 100
                        sinal_percent = f"{sinal:.0f}%"
                    except:
                        pass
                
                # Classificar força do sinal para texto amigável
                if sinal_percent:
                    sinal_num = int(sinal_percent.replace('%', ''))
                    if sinal_num >= 70:
                        sinal_texto = "📶📶📶 Excelente"
                    elif sinal_num >= 40:
                        sinal_texto = "📶📶 Bom"
                    elif sinal_num >= 20:
                        sinal_texto = "📶 Fraco"
                    else:
                        sinal_texto = "📶 Muito fraco"
                else:
                    sinal_texto = "📶 Desconhecido"
                
                # Tipo de segurança
                if encryption_match:
                    encryption_type = 'WPA2' if encryption_match.group(1) == 'on' else 'Aberta'
                else:
                    encryption_type = 'Desconhecida'
                
                redes.append({
                    'bssid': bssid_match.group(1),
                    'ssid': ssid,
                    'channel': channel_match.group(1) if channel_match else '?',
                    'quality': qualidade,
                    'sinal': sinal_percent,
                    'sinal_texto': sinal_texto,
                    'encrypted': encryption_match.group(1) == 'on' if encryption_match else True,
                    'encryption_type': encryption_type
                })
        
        return redes
    except Exception as e:
        print(f"   ⚠️ Erro no scan Wi-Fi: {e}")
        return []

if __name__ == "__main__":
    print("🔍 Wi-Fi Scanner Test")
    interfaces = listar_interfaces_wifi()
    print(f"Interfaces: {interfaces}")
    if interfaces:
        redes = scan_wifi_simples()
        for rede in redes[:10]:
            print(f"  {rede['ssid']} - {rede['bssid']} ({rede.get('sinal', 'N/A')})")
