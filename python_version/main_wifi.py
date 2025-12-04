#!/usr/bin/env python3
"""
WiFi Interactive Terminal Tool - Versión Mejorada
Adaptado para usar adaptador WiFi BrosTrend AC1200 AC3L
Con mejoras de interfaz, performance y funcionalidades adicionales
"""

import sys
import os
import time
import select
import pickle
import signal
import queue
import threading
from typing import Optional, List
from collections import deque

# Intentar importar readline (no disponible en Windows por defecto)
try:
    import readline
    READLINE_AVAILABLE = True
except ImportError:
    READLINE_AVAILABLE = False

# Importar módulos locales
import config_wifi as config
import utils
from wifi_driver import WiFiDriver, WiFiNetwork, WiFiPacket

# Comandos abreviados
COMMAND_ABBREVIATIONS = {
    's': 'scan',
    't': 'tx',
    'r': 'rx',
    'j': 'jam',
    'j24': 'jam 2.4',
    'j5': 'jam 5',
    'ja': 'jam all',
    'c': 'chat',
    'st': 'status',
    'h': 'help',
    'q': 'quit',
    'x': 'x',
    'w': 'wifiscan',
    'f': 'filter',
    'e': 'export',
}


class CommandHistory:
    """Maneja historial de comandos"""
    def __init__(self, max_size=100):
        self.history = deque(maxlen=max_size)
        self.current_index = -1
        self.setup_readline()
    
    def setup_readline(self):
        """Configura readline para historial y autocompletado"""
        if sys.platform != 'win32' and READLINE_AVAILABLE:
            try:
                # Historial de archivo
                histfile = os.path.join(os.path.expanduser("~"), ".wifi_jammer_history")
                try:
                    readline.read_history_file(histfile)
                except FileNotFoundError:
                    pass
                
                # Configurar readline
                readline.set_history_length(100)
                readline.parse_and_bind("tab: complete")
                readline.set_completer(self.completer)
            except Exception:
                # Si falla, continuar sin readline
                pass
    
    def completer(self, text, state):
        """Autocompletado de comandos"""
        commands = [
            'setchannel', 'setband', 'getrssi', 'scan', 'wifiscan',
            'rx', 'tx', 'jam', 'rec', 'add', 'show', 'flush', 'play',
            'rxraw', 'recraw', 'playraw', 'showraw', 'showbit', 'addraw',
            'save', 'load', 'echo', 'chat', 'x', 'init', 'help', 'status',
            'filter', 'export', 'quit'
        ]
        
        matches = [cmd for cmd in commands if cmd.startswith(text)]
        
        if state < len(matches):
            return matches[state]
        return None
    
    def add(self, command):
        """Añade comando al historial"""
        if command and command.strip():
            self.history.append(command.strip())
            if sys.platform != 'win32' and READLINE_AVAILABLE:
                try:
                    readline.add_history(command.strip())
                except Exception:
                    pass
    
    def save(self):
        """Guarda historial a archivo"""
        if sys.platform != 'win32' and READLINE_AVAILABLE:
            try:
                histfile = os.path.join(os.path.expanduser("~"), ".wifi_jammer_history")
                readline.write_history_file(histfile)
            except Exception:
                pass


class WiFiTerminal:
    """Terminal interactivo mejorado para controlar WiFi"""
    
    def __init__(self):
        """Inicializa el terminal WiFi"""
        # Estado de modos
        self.receiving_mode = False
        self.jamming_mode = False
        self.recording_mode = False
        self.chat_mode = False
        
        # Buffers
        self.cc_receiving_buffer = bytearray(config.CCBUFFERSIZE)
        self.cc_sending_buffer = bytearray(config.CCBUFFERSIZE)
        self.big_recording_buffer = bytearray(config.RECORDINGBUFFERSIZE)
        self.big_recording_buffer_pos = 0
        self.frames_in_buffer = 0
        
        # Configuración
        self.do_echo = True
        self.rxraw_active = False
        self.scan_active = False
        
        # Historial
        self.history = CommandHistory()
        
        # Filtros
        self.filter_bssid = None
        self.filter_ssid = None
        self.filter_type = None
        
        # Inicializar WiFi
        print("Inicializando adaptador WiFi...")
        try:
            self.wifi = WiFiDriver(interface=config.WIFI_INTERFACE)
            
            # Activar modo monitor
            if not self.wifi.set_monitor_mode(True):
                print("ADVERTENCIA: No se pudo activar modo monitor. Algunas funciones pueden no funcionar.")
                print("Asegúrate de ejecutar con sudo y que aircrack-ng esté instalado.")
            
            # Configurar canal por defecto
            self.wifi.set_channel(config.DEFAULT_CHANNEL)
            print(f"WiFi inicializado correctamente en canal {config.DEFAULT_CHANNEL}.\n")
        
        except Exception as e:
            print(f"ERROR: No se pudo inicializar WiFi: {e}")
            print("Verifica que el adaptador esté conectado y que tengas permisos.")
            sys.exit(1)
        
        # Registrar manejador de señales para cleanup
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Maneja señales del sistema para cleanup seguro"""
        print("\n\r\nRecibida señal de interrupción. Limpiando...")
        self.cleanup()
        sys.exit(0)
    
    def print_help(self):
        """Muestra la ayuda de comandos mejorada"""
        help_text = """
COMANDOS BÁSICOS:
=================
setchannel <channel>  : Cambiar canal WiFi (2.4GHz: 1-14, 5GHz: 36-165)
setband <band>        : Cambiar banda ("2.4" o "5")
getrssi               : Mostrar RSSI del último paquete
status                : Mostrar estado y estadísticas actuales

ESCANEO:
========
scan <start> <stop>   : Escanear rango de canales por señal
wifiscan [duration]   : Escanear y listar redes WiFi (default: 3 seg)

RECEPCIÓN/TRANSMISIÓN:
======================
rx                    : Activar/desactivar recepción de paquetes
tx <hex-vals>         : Enviar paquete WiFi (hex)
jam [opciones]        : Activar/desactivar jamming WiFi
                       - jam: Canal actual
                       - jam <canal>: Canal específico (ej: jam 6)
                       - jam 2.4: Todos los canales 2.4 GHz (1-14)
                       - jam 5: Todos los canales 5 GHz (36-165)
                       - jam all: Todos los canales (2.4 y 5 GHz)
                       - jam <bssid>: Red específica en canal actual
                       - jam <canal> <bssid>: Red específica en canal
                       - jam 2.4 <bssid>: Red en todos los canales 2.4 GHz
                       - jam 5 <bssid>: Red en todos los canales 5 GHz
                       - jam all <bssid>: Red en todos los canales
chat                  : Modo chat (envío/recepción de texto)

GRABACIÓN:
==========
rec                   : Activar/desactivar grabación de paquetes
add <hex-vals>        : Añadir paquete manualmente al buffer
show                  : Mostrar contenido del buffer de grabación
flush                 : Limpiar buffer de grabación
play <N>              : Reproducir todos (0) o N-ésimo paquete grabado

RAW MODE:
=========
rxraw <microseconds>  : Sniffer RAW con intervalo
recraw <microseconds> : Grabar RAW con intervalo
playraw <microseconds>: Reproducir RAW grabado
showraw               : Mostrar buffer en formato RAW
showbit               : Mostrar buffer como bits

ARCHIVOS:
=========
save                  : Guardar buffer a archivo
load                  : Cargar buffer desde archivo
export <file>         : Exportar paquetes a PCAP (Wireshark)

FILTROS:
========
filter bssid <mac>    : Filtrar por BSSID/MAC
filter ssid <name>    : Filtrar por SSID
filter type <type>    : Filtrar por tipo (beacon, data, etc.)
filter clear          : Limpiar filtros

OTROS:
======
echo <0|1>            : Activar/desactivar echo
init                  : Reinicializar adaptador WiFi
x                     : Detener todas las operaciones activas
quit                  : Salir
help                  : Mostrar esta ayuda

COMANDOS ABREVIADOS:
====================
s, t, r, j, j24, j5, ja, c, st, h, q, x, w, f, e
  - j24: jam 2.4 (banda 2.4 GHz)
  - j5: jam 5 (banda 5 GHz)
  - ja: jam all (todas las bandas)

NOTA: Comandos de CC1101 (setmhz, setmodulation, etc.) se adaptan automáticamente.
"""
        print(help_text)
    
    def expand_command(self, cmdline: str) -> str:
        """Expande comandos abreviados"""
        parts = cmdline.strip().split(None, 1)
        if not parts:
            return cmdline
        
        cmd = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""
        
        # Expandir abreviatura
        if cmd in COMMAND_ABBREVIATIONS:
            full_cmd = COMMAND_ABBREVIATIONS[cmd]
            # Si el comando expandido ya tiene argumentos, no agregar args adicionales
            if ' ' in full_cmd:
                return full_cmd
            return f"{full_cmd} {args}".strip()
        
        return cmdline
    
    def _freq_to_channel(self, freq_mhz: float) -> int:
        """Convierte frecuencia MHz a canal WiFi (aproximado)"""
        if 2400 <= freq_mhz <= 2500:
            channel = int((freq_mhz - 2407) / 5) + 1
            if channel < 1:
                channel = 1
            elif channel > 14:
                channel = 14
            return channel
        elif 5000 <= freq_mhz <= 6000:
            channel = int((freq_mhz - 5000) / 5) + 36
            if channel < 36:
                channel = 36
            elif channel > 165:
                channel = 165
            return channel
        else:
            return config.DEFAULT_CHANNEL
    
    def exec_command(self, cmdline: str):
        """Ejecuta un comando (mejorado)"""
        if not cmdline.strip():
            return
        
        # Expandir abreviatura
        cmdline = self.expand_command(cmdline)
        
        # Añadir al historial
        self.history.add(cmdline)
        
        parts = cmdline.strip().split(None, 1)
        if not parts:
            return
        
        command = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""
        
        try:
            # Mapear comandos antiguos a nuevos
            if command == "setmhz":
                freq = float(args)
                channel = self._freq_to_channel(freq)
                command = "setchannel"
                args = str(channel)
                print(f"NOTA: Frecuencia {freq} MHz mapeada a canal WiFi {channel}\r\n")
            
            if command == "help" or command == "h":
                self.print_help()
            
            elif command == "status" or command == "st":
                self._cmd_status()
            
            elif command == "setchannel":
                if not args:
                    print(f"Canal actual: {self.wifi.get_channel()}\r\n")
                else:
                    channel = int(args)
                    if self.wifi.set_channel(channel):
                        print(f"\r\nWiFi Channel: {channel}\r\n")
                    else:
                        print("Error: Canal inválido. Use 1-14 para 2.4GHz o 36-165 para 5GHz\r\n")
            
            elif command == "setband":
                band = args.strip()
                if band in ["2.4", "5"]:
                    self.wifi.current_band = band
                    print(f"\r\nWiFi Band: {band} GHz\r\n")
                else:
                    print("Error: Banda debe ser '2.4' o '5'\r\n")
            
            elif command == "getrssi":
                rssi = self.wifi.get_rssi()
                print(f"RSSI: {rssi} dBm\r\n")
            
            elif command == "scan":
                parts = args.split()
                if len(parts) >= 2:
                    start_ch = int(float(parts[0]))
                    end_ch = int(float(parts[1]))
                    self._cmd_scan_wifi(start_ch, end_ch)
                else:
                    print("Error: Parámetros incorrectos. Use: scan <canal_inicio> <canal_fin>\r\n")
            
            elif command == "wifiscan" or command == "w":
                duration = float(args) if args else 3.0
                self._cmd_wifiscan(duration)
            
            elif command == "rx" or command == "r":
                if self.receiving_mode:
                    self.receiving_mode = False
                    print("\r\nRecepción de paquetes WiFi: DESACTIVADA\r\n")
                else:
                    if not self.wifi.monitor_mode:
                        self.wifi.set_monitor_mode(True)
                    self.receiving_mode = True
                    self.jamming_mode = False
                    self.recording_mode = False
                    print("\r\nRecepción de paquetes WiFi: ACTIVADA\r\n")
            
            elif command == "tx" or command == "t":
                if not args:
                    print("Error: Parámetros incorrectos. Use: tx <hex-vals>\r\n")
                elif utils.validate_hex_string(args):
                    data = utils.hex_to_bytes(args)
                    print("\r\nTransmitiendo paquete WiFi...\r\n")
                    if self.wifi.send_packet(data):
                        hex_str = utils.bytes_to_hex(data)
                        print(f"Paquete enviado: {hex_str}\r\n")
                    else:
                        print("Error enviando paquete.\r\n")
                else:
                    print("Error: Cadena hexadecimal inválida.\r\n")
            
            elif command == "jam" or command == "j":
                if self.jamming_mode:
                    self.jamming_mode = False
                    self.wifi.stop_jamming()
                    print("\r\nJamming: DESACTIVADO\r\n")
                else:
                    self.jamming_mode = True
                    self.receiving_mode = False
                    if not self.wifi.monitor_mode:
                        self.wifi.set_monitor_mode(True)
                    
                    # Parsear argumentos
                    jam_mode = "channel"  # Por defecto: canal actual
                    bssid = None
                    channel = None
                    
                    if args:
                        args_lower = args.strip().lower()
                        parts = args.strip().split()
                        
                        # Detectar modo de jamming
                        if args_lower in ['all', 'full', 'todos', 'both']:
                            jam_mode = "all"
                        elif args_lower in ['2.4', '2.4ghz', 'band2.4', 'band_2_4']:
                            jam_mode = "band_2_4"
                        elif args_lower in ['5', '5ghz', 'band5', 'band_5']:
                            jam_mode = "band_5"
                        elif len(parts) > 0:
                            # Verificar si el primer argumento es un modo
                            first_arg = parts[0].lower()
                            if first_arg in ['all', 'full', 'todos', 'both']:
                                jam_mode = "all"
                                if len(parts) > 1:
                                    if len(parts[1]) == 17:
                                        bssid = parts[1]
                            elif first_arg in ['2.4', '2.4ghz', 'band2.4', 'band_2_4']:
                                jam_mode = "band_2_4"
                                if len(parts) > 1:
                                    if len(parts[1]) == 17:
                                        bssid = parts[1]
                            elif first_arg in ['5', '5ghz', 'band5', 'band_5']:
                                jam_mode = "band_5"
                                if len(parts) > 1:
                                    if len(parts[1]) == 17:
                                        bssid = parts[1]
                            elif len(parts[0]) == 17:
                                # Es un BSSID directamente
                                bssid = parts[0]
                            elif parts[0].isdigit():
                                # Es un canal específico
                                channel = int(parts[0])
                                jam_mode = "channel"
                                if len(parts) > 1 and len(parts[1]) == 17:
                                    bssid = parts[1]
                    
                    # Si no se especificó canal y el modo es "channel", usar canal actual
                    if jam_mode == "channel" and channel is None:
                        channel = self.wifi.current_channel
                    
                    # Iniciar jamming
                    success = self.wifi.start_jamming(target_bssid=bssid, channel=channel, jam_mode=jam_mode)
                    
                    if success:
                        mode_desc = {
                            "channel": f"Canal {channel}",
                            "band_2_4": "Banda 2.4 GHz (canales 1-14)",
                            "band_5": "Banda 5 GHz (canales 36-165)",
                            "all": "Todas las bandas (2.4 y 5 GHz)"
                        }
                        print(f"\r\nJamming: ACTIVADO en {mode_desc[jam_mode]} (BSSID: {bssid or 'Broadcast'})\r\n")
                    else:
                        self.jamming_mode = False
                        print("\r\nError activando jamming.\r\n")
            
            elif command == "rec":
                if self.recording_mode:
                    self.recording_mode = False
                    self.big_recording_buffer_pos = 0
                    print(f"\r\nGrabación desactivada. Frames almacenados: {self.frames_in_buffer}\r\n")
                else:
                    if not self.wifi.monitor_mode:
                        self.wifi.set_monitor_mode(True)
                    self.recording_mode = True
                    self.jamming_mode = False
                    self.receiving_mode = False
                    self.big_recording_buffer_pos = 0
                    self.frames_in_buffer = 0
                    self.big_recording_buffer = bytearray(config.RECORDINGBUFFERSIZE)
                    print("\r\nGrabación: ACTIVADA\r\n")
            
            elif command == "add":
                if not args or not utils.validate_hex_string(args):
                    print("Error: Parámetros incorrectos.\r\n")
                else:
                    data = utils.hex_to_bytes(args)
                    self._add_frame(data)
            
            elif command == "show":
                self._cmd_show()
            
            elif command == "flush":
                self.big_recording_buffer = bytearray(config.RECORDINGBUFFERSIZE)
                self.big_recording_buffer_pos = 0
                self.frames_in_buffer = 0
                print("\r\nBuffer de grabación limpiado.\r\n")
            
            elif command == "play":
                frame_num = int(args) if args else 0
                self._cmd_play(frame_num)
            
            elif command == "rxraw":
                if args:
                    usec = int(args)
                    if usec > 0:
                        self._cmd_rxraw_wifi(usec)
                    else:
                        print("Error: Parámetros incorrectos.\r\n")
                else:
                    print("Error: Parámetros incorrectos.\r\n")
            
            elif command == "recraw":
                if args:
                    usec = int(args)
                    if usec > 0:
                        print("\r\nGrabando datos RAW WiFi...\r\n")
                        self._cmd_recraw_wifi(usec)
                    else:
                        print("Error: Parámetros incorrectos.\r\n")
                else:
                    print("Error: Parámetros incorrectos.\r\n")
            
            elif command == "playraw":
                if args:
                    usec = int(args)
                    if usec > 0:
                        self._cmd_playraw_wifi(usec)
                    else:
                        print("Error: Parámetros incorrectos.\r\n")
                else:
                    print("Error: Parámetros incorrectos.\r\n")
            
            elif command == "showraw":
                self._cmd_showraw()
            
            elif command == "showbit":
                self._cmd_showbit()
            
            elif command == "addraw":
                if not args or not utils.validate_hex_string(args):
                    print("Error: Parámetros incorrectos.\r\n")
                else:
                    data = utils.hex_to_bytes(args)
                    self._add_raw(data)
            
            elif command == "save":
                self._cmd_save()
            
            elif command == "load":
                self._cmd_load()
            
            elif command == "export" or command == "e":
                if not args:
                    filename = f"wifi_capture_{int(time.time())}.pcap"
                else:
                    filename = args.strip()
                self._cmd_export_pcap(filename)
            
            elif command == "filter" or command == "f":
                self._cmd_filter(args)
            
            elif command == "echo":
                self.do_echo = bool(int(args)) if args else True
                status = "activado" if self.do_echo else "desactivado"
                print(f"Echo: {status}\r\n")
            
            elif command == "chat" or command == "c":
                self.chat_mode = True
                self.jamming_mode = False
                self.receiving_mode = False
                self.recording_mode = False
                print("\r\nModo chat activado (WiFi). Escribe mensajes directamente.\r\n\r\n")
            
            elif command == "x":
                self.receiving_mode = False
                self.jamming_mode = False
                self.recording_mode = False
                self.rxraw_active = False
                self.scan_active = False
                self.wifi.stop_jamming()
                print("\r\nTodas las operaciones detenidas.\r\n")
            
            elif command == "init":
                if not self.wifi.monitor_mode:
                    self.wifi.set_monitor_mode(True)
                self.wifi.set_channel(config.DEFAULT_CHANNEL)
                print("Adaptador WiFi reinicializado\r\n")
            
            elif command == "quit" or command == "q":
                print("\r\nSaliendo...\r\n")
                self.cleanup()
                sys.exit(0)
            
            # Comandos no implementados en WiFi (compatibilidad)
            elif command in ["setmodulation", "setdeviation", "setchsp", "setrxbw", 
                           "setdrate", "setpa", "setsyncmode", "setsyncword", "setadrchk",
                           "setaddr", "setwhitedata", "setpktformat", "setlengthconfig",
                           "setpacketlength", "setcrc", "setcrcaf", "setdcfilteroff",
                           "setmanchester", "setfec", "setpre", "setpqt", "setappendstatus",
                           "brute"]:
                print(f"NOTA: Comando '{command}' no aplicable para WiFi. Funcionalidad limitada.\r\n")
            
            else:
                print(f"Error: Comando desconocido: {command}. Use 'help' para ayuda.\r\n")
        
        except ValueError as e:
            print(f"Error: Valor inválido: {e}\r\n")
        except Exception as e:
            print(f"Error ejecutando comando: {e}\r\n")
    
    def _cmd_status(self):
        """Muestra estado y estadísticas"""
        stats = self.wifi.get_statistics()
        
        print("\r\n=== ESTADO DEL SISTEMA ===\r\n")
        print(f"Interfaz: {self.wifi.interface}")
        if self.wifi.monitor_interface:
            print(f"Modo Monitor: {self.wifi.monitor_interface}")
        print(f"Canal Actual: {self.wifi.current_channel} ({self.wifi.current_band} GHz)")
        print(f"RSSI Último: {self.wifi.get_rssi()} dBm")
        print()
        print("=== MODOS ACTIVOS ===")
        print(f"Recepción: {'ACTIVA' if self.receiving_mode else 'inactiva'}")
        print(f"Jamming: {'ACTIVO' if self.jamming_mode else 'inactivo'}")
        print(f"Grabación: {'ACTIVA' if self.recording_mode else 'inactiva'}")
        print(f"Chat: {'ACTIVO' if self.chat_mode else 'inactivo'}")
        print()
        print("=== ESTADÍSTICAS ===")
        print(f"Paquetes Recibidos: {stats['packets_received']}")
        print(f"Paquetes Enviados: {stats['packets_sent']}")
        print(f"Paquetes Perdidos: {stats['packets_dropped']}")
        print(f"Tasa: {stats['packets_per_second']:.2f} pps")
        print(f"Buffer: {stats['buffer_size']} paquetes")
        print(f"Redes Detectadas: {stats['networks_found']}")
        print()
        print("=== BUFFER GRABACIÓN ===")
        print(f"Frames almacenados: {self.frames_in_buffer}")
        print(f"Posición: {self.big_recording_buffer_pos}/{config.RECORDINGBUFFERSIZE}")
        print()
        
        # Filtros activos
        if self.filter_bssid or self.filter_ssid or self.filter_type:
            print("=== FILTROS ACTIVOS ===")
            if self.filter_bssid:
                print(f"BSSID: {self.filter_bssid}")
            if self.filter_ssid:
                print(f"SSID: {self.filter_ssid}")
            if self.filter_type:
                print(f"Tipo: {self.filter_type}")
            print()
        print()
    
    def _cmd_wifiscan(self, duration: float = 3.0):
        """Escanea y lista redes WiFi"""
        print(f"\r\nEscaneando redes WiFi (duración: {duration}s)...\r\n")
        
        networks = self.wifi.scan_networks(duration=duration)
        
        if networks:
            print(f"\r\n{'SSID':<30} {'BSSID':<18} {'Canal':<8} {'RSSI':<8} {'Último'}\r\n")
            print("-" * 80 + "\r\n")
            
            for net in networks[:20]:  # Mostrar máximo 20
                ssid = net.ssid[:28] if net.ssid else "<hidden>"
                bssid = net.bssid or "Unknown"
                channel = str(net.channel)
                rssi = f"{net.rssi} dBm"
                elapsed = int(time.time() - net.last_seen)
                
                print(f"{ssid:<30} {bssid:<18} {channel:<8} {rssi:<8} {elapsed}s\r\n")
            
            if len(networks) > 20:
                print(f"\r\n... y {len(networks) - 20} redes más.\r\n")
        else:
            print("No se encontraron redes WiFi.\r\n")
        
        print()
    
    def _cmd_scan_wifi(self, start_ch: int, end_ch: int):
        """Escanea canales WiFi mejorado"""
        print(f"\r\nEscaneando canales WiFi {start_ch} a {end_ch}...\r\n")
        self.scan_active = True
        
        results = []
        channels_to_scan = []
        
        # Construir lista de canales válidos a escanear
        for ch in range(start_ch, min(end_ch + 1, 165)):
            if ch in self.wifi.CHANNELS_2_4 or ch in self.wifi.CHANNELS_5:
                channels_to_scan.append(ch)
        
        if not channels_to_scan:
            print("Error: No hay canales válidos en el rango especificado.\r\n")
            self.scan_active = False
            return
        
        # Escanear cada canal una sola vez
        for channel in channels_to_scan:
            if not self.scan_active:
                break
            
            # Verificar si hay entrada del usuario (no bloqueante)
            try:
                if not self.input_queue.empty():
                    line = self.input_queue.get_nowait()
                    if line and line.strip().lower() in ['', 'enter', 'stop', 'x']:
                        print("\r\nEscaneo detenido por el usuario.\r\n")
                        break
            except queue.Empty:
                pass
            
            self.wifi.set_channel(channel, silent=True)
            time.sleep(0.2)  # Esperar para capturar paquetes
            
            rssi = self.wifi.get_channel_rssi_avg()
            
            if rssi > -75:
                print(f"\r\nSeñal encontrada en Canal: {channel} RSSI: {rssi} dBm\r\n")
                results.append((channel, rssi))
            else:
                # Mostrar progreso incluso si no hay señal fuerte
                print(f"\rCanal {channel}: RSSI {rssi} dBm", end='', flush=True)
        
        self.scan_active = False
        
        print("\r\n")  # Nueva línea después del progreso
        
        if results:
            print(f"\r\nResumen: {len(results)} canales con señal encontrados.\r\n")
            for result in results:
                if len(result) == 4:
                    channel, rssi, freq_mhz, band = result
                    print(f"  Canal {channel} ({freq_mhz} MHz, {band}): {rssi} dBm\r\n")
                else:
                    channel, rssi = result
                    print(f"  Canal {channel}: {rssi} dBm\r\n")
        else:
            print("\r\nNo se encontraron señales fuertes (RSSI > -75 dBm) en el rango especificado.\r\n")
            print("Nota: Puede haber tráfico débil. Usa 'wifiscan' para ver todas las redes.\r\n")
    
    def _cmd_filter(self, args: str):
        """Maneja filtros"""
        parts = args.split(None, 1) if args else []
        
        if not parts:
            # Mostrar filtros actuales
            print("\r\n=== FILTROS ACTIVOS ===\r\n")
            if self.filter_bssid:
                print(f"BSSID: {self.filter_bssid}\r\n")
            if self.filter_ssid:
                print(f"SSID: {self.filter_ssid}\r\n")
            if self.filter_type:
                print(f"Tipo: {self.filter_type}\r\n")
            if not self.filter_bssid and not self.filter_ssid and not self.filter_type:
                print("No hay filtros activos.\r\n")
            return
        
        filter_type = parts[0].lower()
        filter_value = parts[1] if len(parts) > 1 else None
        
        if filter_type == "clear":
            self.filter_bssid = None
            self.filter_ssid = None
            self.filter_type = None
            self.wifi.set_filter_bssid(None)
            self.wifi.set_filter_ssid(None)
            self.wifi.set_filter_packet_type(None)
            print("\r\nFiltros limpiados.\r\n")
        
        elif filter_type == "bssid":
            if filter_value:
                self.filter_bssid = filter_value
                self.wifi.set_filter_bssid(filter_value)
                print(f"\r\nFiltro BSSID configurado: {filter_value}\r\n")
            else:
                print("Error: Especifica un BSSID. Ejemplo: filter bssid AA:BB:CC:DD:EE:FF\r\n")
        
        elif filter_type == "ssid":
            if filter_value:
                self.filter_ssid = filter_value
                self.wifi.set_filter_ssid(filter_value)
                print(f"\r\nFiltro SSID configurado: {filter_value}\r\n")
            else:
                print("Error: Especifica un SSID. Ejemplo: filter ssid MiRed\r\n")
        
        elif filter_type == "type":
            if filter_value:
                self.filter_type = filter_value
                self.wifi.set_filter_packet_type(filter_value)
                print(f"\r\nFiltro tipo configurado: {filter_value}\r\n")
            else:
                print("Error: Especifica un tipo. Ejemplo: filter type beacon\r\n")
        
        else:
            print("Error: Tipo de filtro desconocido. Use: bssid, ssid, type, o clear\r\n")
    
    def _cmd_export_pcap(self, filename: str):
        """Exporta paquetes a archivo PCAP"""
        if not filename.endswith('.pcap'):
            filename += '.pcap'
        
        print(f"\r\nExportando paquetes a {filename}...\r\n")
        
        packet_count = 100  # Por defecto
        if self.wifi.export_pcap(filename, packet_count):
            print(f"\r\nExportación completada: {filename}\r\n")
        else:
            print("\r\nError en la exportación.\r\n")
    
    def _add_frame(self, data: bytes):
        """Añade un frame al buffer de grabación"""
        data_len = len(data)
        if (self.big_recording_buffer_pos + data_len + 1) < config.RECORDINGBUFFERSIZE:
            self.big_recording_buffer[self.big_recording_buffer_pos] = data_len
            self.big_recording_buffer_pos += 1
            self.big_recording_buffer[self.big_recording_buffer_pos:self.big_recording_buffer_pos + data_len] = data
            self.big_recording_buffer_pos += data_len
            self.frames_in_buffer += 1
            print(f"\r\nFrame {self.frames_in_buffer} añadido.\r\n")
        else:
            print("\r\nBuffer lleno. El frame no cabe.\r\n")
    
    def _cmd_show(self):
        """Muestra el contenido del buffer de grabación"""
        if self.frames_in_buffer > 0:
            print("\r\nPaquetes almacenados en buffer:\r\n")
            pos = 0
            for i in range(1, self.frames_in_buffer + 1):
                if pos >= config.RECORDINGBUFFERSIZE:
                    break
                frame_len = self.big_recording_buffer[pos]
                pos += 1
                if 0 < frame_len <= 60 and pos + frame_len <= config.RECORDINGBUFFERSIZE:
                    frame_data = bytes(self.big_recording_buffer[pos:pos + frame_len])
                    hex_str = utils.bytes_to_hex(frame_data)
                    print(f"\r\nFrame {i} : {hex_str}\r\n")
                    pos += frame_len
            print("\r\n")
        else:
            print("Error: No hay frames en el buffer.\r\n")
    
    def _cmd_play(self, frame_num: int):
        """Reproduce frames del buffer"""
        if frame_num <= self.frames_in_buffer:
            print("\r\nReproduciendo paquetes grabados...\r\n")
            pos = 0
            count = 0
            for i in range(1, self.frames_in_buffer + 1):
                if pos >= config.RECORDINGBUFFERSIZE:
                    break
                frame_len = self.big_recording_buffer[pos]
                pos += 1
                if 0 < frame_len <= 60 and (i == frame_num or frame_num == 0):
                    frame_data = bytes(self.big_recording_buffer[pos:pos + frame_len])
                    self.wifi.send_packet(frame_data)
                    count += 1
                    time.sleep(0.01)  # Pequeña pausa entre paquetes
                pos += frame_len
            print(f"\r\nReproducción completada: {count} paquetes enviados.\r\n")
        else:
            print("Error: Frame número inválido.\r\n")
    
    def _cmd_rxraw_wifi(self, usec: int):
        """RX RAW mode - WiFi sniffer"""
        print("\r\nWiFi sniffer RAW activado...\r\n")
        self.rxraw_active = True
        
        if not self.wifi.monitor_mode:
            self.wifi.set_monitor_mode(True)
        
        while self.rxraw_active:
            # Verificar si hay entrada
            if sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
                sys.stdin.readline()
                break
            
            packet = self.wifi.receive_packet(timeout=0.1)
            if packet:
                # Mostrar en hex
                hex_str = utils.bytes_to_hex(packet[:32])  # Primeros 32 bytes
                print(hex_str, end='', flush=True)
            
            time.sleep(usec / 1000000.0)
        
        print("\r\n\r\nSniffer detenido.\r\n\r\n")
    
    def _cmd_recraw_wifi(self, usec: int):
        """Record RAW WiFi data"""
        print("\r\nGrabando datos RAW WiFi...\r\n")
        
        if not self.wifi.monitor_mode:
            self.wifi.set_monitor_mode(True)
        
        recorded = 0
        start_time = time.time()
        
        while recorded < config.RECORDINGBUFFERSIZE:
            packet = self.wifi.receive_packet(timeout=0.5)
            if packet:
                packet_len = min(len(packet), config.RECORDINGBUFFERSIZE - recorded)
                self.big_recording_buffer[recorded:recorded + packet_len] = packet[:packet_len]
                recorded += packet_len
            
            # Verificar timeout o entrada
            if sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
                sys.stdin.readline()
                break
            
            time.sleep(usec / 1000000.0)
        
        print(f"\r\nGrabación RAW completada. {recorded} bytes grabados.\r\n\r\n")
    
    def _cmd_playraw_wifi(self, usec: int):
        """Play RAW WiFi data"""
        print("\r\nReproduciendo datos RAW...\r\n")
        
        # Reproducir datos
        sent = 0
        for i in range(0, config.RECORDINGBUFFERSIZE, 32):
            chunk = bytes(self.big_recording_buffer[i:i + 32])
            if chunk and any(chunk):  # Solo enviar si no es todo ceros
                self.wifi.send_packet(chunk)
                sent += 1
                time.sleep(usec / 1000000.0)
        
        print(f"\r\nReproducción RAW completada. {sent} chunks enviados.\r\n\r\n")
    
    def _cmd_showraw(self):
        """Show RAW data"""
        print("\r\nDatos RAW grabados:\r\n")
        for i in range(0, config.RECORDINGBUFFERSIZE, 32):
            chunk = bytes(self.big_recording_buffer[i:i + 32])
            if any(chunk):  # Solo mostrar si no es todo ceros
                hex_str = utils.bytes_to_hex(chunk)
                print(hex_str, end='', flush=True)
        print("\r\n\r\n")
    
    def _cmd_showbit(self):
        """Show RAW data as bit stream"""
        print("\r\nDatos RAW como bits:\r\n")
        for i in range(0, config.RECORDINGBUFFERSIZE, 32):
            chunk = bytes(self.big_recording_buffer[i:i + 32])
            if any(chunk):
                bit_stream = utils.format_bit_stream(chunk)
                print(bit_stream, end='', flush=True)
        print("\r\n\r\n")
    
    def _add_raw(self, data: bytes):
        """Añade datos RAW al buffer"""
        data_len = len(data)
        if (self.big_recording_buffer_pos + data_len) < config.RECORDINGBUFFERSIZE:
            self.big_recording_buffer[self.big_recording_buffer_pos:self.big_recording_buffer_pos + data_len] = data
            self.big_recording_buffer_pos += data_len
            print("\r\nChunk añadido al buffer.\r\n\r\n")
        else:
            print("\r\nBuffer lleno. El chunk no cabe.\r\n")
    
    def _cmd_save(self):
        """Guarda el buffer a archivo"""
        print("\r\nGuardando buffer...\r\n")
        try:
            data = {
                'buffer': list(self.big_recording_buffer),
                'position': self.big_recording_buffer_pos,
                'frames': self.frames_in_buffer
            }
            with open(config.EEPROM_FILE, 'wb') as f:
                pickle.dump(data, f)
            print("\r\nGuardado completado.\r\n\r\n")
        except Exception as e:
            print(f"Error guardando: {e}\r\n")
    
    def _cmd_load(self):
        """Carga el buffer desde archivo"""
        print("\r\nCargando buffer desde archivo...\r\n")
        try:
            with open(config.EEPROM_FILE, 'rb') as f:
                data = pickle.load(f)
            self.big_recording_buffer = bytearray(data['buffer'])
            self.big_recording_buffer_pos = data.get('position', 0)
            self.frames_in_buffer = data.get('frames', 0)
            print("\r\nCarga completada. Use 'show' o 'showraw' para ver el contenido.\r\n\r\n")
        except FileNotFoundError:
            print("No se encontró archivo guardado.\r\n")
        except Exception as e:
            print(f"Error cargando: {e}\r\n")
    
    def process_wifi(self):
        """Procesa paquetes WiFi recibidos"""
        if self.wifi.check_receive_flag() and (self.receiving_mode or self.recording_mode or self.chat_mode):
            # Limpiar buffer
            self.cc_receiving_buffer = bytearray(config.CCBUFFERSIZE)
            length = self.wifi.receive_data(self.cc_receiving_buffer)
            
            if length > 0 and length < config.CCBUFFERSIZE:
                # Modo Chat
                if self.chat_mode:
                    try:
                        text = bytes(self.cc_receiving_buffer[:length]).decode('utf-8', errors='ignore')
                        print(text, end='', flush=True)
                    except:
                        pass
                
                # Modo Recepción - Mostrar información detallada de paquetes WiFi
                elif self.receiving_mode and not self.recording_mode:
                    # Obtener el último paquete procesado del WiFi driver
                    if hasattr(self.wifi, 'last_packet') and self.wifi.last_packet:
                        pkt = self.wifi.last_packet
                        self._print_packet_info(pkt)
                    else:
                        # Fallback: mostrar hex si no hay información parseada
                        hex_str = utils.bytes_to_hex(bytes(self.cc_receiving_buffer[:length]))
                        print(hex_str, end='', flush=True)
                
                # Modo Grabación
                elif self.recording_mode and not self.receiving_mode:
                    if (self.big_recording_buffer_pos + length + 1) < config.RECORDINGBUFFERSIZE:
                        self.big_recording_buffer[self.big_recording_buffer_pos] = length
                        self.big_recording_buffer_pos += 1
                        self.big_recording_buffer[self.big_recording_buffer_pos:self.big_recording_buffer_pos + length] = self.cc_receiving_buffer[:length]
                        self.big_recording_buffer_pos += length
                        self.frames_in_buffer += 1
                    else:
                        print(f"\r\nBuffer de grabación lleno! Deteniendo...\r\nFrames almacenados: {self.frames_in_buffer}\r\n")
                        self.big_recording_buffer_pos = 0
                        self.recording_mode = False
    
    def cleanup(self):
        """Limpia recursos de forma segura"""
        try:
            self.wifi.cleanup()
            self.history.save()
        except:
            pass
    
    def run(self):
        """Bucle principal mejorado"""
        print("WiFi Terminal Tool - Versión Mejorada")
        print("Adaptado para WiFi - BrosTrend AC1200 AC3L\n\r")
        print("Use 'help' para lista de comandos o 'status' para estado actual.\n\r")
        print()
        
        # Usar threading para entrada de comandos (más robusto)
        import threading
        
        self.input_queue = queue.Queue()
        input_active = True
        
        def input_thread():
            """Thread separado para capturar entrada del usuario"""
            while input_active:
                try:
                    # Usar input() normal en thread separado (bloqueante pero funciona mejor)
                    line = input()
                    if line:
                        self.input_queue.put(line)
                except (EOFError, KeyboardInterrupt):
                    self.input_queue.put(None)
                    break
                except Exception:
                    pass
        
        # Iniciar thread de entrada
        input_thread_obj = threading.Thread(target=input_thread, daemon=True)
        input_thread_obj.start()
        
        try:
            while True:
                # Procesar comandos de entrada (no bloqueante)
                try:
                    if not self.input_queue.empty():
                        line = self.input_queue.get_nowait()
                        if line is None:
                            break
                        
                        if line:
                            if self.chat_mode:
                                # En modo chat, enviar directamente
                                data = line.encode('utf-8')
                                self.wifi.send_packet(data)
                                if self.do_echo:
                                    print(line, end='', flush=True)
                            else:
                                # Procesar comando
                                if self.do_echo:
                                    print(f">>> {line}\r\n", end='', flush=True)
                                self.exec_command(line.strip())
                except queue.Empty:
                    pass
                except Exception as e:
                    pass
                
                # Procesar WiFi
                self.process_wifi()
                
                # Pequeña pausa para no saturar CPU
                time.sleep(0.01)
        
        except KeyboardInterrupt:
            print("\n\r\nInterrupción detectada. Limpiando...")
        finally:
            input_active = False
            self.cleanup()


def main():
    """Función principal"""
    # Verificar permisos (solo en Unix/Linux)
    try:
        if hasattr(os, 'geteuid') and os.geteuid() != 0:
            print("ADVERTENCIA: Se recomienda ejecutar con sudo para modo monitor.")
            print("Algunas funciones pueden no funcionar sin permisos de administrador.\n")
    except AttributeError:
        # Windows no tiene geteuid()
        pass
    
    terminal = WiFiTerminal()
    terminal.run()


if __name__ == "__main__":
    main()
