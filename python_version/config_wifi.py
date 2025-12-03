"""
Configuración para WiFi Jammer usando BrosTrend AC1200 AC3L
Adaptado del proyecto CC1101 para usar WiFi en lugar de RF sub-GHz
"""

# Constantes de buffer
CCBUFFERSIZE = 64
RECORDINGBUFFERSIZE = 4096
EPROMSIZE = 4096
BUF_LENGTH = 128

# Configuración WiFi
WIFI_INTERFACE = None  # Se detectará automáticamente o configurar manualmente: "wlan0", "wlan1", etc.
MONITOR_INTERFACE = None  # Se creará automáticamente

# Canales WiFi
CHANNELS_2_4 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
CHANNELS_5 = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]

# Configuración por defecto
DEFAULT_CHANNEL = 6  # Canal WiFi 2.4 GHz por defecto
DEFAULT_BAND = "2.4"  # "2.4" o "5"

# Archivo para almacenamiento persistente
EEPROM_FILE = 'wifi_eeprom.dat'

# Configuración de jamming
JAM_DEAUTH_COUNT = 0  # 0 = infinito

