"""
Configuración para WiFi Jammer usando TP-Link TL-WN722N
Adaptado del proyecto CC1101 para usar WiFi en lugar de RF sub-GHz

NOTA: TP-Link TL-WN722N solo soporta 2.4 GHz (no 5 GHz)
"""

# Versión del proyecto
__version__ = "2.0.0"
VERSION = __version__

# Constantes de buffer
CCBUFFERSIZE = 64
RECORDINGBUFFERSIZE = 4096
EPROMSIZE = 4096
BUF_LENGTH = 128

# Configuración WiFi
WIFI_INTERFACE = None  # Se detectará automáticamente o configurar manualmente: "wlan0", "wlan1", etc.
MONITOR_INTERFACE = None  # Se creará automáticamente

# Canales WiFi
# TP-Link TL-WN722N solo soporta 2.4 GHz
CHANNELS_2_4 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
CHANNELS_5 = []  # TL-WN722N no soporta 5 GHz - lista vacía para evitar errores

# Configuración por defecto
DEFAULT_CHANNEL = 6  # Canal WiFi 2.4 GHz por defecto
DEFAULT_BAND = "2.4"  # Solo "2.4" disponible para TL-WN722N

# Archivo para almacenamiento persistente
EEPROM_FILE = 'tl_wn722n_eeprom.dat'

# Configuración de jamming
JAM_DEAUTH_COUNT = 0  # 0 = infinito

# Información del adaptador
ADAPTER_NAME = "TP-Link TL-WN722N"
ADAPTER_BANDS = ["2.4"]  # Solo 2.4 GHz
ADAPTER_SUPPORTS_5GHZ = False

# Optimizaciones para Raspberry Pi 4
import os
try:
    import multiprocessing
    CPU_CORES = multiprocessing.cpu_count()
except:
    CPU_CORES = 4  # Default para RPi 4

# Detección automática de hardware
try:
    if os.path.exists('/proc/device-tree/model'):
        with open('/proc/device-tree/model', 'r') as f:
            model = f.read()
            RPI_DETECTED = 'Raspberry Pi' in model
    else:
        RPI_DETECTED = False
except Exception:
    RPI_DETECTED = False

# Configuración optimizada para Raspberry Pi 4
# RPi 4 tiene 4 cores ARM Cortex-A72
MAX_WORKER_THREADS = min(CPU_CORES, 8)  # Usar hasta 8 threads (optimizado para RPi 4)
OPTIMIZE_FOR_RPI = RPI_DETECTED  # Auto-detectar si es Raspberry Pi

# Optimizaciones de rendimiento
ENABLE_PACKET_POOL = True  # Pool de paquetes pre-compilados
PACKET_POOL_SIZE = 100  # Tamaño del pool de paquetes
PRE_COMPILE_PACKETS = True  # Pre-compilar paquetes comunes
OPTIMIZE_MEMORY = True  # Optimizar uso de memoria para ARM

# Optimizaciones específicas para TL-WN722N
TL_WN722N_MAX_PACKET_RATE = 1000  # Máxima tasa de paquetes/segundo (estimado)
TL_WN722N_OPTIMAL_INTERVAL = 0.001  # Intervalo óptimo entre paquetes (1ms)
ENABLE_BURST_MODE = True  # Modo ráfaga optimizado
BURST_SIZE = 10  # Paquetes por ráfaga

# Optimizaciones de buffer y memoria
BUFFER_OPTIMIZATION = True  # Optimizar buffers para ARM
QUEUE_SIZE_MULTIPLIER = 2 if RPI_DETECTED else 1  # Queues más grandes en RPi
PACKET_BUFFER_SIZE = 2000 if RPI_DETECTED else 1000  # Buffer más grande en RPi

# Optimizaciones de threading
USE_MULTIPROCESSING = False  # Mantener threading (mejor para I/O)
THREAD_PRIORITY = "normal"  # Prioridad de threads (puede ser "high" en sistemas RT)

# Configuración Bluetooth
# Bluetooth usa 79 canales de 1 MHz en la banda 2.4 GHz (2402-2480 MHz)
# Canales Bluetooth (frecuencia en MHz = 2402 + canal)
BLUETOOTH_CHANNELS = list(range(0, 79))  # Canales 0-78
BLUETOOTH_FREQ_START = 2402  # MHz
BLUETOOTH_FREQ_END = 2480  # MHz
BLUETOOTH_CHANNEL_WIDTH = 1  # MHz por canal

# Canales BLE críticos identificados por nRFBox (advertising channels)
BLE_ADVERTISING_CHANNELS = [2, 26, 80]  # Canales BLE más importantes
BLE_ADVERTISING_CHANNELS_WEIGHT = 3  # Peso para priorizar estos canales

# Canales Bluetooth clásico (basado en nRFBox)
BT_CLASSIC_CHANNELS = [32, 34, 46, 48, 50, 52, 0, 1, 2, 4, 6, 8, 22, 24, 26, 28, 30, 74, 76, 78, 80]

# Agrupación de canales WiFi por solapamiento Bluetooth (basado en nRFBox)
# WiFi canal -> Canales Bluetooth que cubre mejor
WIFI_BT_COVERAGE_GROUPS = {
    # Grupo BLE bajo: WiFi canales 1-3 cubren mejor BLE canal 2
    'ble_low': {'wifi_channels': [1, 2, 3], 'bt_channels': [0, 1, 2, 3, 4, 5, 6, 7, 8]},
    # Grupo BLE medio: WiFi canal 6 cubre mejor BLE canal 26 y BT clásico
    'ble_mid': {'wifi_channels': [6, 7, 8], 'bt_channels': [22, 24, 26, 28, 30, 32, 34, 35]},
    # Grupo BLE alto: WiFi canal 11 cubre mejor BLE canal 80
    'ble_high': {'wifi_channels': [10, 11, 12], 'bt_channels': [74, 76, 78, 80]},
    # Grupo BT clásico extendido: Canales adicionales de Bluetooth clásico
    'bt_classic': {'wifi_channels': [5, 6, 7, 8, 9], 'bt_channels': [46, 48, 50, 52]}
}

# Configuración de jamming Bluetooth
BT_JAM_INTERVAL = 0.625  # ms - tiempo de slot Bluetooth (625 μs)
BT_JAM_PACKET_RATE = 1600  # paquetes por segundo (aprox. 1 paquete cada 625 μs)

# Mejoras de jamming Bluetooth (optimizado con técnicas de nRFBox)
BT_JAM_AGGRESSIVE_MODE = True  # Modo agresivo: más paquetes, mayor tamaño
BT_JAM_PACKET_SIZE = 1500  # Tamaño de paquete en bytes (máximo para mayor interferencia)
BT_JAM_BURST_COUNT = 100  # Paquetes por ráfaga (aumentado desde 50, basado en nRFBox)
BT_JAM_BURST_INTERVAL = 0.0  # Sin pausa entre paquetes en ráfaga (eliminado, como nRFBox)
BT_JAM_HOP_RATE_MULTIPLIER = 3.0  # Multiplicador aumentado para hopping más rápido
BT_JAM_PRIORITY_CHANNELS = [2, 26, 80]  # Canales BLE advertising (basado en nRFBox)

# Patrón de datos optimizado (basado en nRFBox: alternancia 0xAA/0x55)
BT_JAM_DATA_PATTERN = bytes([0xAA, 0x55] * 750)  # Patrón alternante para interferencia efectiva
BT_JAM_USE_OPTIMIZED_PATTERN = True  # Usar patrón optimizado

# Configuración de jamming por grupos (inspirado en nRFBox)
BT_JAM_USE_GROUP_STRATEGY = True  # Usar estrategia de grupos de canales
BT_JAM_GROUP_ROTATION_INTERVAL = 0.1  # Rotar entre grupos cada 100ms

