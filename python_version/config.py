"""
Configuración y constantes para CC1101 Jammer
Migrado de C++/Arduino a Python
"""

# Constantes de buffer
CCBUFFERSIZE = 64
RECORDINGBUFFERSIZE = 4096
EPROMSIZE = 4096  # Para Raspberry Pi usaremos archivo en lugar de EEPROM
BUF_LENGTH = 128

# Configuración de pines para Raspberry Pi 4
# SPI pins (hardware SPI0 en Raspberry Pi)
SCK = 11    # GPIO 11 (SPI0_SCLK)
MISO = 9    # GPIO 9  (SPI0_MISO)
MOSI = 10   # GPIO 10 (SPI0_MOSI)
SS = 8      # GPIO 8  (SPI0_CE0) - Chip Select

# GPIO pins para GDO0 y GDO2
GDO0 = 17   # GPIO 17
GDO2 = 27   # GPIO 27

# Configuración por defecto del CC1101
DEFAULT_FREQUENCY = 433.92  # MHz
DEFAULT_MODULATION = 2      # ASK/OOK
DEFAULT_DEVIATION = 47.60   # kHz
DEFAULT_CHANNEL = 0
DEFAULT_CHSP = 199.95       # kHz
DEFAULT_RXBW = 812.50       # kHz
DEFAULT_DRATE = 9.6         # kBaud
DEFAULT_PA = 10             # TxPower
DEFAULT_SYNC_MODE = 2
DEFAULT_SYNC_WORD_HIGH = 211
DEFAULT_SYNC_WORD_LOW = 145

# Archivo para almacenamiento persistente (equivalente a EEPROM)
EEPROM_FILE = 'cc1101_eeprom.dat'

# Velocidad de comunicación SPI
SPI_MAX_SPEED_HZ = 1000000  # 1 MHz (conservador para CC1101)

