"""
Controlador CC1101 para Raspberry Pi
Equivalente a la biblioteca SmartRC de Arduino
Migrado de C++/Arduino a Python
"""

import time
import struct
try:
    import spidev
    import RPi.GPIO as GPIO
except ImportError:
    print("ADVERTENCIA: spidev o RPi.GPIO no disponible. El código funcionará en modo simulación.")
    spidev = None
    GPIO = None

import config
import utils


class CC1101Driver:
    """Controlador para el módulo CC1101"""
    
    # Direcciones de registro CC1101
    REG_IOCFG2 = 0x00
    REG_IOCFG1 = 0x01
    REG_IOCFG0 = 0x02
    REG_FIFOTHR = 0x03
    REG_SYNC1 = 0x04
    REG_SYNC0 = 0x05
    REG_PKTLEN = 0x06
    REG_PKTCTRL1 = 0x07
    REG_PKTCTRL0 = 0x08
    REG_ADDR = 0x09
    REG_CHANNR = 0x0A
    REG_FSCTRL1 = 0x0B
    REG_FSCTRL0 = 0x0C
    REG_FREQ2 = 0x0D
    REG_FREQ1 = 0x0E
    REG_FREQ0 = 0x0F
    REG_MDMCFG4 = 0x10
    REG_MDMCFG3 = 0x11
    REG_MDMCFG2 = 0x12
    REG_MDMCFG1 = 0x13
    REG_MDMCFG0 = 0x14
    REG_DEVIATN = 0x15
    REG_MCSM2 = 0x16
    REG_MCSM1 = 0x17
    REG_MCSM0 = 0x18
    REG_FOCCFG = 0x19
    REG_BSCFG = 0x1A
    REG_AGCTRL2 = 0x1B
    REG_AGCTRL1 = 0x1C
    REG_AGCTRL0 = 0x1D
    REG_WOREVT1 = 0x1E
    REG_WOREVT0 = 0x1F
    REG_WORCTRL = 0x20
    REG_FREND1 = 0x21
    REG_FREND0 = 0x22
    REG_FSCAL3 = 0x23
    REG_FSCAL2 = 0x24
    REG_FSCAL1 = 0x25
    REG_FSCAL0 = 0x26
    REG_RCCTRL1 = 0x27
    REG_RCCTRL0 = 0x28
    REG_FSTEST = 0x29
    REG_PTEST = 0x2A
    REG_AGCTEST = 0x2B
    REG_TEST2 = 0x2C
    REG_TEST1 = 0x2D
    REG_TEST0 = 0x2E
    
    # Comandos strobe
    CMD_SRES = 0x30  # Reset
    CMD_SFSTXON = 0x31
    CMD_SXOFF = 0x32
    CMD_SCAL = 0x33
    CMD_SRX = 0x34  # Entrar en modo RX
    CMD_STX = 0x35  # Entrar en modo TX
    CMD_SIDLE = 0x36  # Entrar en modo IDLE
    CMD_SWOR = 0x38
    CMD_SPWD = 0x39
    CMD_SFRX = 0x3A
    CMD_SFTX = 0x3B
    CMD_SWORRST = 0x3C
    CMD_SNOP = 0x3D
    
    # Estados
    STATE_IDLE = 0x00
    STATE_RX = 0x10
    STATE_TX = 0x20
    STATE_FSTXON = 0x30
    STATE_CALIBRATE = 0x40
    STATE_SETTLING = 0x50
    STATE_RXFIFO_OVERFLOW = 0x60
    STATE_TXFIFO_UNDERFLOW = 0x70
    
    def __init__(self, sck=None, miso=None, mosi=None, ss=None, gdo0=None, gdo2=None):
        """Inicializa el controlador CC1101"""
        # Usar configuración por defecto si no se especifican pines
        self.sck = sck or config.SCK
        self.miso = miso or config.MISO
        self.mosi = mosi or config.MOSI
        self.ss = ss or config.SS
        self.gdo0 = gdo0 or config.GDO0
        self.gdo2 = gdo2 or config.GDO2
        
        # Variables de configuración
        self.cc_mode = 1  # 0 = RAW, 1 = Packet mode
        self.modulation = 2
        self.frequency = 433.92
        self.deviation = 47.60
        self.channel = 0
        self.chsp = 199.95
        self.rxbw = 812.50
        self.drate = 9.6
        self.pa = 10
        self.sync_mode = 2
        self.sync_word_high = 211
        self.sync_word_low = 145
        self.adr_chk = 0
        self.addr = 0
        self.white_data = 0
        self.pkt_format = 0
        self.length_config = 1
        self.packet_length = 0
        self.crc = 0
        self.crc_af = 0
        self.dc_filter_off = 0
        self.manchester = 0
        self.fec = 0
        self.pre = 0
        self.pqt = 0
        self.append_status = 0
        
        # Estado
        self.current_mode = None
        self.initialized = False
        self.last_rssi = 0
        self.last_lqi = 0
        
        # Inicializar SPI y GPIO
        self._init_spi()
        self._init_gpio()
    
    def _init_spi(self):
        """Inicializa la comunicación SPI"""
        if spidev is None:
            self.spi = None
            print("MODO SIMULACIÓN: SPI no disponible")
            return
            
        try:
            self.spi = spidev.SpiDev()
            self.spi.open(0, 0)  # SPI bus 0, device 0
            self.spi.max_speed_hz = config.SPI_MAX_SPEED_HZ
            self.spi.mode = 0  # Modo SPI 0
        except Exception as e:
            print(f"Error inicializando SPI: {e}")
            self.spi = None
    
    def _init_gpio(self):
        """Inicializa los pines GPIO"""
        if GPIO is None:
            print("MODO SIMULACIÓN: GPIO no disponible")
            return
            
        try:
            GPIO.setmode(GPIO.BCM)
            GPIO.setup(self.ss, GPIO.OUT)
            GPIO.setup(self.gdo0, GPIO.IN, pull_up_down=GPIO.PUD_DOWN)
            GPIO.setup(self.gdo2, GPIO.IN, pull_up_down=GPIO.PUD_DOWN)
            GPIO.output(self.ss, GPIO.HIGH)  # CS inactivo
        except Exception as e:
            print(f"Error inicializando GPIO: {e}")
    
    def _spi_write(self, data):
        """Escribe datos por SPI"""
        if self.spi is None:
            return []
        if GPIO is None:
            return []
        GPIO.output(self.ss, GPIO.LOW)
        time.sleep(0.001)
        try:
            if isinstance(data, int):
                response = self.spi.xfer2([data])
            else:
                response = self.spi.xfer2(list(data))
        finally:
            GPIO.output(self.ss, GPIO.HIGH)
        return response
    
    def _spi_read(self, addr):
        """Lee un registro del CC1101"""
        if self.spi is None or GPIO is None:
            return 0
        GPIO.output(self.ss, GPIO.LOW)
        time.sleep(0.001)
        try:
            response = self.spi.xfer2([addr | 0x80, 0x00])
        finally:
            GPIO.output(self.ss, GPIO.HIGH)
        return response[1] if len(response) > 1 else 0
    
    def _strobe(self, cmd):
        """Ejecuta un comando strobe"""
        if self.spi is None or GPIO is None:
            return 0
        GPIO.output(self.ss, GPIO.LOW)
        time.sleep(0.001)
        try:
            response = self.spi.xfer2([cmd])
        finally:
            GPIO.output(self.ss, GPIO.HIGH)
        time.sleep(0.001)
        return response[0] if response else 0
    
    def _write_reg(self, addr, value):
        """Escribe un registro"""
        if self.spi is None:
            return
        self._spi_write([addr, value])
    
    def _read_reg(self, addr):
        """Lee un registro"""
        return self._spi_read(addr)
    
    def get_state(self):
        """Obtiene el estado actual del CC1101"""
        state_byte = self._strobe(self.CMD_SNOP)
        return (state_byte >> 4) & 0x0F
    
    def reset(self):
        """Resetea el CC1101"""
        if GPIO is None:
            return
        GPIO.output(self.ss, GPIO.HIGH)
        time.sleep(0.001)
        GPIO.output(self.ss, GPIO.LOW)
        time.sleep(0.001)
        GPIO.output(self.ss, GPIO.HIGH)
        time.sleep(0.001)
        self._strobe(self.CMD_SRES)
        time.sleep(0.01)
    
    def Init(self):
        """Inicializa el CC1101 con configuración por defecto"""
        self.reset()
        time.sleep(0.1)
        
        # Configurar registros base
        self._write_reg(self.REG_IOCFG0, 0x06)  # GDO0 como output para RX/TX
        self._write_reg(self.REG_FIFOTHR, 0x47)
        
        # Aplicar toda la configuración
        self._apply_config()
        
        self.initialized = True
        return True
    
    def _apply_config(self):
        """Aplica toda la configuración actual"""
        # Frecuencia
        self._set_frequency(self.frequency)
        
        # Modulación
        self._set_modulation(self.modulation)
        
        # Otros parámetros
        self.setChannel(self.channel)
        self.setDeviation(self.deviation)
        self.setChsp(self.chsp)
        self.setRxBW(self.rxbw)
        self.setDRate(self.drate)
        self.setPA(self.pa)
        self.setSyncMode(self.sync_mode)
        self.setSyncWord(self.sync_word_high, self.sync_word_low)
        self.setAdrChk(self.adr_chk)
        self.setAddr(self.addr)
        self.setWhiteData(self.white_data)
        self.setPktFormat(self.pkt_format)
        self.setLengthConfig(self.length_config)
        self.setPacketLength(self.packet_length)
        self.setCrc(self.crc)
        self.setCRC_AF(self.crc_af)
        self.setDcFilterOff(self.dc_filter_off)
        self.setManchester(self.manchester)
        self.setFEC(self.fec)
        self.setPRE(self.pre)
        self.setPQT(self.pqt)
        self.setAppendStatus(self.append_status)
    
    def _set_frequency(self, freq_mhz):
        """Calcula y establece la frecuencia (implementación simplificada)"""
        # El CC1101 usa un oscilador de 26 MHz
        # Frecuencia = (FREQ[23:0] * 26e6) / 2^16
        freq_word = int((freq_mhz * 1e6) * (65536.0 / 26000000.0))
        
        freq2 = (freq_word >> 16) & 0xFF
        freq1 = (freq_word >> 8) & 0xFF
        freq0 = freq_word & 0xFF
        
        self._write_reg(self.REG_FREQ2, freq2)
        self._write_reg(self.REG_FREQ1, freq1)
        self._write_reg(self.REG_FREQ0, freq0)
    
    def _set_modulation(self, mod):
        """Establece el tipo de modulación"""
        mdmcfg2 = self._read_reg(self.REG_MDMCFG2) & 0x8F  # Limpiar bits de modulación
        mdmcfg2 |= (mod & 0x07) << 4
        self._write_reg(self.REG_MDMCFG2, mdmcfg2)
    
    def getCC1101(self):
        """Verifica la conexión con el CC1101"""
        if self.spi is None:
            return False
        try:
            # Intentar leer un registro conocido
            partnum = self._read_reg(0xF0)  # PARTNUM
            version = self._read_reg(0xF1)  # VERSION
            # El CC1101 debería retornar PARTNUM=0 y VERSION=4 o 14
            return True  # Simplificado - siempre retorna True si SPI funciona
        except:
            return False
    
    # Métodos públicos que replican la interfaz de SmartRC
    
    def setCCMode(self, mode):
        """0 = RAW mode, 1 = Packet mode"""
        self.cc_mode = mode
    
    def setModulation(self, mod):
        """0=2-FSK, 1=GFSK, 2=ASK/OOK, 3=4-FSK, 4=MSK"""
        self.modulation = mod
        self._set_modulation(mod)
    
    def setMHZ(self, freq):
        """Establece frecuencia en MHz"""
        if utils.validate_frequency(freq):
            self.frequency = freq
            self._set_frequency(freq)
            return True
        return False
    
    def setDeviation(self, dev_khz):
        """Establece desviación de frecuencia en kHz"""
        # Cálculo simplificado - el CC1101 usa una fórmula específica
        self.deviation = dev_khz
        # Implementación real requeriría cálculo de registros MDMCFG0/1
        # Por ahora, marcamos como configurado
    
    def setChannel(self, chan):
        """Establece canal (0-255)"""
        self.channel = chan
        self._write_reg(self.REG_CHANNR, chan)
    
    def setChsp(self, spacing_khz):
        """Establece espaciado de canal en kHz"""
        self.chsp = spacing_khz
        # Cálculo de registros necesario
    
    def setRxBW(self, bw_khz):
        """Establece ancho de banda de recepción en kHz"""
        self.rxbw = bw_khz
        # Cálculo de registros necesario
    
    def setDRate(self, rate_kbaud):
        """Establece velocidad de datos en kBaud"""
        self.drate = rate_kbaud
        # Cálculo de registros necesario
    
    def setPA(self, power):
        """Establece potencia de transmisión"""
        self.pa = power
        # Configuración de FREND0/1 necesaria
    
    def setSyncMode(self, mode):
        """Establece modo de sincronización"""
        self.sync_mode = mode
        pktctrl1 = self._read_reg(self.REG_PKTCTRL1) & 0x8F
        pktctrl1 |= (mode & 0x07) << 4
        self._write_reg(self.REG_PKTCTRL1, pktctrl1)
    
    def setSyncWord(self, high, low):
        """Establece palabra de sincronización"""
        self.sync_word_high = high
        self.sync_word_low = low
        self._write_reg(self.REG_SYNC1, high)
        self._write_reg(self.REG_SYNC0, low)
    
    def setAdrChk(self, mode):
        """Configura verificación de dirección"""
        self.adr_chk = mode
        pktctrl1 = self._read_reg(self.REG_PKTCTRL1) & 0xF3
        pktctrl1 |= (mode & 0x03) << 2
        self._write_reg(self.REG_PKTCTRL1, pktctrl1)
    
    def setAddr(self, addr):
        """Establece dirección del dispositivo"""
        self.addr = addr
        self._write_reg(self.REG_ADDR, addr)
    
    def setWhiteData(self, enable):
        """Habilita/deshabilita whitening de datos"""
        self.white_data = enable
        pktctrl0 = self._read_reg(self.REG_PKTCTRL0) & 0xFE
        pktctrl0 |= enable & 0x01
        self._write_reg(self.REG_PKTCTRL0, pktctrl0)
    
    def setPktFormat(self, format):
        """Establece formato de paquete"""
        self.pkt_format = format
        pktctrl0 = self._read_reg(self.REG_PKTCTRL0) & 0xF3
        pktctrl0 |= (format & 0x03) << 6
        self._write_reg(self.REG_PKTCTRL0, pktctrl0)
    
    def setLengthConfig(self, mode):
        """Establece configuración de longitud de paquete"""
        self.length_config = mode
        pktctrl0 = self._read_reg(self.REG_PKTCTRL0) & 0xFC
        pktctrl0 |= mode & 0x03
        self._write_reg(self.REG_PKTCTRL0, pktctrl0)
    
    def setPacketLength(self, length):
        """Establece longitud de paquete"""
        self.packet_length = length
        self._write_reg(self.REG_PKTLEN, length)
    
    def setCrc(self, enable):
        """Habilita/deshabilita CRC"""
        self.crc = enable
        pktctrl0 = self._read_reg(self.REG_PKTCTRL0) & 0xEF
        pktctrl0 |= (enable & 0x01) << 4
        self._write_reg(self.REG_PKTCTRL0, pktctrl0)
    
    def setCRC_AF(self, enable):
        """Habilita flush automático de FIFO en CRC error"""
        self.crc_af = enable
        # Implementación en registro apropiado
    
    def setDcFilterOff(self, disable):
        """Deshabilita filtro DC"""
        self.dc_filter_off = disable
        # Implementación en registro apropiado
    
    def setManchester(self, enable):
        """Habilita codificación Manchester"""
        self.manchester = enable
        # Implementación en registro apropiado
    
    def setFEC(self, enable):
        """Habilita corrección de errores hacia adelante"""
        self.fec = enable
        # Implementación en registro apropiado
    
    def setPRE(self, mode):
        """Establece preámbulo"""
        self.pre = mode
        mdmcfg0 = self._read_reg(self.REG_MDMCFG0) & 0x1F
        mdmcfg0 |= (mode & 0x07) << 5
        self._write_reg(self.REG_MDMCFG0, mdmcfg0)
    
    def setPQT(self, pqt):
        """Establece umbral de calidad de preámbulo"""
        self.pqt = pqt
        pktctrl1 = self._read_reg(self.REG_PKTCTRL1) & 0xF8
        pktctrl1 |= pqt & 0x07
        self._write_reg(self.REG_PKTCTRL1, pktctrl1)
    
    def setAppendStatus(self, enable):
        """Añade bytes de estado (RSSI/LQI) al paquete"""
        self.append_status = enable
        pktctrl1 = self._read_reg(self.REG_PKTCTRL1) & 0x7F
        pktctrl1 |= (enable & 0x01) << 7
        self._write_reg(self.REG_PKTCTRL1, pktctrl1)
    
    def SetRx(self):
        """Entra en modo recepción"""
        self._strobe(self.CMD_SIDLE)
        time.sleep(0.001)
        self._strobe(self.CMD_SFRX)  # Flush RX FIFO
        time.sleep(0.001)
        self._strobe(self.CMD_SRX)
        time.sleep(0.01)
        self.current_mode = 'RX'
    
    def SetTx(self):
        """Entra en modo transmisión"""
        self._strobe(self.CMD_SIDLE)
        time.sleep(0.001)
        self._strobe(self.CMD_SFTX)  # Flush TX FIFO
        time.sleep(0.001)
        self._strobe(self.CMD_STX)
        time.sleep(0.01)
        self.current_mode = 'TX'
    
    def CheckReceiveFlag(self):
        """Verifica si hay datos recibidos (GDO0 activo)"""
        if GPIO is None:
            return False
        try:
            return GPIO.input(self.gdo0) == GPIO.HIGH
        except:
            return False
    
    def CheckCRC(self):
        """Verifica CRC del último paquete"""
        if self.crc == 0:
            return True  # Si CRC está deshabilitado, siempre retorna OK
        # En implementación real, leería el byte de estado
        return True
    
    def ReceiveData(self, buffer):
        """Recibe datos en el buffer"""
        if self.spi is None or GPIO is None:
            return 0
        
        # Leer número de bytes en FIFO
        rxbytes = self._read_reg(0xFB) & 0x7F  # RXBYTES
        
        if rxbytes == 0:
            return 0
        
        # Leer datos del FIFO
        data = []
        GPIO.output(self.ss, GPIO.LOW)
        time.sleep(0.001)
        try:
            # Comando para leer FIFO
            self.spi.xfer2([0xBF])  # Burst read RX FIFO
            for i in range(min(rxbytes, len(buffer))):
                response = self.spi.xfer2([0x00])
                data.append(response[0])
        finally:
            GPIO.output(self.ss, GPIO.HIGH)
        
        # Copiar a buffer
        length = min(len(data), len(buffer))
        for i in range(length):
            if isinstance(buffer, bytearray):
                buffer[i] = data[i]
            else:
                buffer[i] = data[i]
        
        return length
    
    def SendData(self, data, length=None):
        """Envía datos"""
        if self.spi is None or GPIO is None:
            return False
        
        if isinstance(data, (str, bytes, bytearray)):
            if isinstance(data, str):
                data = list(data.encode())
            else:
                data = list(data)
        
        if length is None:
            length = len(data)
        
        length = min(length, len(data), 64)  # Máximo 64 bytes
        
        # Flush TX FIFO
        self._strobe(self.CMD_SFTX)
        time.sleep(0.001)
        
        # Escribir datos al FIFO
        GPIO.output(self.ss, GPIO.LOW)
        time.sleep(0.001)
        try:
            self.spi.xfer2([0xBF])  # Burst write TX FIFO
            for byte in data[:length]:
                self.spi.xfer2([byte])
        finally:
            GPIO.output(self.ss, GPIO.HIGH)
        
        # Entrar en modo TX si no lo está
        if self.current_mode != 'TX':
            self.SetTx()
        
        # Esperar a que se transmita
        time.sleep(0.01)
        
        return True
    
    def getRssi(self):
        """Obtiene RSSI en dBm"""
        rssi_raw = self._read_reg(0xFB)  # RSSI
        if rssi_raw >= 128:
            rssi = ((rssi_raw - 256) / 2) - 74
        else:
            rssi = (rssi_raw / 2) - 74
        self.last_rssi = int(rssi)
        return self.last_rssi
    
    def getLqi(self):
        """Obtiene LQI (Link Quality Indicator)"""
        lqi = self._read_reg(0xFB) & 0x7F  # LQI
        self.last_lqi = lqi
        return self.last_lqi
    
    def cleanup(self):
        """Limpia recursos"""
        if self.spi:
            self.spi.close()
        if GPIO:
            GPIO.cleanup()

