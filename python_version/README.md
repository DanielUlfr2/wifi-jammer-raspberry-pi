# CC1101 Jammer - Versión Python para Raspberry Pi

Migración completa del proyecto de C++/Arduino a Python para Raspberry Pi 4.

## 📋 Características

- ✅ **100% compatible** con la versión original en C++
- ✅ Todos los comandos CLI funcionan igual
- ✅ Misma interfaz de usuario
- ✅ Funcionalidad completa de RF (RX/TX/JAM/RAW)

## 🔧 Requisitos

### Hardware
- Raspberry Pi 4
- Módulo CC1101
- Conexiones SPI según `config.py`

### Software
- Python 3.7 o superior
- Raspbian/Raspberry Pi OS
- SPI habilitado

## 📦 Instalación

1. **Habilitar SPI en Raspberry Pi:**
```bash
sudo raspi-config
# Interface Options → SPI → Enable
sudo reboot
```

2. **Instalar dependencias del sistema:**
```bash
sudo apt update
sudo apt install python3-pip python3-venv -y
```

3. **Crear entorno virtual (recomendado):**
```bash
cd python_version
python3 -m venv venv
source venv/bin/activate
```

4. **Instalar dependencias Python:**
```bash
pip install -r requirements.txt
```

## 🔌 Conexiones

Conecta el CC1101 a la Raspberry Pi según la configuración en `config.py`:

```
Raspberry Pi 4    →    CC1101
─────────────────────────────────
GPIO 11 (SPI0_SCLK)  →  SCK
GPIO 9  (SPI0_MISO)  →  MISO
GPIO 10 (SPI0_MOSI)  →  MOSI
GPIO 8  (SPI0_CE0)   →  SS/CS
GPIO 17              →  GDO0
GPIO 27              →  GDO2 (opcional)
3.3V                 →  VCC
GND                  →  GND
```

**IMPORTANTE:** El CC1101 requiere 3.3V. No conectes a 5V o lo dañarás.

## 🚀 Uso

### Ejecutar el programa:
```bash
python3 main.py
```

### Comandos disponibles:
- `help` - Muestra ayuda completa
- `setmhz 433.92` - Configurar frecuencia
- `rx` - Habilitar recepción
- `tx AABBCCDD` - Transmitir datos (hex)
- `rec` - Grabar señales
- `play 0` - Reproducir señales grabadas
- `scan 430 440` - Escanear frecuencias
- Y muchos más... (ver `help`)

### Ejemplo de sesión:
```
$ python3 main.py
CC1101 terminal tool connected, use 'help' for list of commands...

> setmhz 433.92
Frequency: 433.92 MHz

> rx
Receiving and printing RF packet changed to Enabled

> (esperar señales recibidas...)

> x
```

## ⚙️ Configuración

Edita `config.py` para cambiar:
- Pines GPIO
- Tamaños de buffer
- Valores por defecto del CC1101
- Archivo de almacenamiento

## 🔄 Diferencias con la versión original

1. **Almacenamiento:** Usa archivo pickle en lugar de EEPROM
2. **Plataforma:** Raspberry Pi en lugar de ESP8266
3. **Lenguaje:** Python en lugar de C++/Arduino
4. **Funcionalidad:** Idéntica, mismo comportamiento

## 🐛 Solución de problemas

### Error: "No se pudo comunicar con CC1101"
- Verifica las conexiones SPI
- Asegúrate de que SPI esté habilitado
- Verifica que el módulo CC1101 esté alimentado con 3.3V

### Error: "Permission denied" en SPI
```bash
sudo usermod -a -G spi,gpio $USER
sudo reboot
```

### No recibe señales
- Verifica la antena del CC1101
- Ajusta la frecuencia con `setmhz`
- Prueba diferentes modulaciones

## 📝 Notas

- El código funciona en modo simulación si no hay hardware disponible
- Algunas funciones RAW pueden requerir ajustes de timing
- Compatible con todas las funcionalidades de la versión original

## 📄 Licencia

Basado en el trabajo de Adam Loboda 2023.
Migrado a Python para Raspberry Pi.

