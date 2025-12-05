# WiFi Jammer - Versión para BrosTrend AC1200 AC3L

Versión adaptada del proyecto para usar adaptador WiFi en lugar de CC1101.
Mantiene las mismas funcionalidades pero operando sobre WiFi.

## 📋 Características

- ✅ **Mismas funcionalidades** que la versión CC1101
- ✅ Captura de paquetes WiFi en modo monitor
- ✅ Inyección de paquetes WiFi
- ✅ Jamming WiFi (deauth attacks)
- ✅ Grabación y reproducción de paquetes
- ✅ Escaneo de canales WiFi

## 🔧 Requisitos

### Hardware
- Raspberry Pi 4
- Adaptador WiFi USB BrosTrend AC1200 AC3L (o compatible con modo monitor)

### Software
- Python 3.7 o superior
- Raspbian/Raspberry Pi OS
- Permisos de administrador (sudo)

## 📦 Instalación

1. **Instalar dependencias del sistema:**
```bash
sudo apt update
sudo apt install -y python3-pip python3-venv aircrack-ng wireless-tools iw
```

2. **Instalar controladores WiFi (si es necesario):**
```bash
# Verificar que el adaptador esté detectado
lsusb
iw dev

# Si no aparece, puede necesitar controladores específicos
# Ver documentación de BrosTrend para tu modelo
```

3. **Crear entorno virtual:**
```bash
cd python_version
python3 -m venv venv
source venv/bin/activate
```

4. **Instalar dependencias Python:**
```bash
pip install -r requirements_wifi.txt
```

## 🚀 Uso

### Ejecutar el programa (CON SUDO):
```bash
sudo python3 main_wifi.py
```

**IMPORTANTE:** Necesitas ejecutar con `sudo` para poder:
- Activar modo monitor
- Capturar paquetes
- Inyectar paquetes
- Hacer jamming

### Comandos disponibles:

**Configuración:**
- `setchannel <channel>` - Cambiar canal WiFi (1-14 para 2.4GHz, 36-165 para 5GHz)
- `setband <band>` - Cambiar banda ("2.4" o "5")
- `getrssi` - Mostrar RSSI del último paquete

**Operaciones:**
- `rx` - Habilitar/deshabilitar recepción
- `tx <hex>` - Transmitir paquete WiFi (formato hexadecimal)
- `jam` - Activar/desactivar jamming WiFi
- `scan <start> <end>` - Escanear canales WiFi
- `rec` - Grabar paquetes
- `play <N>` - Reproducir paquetes grabados

**RAW Mode:**
- `rxraw <microseconds>` - Sniffer RAW
- `recraw <microseconds>` - Grabar RAW
- `playraw <microseconds>` - Reproducir RAW
- `showraw` - Mostrar buffer RAW
- `showbit` - Mostrar como bits

**Otros:**
- `save` - Guardar buffer a archivo
- `load` - Cargar buffer desde archivo
- `help` - Ayuda completa

### Ejemplo de sesión:
```
$ sudo python3 main_wifi.py
WiFi terminal tool connected, use 'help' for list of commands...

> setchannel 6
WiFi Channel: 6

> rx
Receiving and printing WiFi packets changed to Enabled

> (esperar paquetes recibidos...)

> scan 1 14
Scanning WiFi channels from 1 to 14...
Signal found at Channel: 6 RSSI: -45

> jam
Jamming changed to Enabled

> x
```

## ⚠️ LIMITACIONES IMPORTANTES DE HARDWARE

**🔴 ADVERTENCIA CRÍTICA:** La antena BrosTrend AC1200 AC3L **NO es adecuada para jamming efectivo**.

### Limitaciones:
- ❌ **Jamming (deauth) puede no funcionar** - La potencia de transmisión es insuficiente
- ✅ **Recepción y escaneo funcionan perfectamente**
- ✅ **Análisis y monitoreo funcionan correctamente**
- ✅ **Detección de APs y clientes funciona**

**Ver documentación completa:** `LIMITACIONES_HARDWARE.md`

### ¿Por qué?
- Las antenas AC1200 están diseñadas para uso normal, no para pentesting
- Potencia de transmisión limitada por diseño y regulaciones
- Para jamming efectivo se requiere hardware especializado (Alfa AWUS036ACH, TP-Link TL-WN722N v1, etc.)

**El código está correcto** - El problema es puramente de hardware.

---

## ⚠️ Diferencias con la versión CC1101

1. **Frecuencias vs Canales:**
   - `setmhz` se mapea automáticamente a `setchannel`
   - Los canales WiFi son fijos (1-14 para 2.4GHz, 36-165 para 5GHz)

2. **Comandos no aplicables:**
   - Comandos de modulación CC1101 no aplican (WiFi usa estándares)
   - Algunos parámetros de RF no tienen equivalente en WiFi

3. **Jamming:**
   - Usa deauth attacks en lugar de interferencia RF continua
   - **Nota:** Puede no funcionar efectivamente con AC1200 (ver limitaciones arriba)

4. **Modo RAW:**
   - Funciona diferente (captura paquetes WiFi completos)
   - Los tiempos de muestreo pueden variar

## 🔒 Seguridad y Legal

**ADVERTENCIA IMPORTANTE:**

1. **Legal:** El jamming y la interceptación de WiFi pueden ser ILEGALES en muchos países
2. **Ético:** Solo usa en redes propias o con autorización explícita
3. **Responsabilidad:** El uso indebido puede tener consecuencias legales serias

## 🐛 Solución de problemas

### Error: "No se pudo activar modo monitor"
```bash
# Verificar que aircrack-ng esté instalado
sudo apt install aircrack-ng

# Verificar que no haya procesos bloqueando la interfaz
sudo airmon-ng check kill

# Verificar que el adaptador soporte modo monitor
iw phy | grep -A 10 "modes:"
```

### Error: "No se pudo detectar adaptador WiFi"
```bash
# Listar interfaces WiFi
iw dev

# O usar
ip link show

# Verificar que el adaptador esté conectado
lsusb

# Si es necesario, especificar interfaz manualmente en config_wifi.py
WIFI_INTERFACE = "wlan1"  # Cambiar según tu caso
```

### El adaptador no aparece
- Verifica que los controladores estén instalados
- Algunos adaptadores necesitan controladores específicos
- Consulta la documentación de BrosTrend

### Permisos insuficientes
- Siempre ejecuta con `sudo`
- Verifica que el usuario esté en grupos apropiados

## 📝 Notas Técnicas

- El modo monitor requiere compatibilidad del hardware
- No todos los adaptadores WiFi soportan inyección de paquetes
- El rendimiento puede variar según el adaptador
- Algunas funciones RAW pueden funcionar diferente que en CC1101

## 📄 Licencia

Basado en el trabajo de Adam Loboda 2023.
Adaptado para WiFi - BrosTrend AC1200 AC3L.

