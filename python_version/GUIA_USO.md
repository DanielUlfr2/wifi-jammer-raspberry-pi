# Guía de Uso - WiFi Jammer para Raspberry Pi

## 🚀 Inicio Rápido

### 1. Ejecutar el Programa

```bash
# En tu Raspberry Pi
cd ~/wifi-jammer-raspberry-pi/python_version
source venv/bin/activate
sudo python3 main_wifi.py
```

**⚠️ IMPORTANTE:** Siempre ejecuta con `sudo` (necesario para modo monitor)

---

## 📋 Comandos Básicos

### Ver Ayuda
```
help
```
o simplemente:
```
h
```

### Ver Estado del Sistema
```
status
```
o:
```
st
```

Muestra:
- Interfaz WiFi activa
- Canal actual
- RSSI del último paquete
- Modos activos (RX, JAM, REC, CHAT)
- Estadísticas (paquetes recibidos/enviados)
- Filtros activos

---

## 🔍 Escaneo de Redes WiFi

### Escanear y Listar Redes WiFi Disponibles
```
wifiscan
```
o:
```
w
```

**Ejemplo:**
```
> wifiscan
Escaneando redes WiFi (duración: 3s)...

SSID                          BSSID              Canal    RSSI     Último
--------------------------------------------------------------------------------
MiRed                         AA:BB:CC:DD:EE:FF  6        -45 dBm  2s
Casa_WiFi                     11:22:33:44:55:66  1        -67 dBm  5s
```

**Escaneo con duración personalizada:**
```
wifiscan 5
```
(Escanea durante 5 segundos)

### Escanear Canales por Señal
```
scan 1 14
```
Escanea canales del 1 al 14 (banda 2.4 GHz) buscando señales.

**Ejemplo:**
```
> scan 1 14
Escaneando canales WiFi 1 a 14. Presiona Enter para detener...

Señal encontrada en Canal: 6 RSSI: -45 dBm
Señal encontrada en Canal: 11 RSSI: -52 dBm
```

---

## 📡 Configuración de Canal y Banda

### Cambiar Canal WiFi
```
setchannel 6
```

**Canales disponibles:**
- **2.4 GHz:** 1-14
- **5 GHz:** 36-165

**Ejemplo:**
```
> setchannel 6
WiFi Channel: 6
```

### Cambiar Banda
```
setband 2.4
```
o:
```
setband 5
```

### Ver Canal Actual
```
setchannel
```
(Sin parámetros muestra el canal actual)

---

## 📥 Recepción de Paquetes

### Activar Recepción
```
rx
```
o:
```
r
```

**Ejemplo:**
```
> rx
Recepción de paquetes WiFi: ACTIVADA

AABBCCDDEEFF11223344556677889900...
```

Los paquetes se mostrarán en formato hexadecimal.

### Desactivar Recepción
```
rx
```
(Ejecuta el mismo comando para desactivar)

---

## 📤 Transmisión de Paquetes

### Enviar un Paquete
```
tx AABBCCDDEEFF
```
o:
```
t AABBCCDDEEFF
```

**Ejemplo:**
```
> tx AABBCCDDEEFF112233
Transmitiendo paquete WiFi...
Paquete enviado: AABBCCDDEEFF112233
```

**Nota:** Los datos deben estar en formato hexadecimal (pares de caracteres 0-9, A-F)

---

## 🎯 Jamming WiFi

### Activar Jamming (Deauth Attack)
```
jam
```
o:
```
j
```

**Ejemplo:**
```
> jam
Jamming: ACTIVADO (BSSID: Broadcast)
```

### Jamming a una Red Específica
```
jam AA:BB:CC:DD:EE:FF
```
(Reemplaza con el BSSID de la red objetivo)

### Desactivar Jamming
```
jam
```
(Ejecuta el mismo comando para desactivar)

o:
```
x
```
(Detiene todas las operaciones)

---

## 💬 Modo Chat

### Activar Modo Chat
```
chat
```
o:
```
c
```

**Ejemplo:**
```
> chat
Modo chat activado (WiFi). Escribe mensajes directamente.

Hola mundo
```

En modo chat, todo lo que escribas se enviará como paquete WiFi.

### Salir del Modo Chat
```
x
```

---

## 🎙️ Grabación de Paquetes

### Activar Grabación
```
rec
```

**Ejemplo:**
```
> rec
Grabación: ACTIVADA
```

Los paquetes recibidos se guardarán en el buffer.

### Ver Paquetes Grabados
```
show
```

**Ejemplo:**
```
> show
Paquetes almacenados en buffer:

Frame 1 : AABBCCDDEEFF112233445566
Frame 2 : 112233445566778899AABBCC
Frame 3 : FFEEDDCCBBAA998877665544
```

### Reproducir Paquetes Grabados
```
play 0
```
(Reproduce todos los paquetes)

```
play 2
```
(Reproduce solo el frame número 2)

### Limpiar Buffer
```
flush
```

### Añadir Paquete Manualmente
```
add AABBCCDDEEFF
```

---

## 🔧 Filtros

### Filtrar por BSSID (MAC Address)
```
filter bssid AA:BB:CC:DD:EE:FF
```
o:
```
f bssid AA:BB:CC:DD:EE:FF
```

**Ejemplo:**
```
> filter bssid AA:BB:CC:DD:EE:FF
Filtro BSSID configurado: AA:BB:CC:DD:EE:FF
```

Solo capturará paquetes de esa red específica.

### Filtrar por SSID (Nombre de Red)
```
filter ssid MiRed
```

**Ejemplo:**
```
> filter ssid MiRed
Filtro SSID configurado: MiRed
```

### Filtrar por Tipo de Paquete
```
filter type beacon
```
(Tipos: `beacon`, `data`, etc.)

### Ver Filtros Activos
```
filter
```
(Sin parámetros muestra los filtros actuales)

### Limpiar Filtros
```
filter clear
```

---

## 📊 Estadísticas y RSSI

### Ver RSSI del Último Paquete
```
getrssi
```

**Ejemplo:**
```
> getrssi
RSSI: -45 dBm
```

### Ver Estadísticas Completas
```
status
```

Muestra:
- Paquetes recibidos
- Paquetes enviados
- Paquetes perdidos
- Tasa de paquetes por segundo
- Redes detectadas
- Estado del buffer

---

## 💾 Guardar y Cargar

### Guardar Buffer a Archivo
```
save
```

Guarda el buffer de grabación en `wifi_eeprom.dat`

### Cargar Buffer desde Archivo
```
load
```

### Exportar a PCAP (Wireshark)
```
export captura.pcap
```
o:
```
e captura.pcap
```

**Ejemplo:**
```
> export mi_captura.pcap
Exportando paquetes a mi_captura.pcap...
Exportados 100 paquetes a mi_captura.pcap
Exportación completada: mi_captura.pcap
```

Luego puedes abrir el archivo en Wireshark para análisis detallado.

---

## 🔬 Modo RAW

### Sniffer RAW
```
rxraw 1000
```
(Captura RAW con intervalo de 1000 microsegundos)

### Grabar RAW
```
recraw 1000
```

### Reproducir RAW
```
playraw 1000
```

### Ver Datos RAW
```
showraw
```

### Ver como Bits
```
showbit
```

---

## 🛠️ Otros Comandos

### Reinicializar Adaptador
```
init
```

### Activar/Desactivar Echo
```
echo 1
```
(Activar)

```
echo 0
```
(Desactivar)

### Detener Todo
```
x
```
Detiene todas las operaciones activas (RX, JAM, REC, etc.)

### Salir del Programa
```
quit
```
o:
```
q
```

---

## 📝 Ejemplos de Uso Común

### Ejemplo 1: Escanear y Analizar Redes

```bash
# 1. Ejecutar programa
sudo python3 main_wifi.py

# 2. Escanear redes
> wifiscan

# 3. Ver estado
> status

# 4. Cambiar a canal de una red específica
> setchannel 6

# 5. Filtrar solo esa red
> filter bssid AA:BB:CC:DD:EE:FF

# 6. Activar recepción
> rx
```

### Ejemplo 2: Grabar y Reproducir

```bash
# 1. Activar grabación
> rec

# 2. Esperar a que capture paquetes (o enviar algunos con tx)

# 3. Ver qué se grabó
> show

# 4. Reproducir todo
> play 0

# 5. Guardar para después
> save
```

### Ejemplo 3: Análisis con Wireshark

```bash
# 1. Activar recepción
> rx

# 2. Esperar a capturar paquetes

# 3. Exportar a PCAP
> export analisis.pcap

# 4. Transferir archivo a PC
# (usar scp, sftp, o USB)

# 5. Abrir en Wireshark para análisis detallado
```

### Ejemplo 4: Jamming Selectivo

```bash
# 1. Escanear redes
> wifiscan

# 2. Identificar BSSID objetivo
# (ejemplo: AA:BB:CC:DD:EE:FF)

# 3. Activar jamming específico
> jam AA:BB:CC:DD:EE:FF

# 4. Detener cuando termines
> x
```

---

## ⌨️ Comandos Abreviados

| Comando Completo | Abreviado |
|------------------|-----------|
| `scan` | `s` |
| `tx` | `t` |
| `rx` | `r` |
| `jam` | `j` |
| `chat` | `c` |
| `status` | `st` |
| `help` | `h` |
| `quit` | `q` |
| `wifiscan` | `w` |
| `filter` | `f` |
| `export` | `e` |
| `x` | `x` |

---

## ⚠️ Notas Importantes

### Permisos
- **Siempre ejecuta con `sudo`** - Necesario para modo monitor
- Sin permisos de administrador, muchas funciones no funcionarán

### Modo Monitor
- El programa intenta activar modo monitor automáticamente
- Si falla, verifica que aircrack-ng esté instalado
- Algunos adaptadores pueden no soportar modo monitor

### Captura de Paquetes
- La captura es pasiva (solo escucha)
- No todos los paquetes se capturan (depende del canal)
- Los paquetes cifrados se capturan pero no se pueden leer sin la clave

### Jamming
- **⚠️ LEGAL:** Solo usa en redes propias o con autorización
- El jamming puede ser ilegal en muchos países
- Usa responsablemente

---

## 🔄 Flujo de Trabajo Típico

1. **Iniciar programa:**
   ```bash
   sudo python3 main_wifi.py
   ```

2. **Ver estado inicial:**
   ```
   > status
   ```

3. **Escanear redes:**
   ```
   > wifiscan
   ```

4. **Configurar canal:**
   ```
   > setchannel 6
   ```

5. **Aplicar filtros (opcional):**
   ```
   > filter bssid AA:BB:CC:DD:EE:FF
   ```

6. **Activar recepción/grabación:**
   ```
   > rx
   ```
   o
   ```
   > rec
   ```

7. **Analizar resultados:**
   ```
   > show
   > status
   ```

8. **Exportar si es necesario:**
   ```
   > export analisis.pcap
   ```

9. **Salir:**
   ```
   > quit
   ```

---

## 🆘 Ayuda Rápida

### Si algo no funciona:

1. **Verificar permisos:**
   ```bash
   sudo whoami  # Debe devolver "root"
   ```

2. **Verificar adaptador:**
   ```bash
   lsusb
   iw dev
   ```

3. **Verificar modo monitor:**
   ```bash
   iw dev wlan0 info
   # Debe mostrar "type monitor"
   ```

4. **Reiniciar adaptador:**
   ```
   > init
   ```

5. **Ver logs del sistema:**
   ```bash
   dmesg | tail -20
   ```

---

## 📚 Recursos Adicionales

- **README_WIFI.md** - Documentación técnica completa
- **INSTALACION_RASPBERRY.md** - Guía de instalación
- **GUIA_INSTALACION_RASPBERRY.md** - Configuración inicial de Raspberry Pi

---

**¡Listo para usar!** 🚀

Si tienes dudas sobre algún comando, usa `help` para ver la lista completa.

