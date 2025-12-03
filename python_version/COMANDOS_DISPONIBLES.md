# 📋 Comandos Disponibles - WiFi Jammer

## 🔧 COMANDOS BÁSICOS

| Comando | Descripción | Ejemplo |
|---------|-------------|---------|
| `setchannel <channel>` | Cambiar canal WiFi | `setchannel 6` (2.4GHz: 1-14, 5GHz: 36-165) |
| `setband <band>` | Cambiar banda | `setband 2.4` o `setband 5` |
| `getrssi` | Mostrar RSSI del último paquete | `getrssi` |
| `status` | Mostrar estado y estadísticas actuales | `status` |

## 🔍 ESCANEO

| Comando | Descripción | Ejemplo |
|---------|-------------|---------|
| `scan <start> <stop>` | Escanear rango de canales por señal | `scan 1 14` |
| `wifiscan [duration]` | Escanear y listar redes WiFi | `wifiscan 5` (default: 3 seg) |

## 📡 RECEPCIÓN/TRANSMISIÓN

| Comando | Descripción | Ejemplo |
|---------|-------------|---------|
| `rx` | Activar/desactivar recepción de paquetes | `rx` |
| `tx <hex-vals>` | Enviar paquete WiFi (formato hexadecimal) | `tx AABBCCDD` |
| `chat` | Modo chat (envío/recepción de texto) | `chat` |

## 🎯 JAMMING (Interferencia WiFi)

El comando `jam` tiene múltiples opciones para saturar redes WiFi:

### Opciones de Jamming:

| Comando | Descripción | Efecto |
|---------|-------------|--------|
| `jam` | Canal actual | Interfiere solo el canal actual |
| `jam <canal>` | Canal específico | Interfiere un canal específico | `jam 6` |
| `jam 2.4` | Banda 2.4 GHz | Interfiere TODOS los canales 1-14 simultáneamente | `jam 2.4` |
| `jam 5` | Banda 5 GHz | Interfiere TODOS los canales 5GHz simultáneamente | `jam 5` |
| `jam all` | Todas las bandas | Interfiere TODOS los canales (2.4 y 5 GHz) simultáneamente | `jam all` |
| `jam <bssid>` | Red específica | Interfiere una red específica por MAC | `jam AA:BB:CC:DD:EE:FF` |
| `jam <canal> <bssid>` | Red en canal | Interfiere red específica en canal específico | `jam 6 AA:BB:CC:DD:EE:FF` |
| `jam 2.4 <bssid>` | Red en banda 2.4 | Interfiere red en todos los canales 2.4GHz | `jam 2.4 AA:BB:CC:DD:EE:FF` |
| `jam 5 <bssid>` | Red en banda 5 | Interfiere red en todos los canales 5GHz | `jam 5 AA:BB:CC:DD:EE:FF` |
| `jam all <bssid>` | Red en todas las bandas | Interfiere red en TODOS los canales | `jam all AA:BB:CC:DD:EE:FF` |

**⚠️ NOTA:** Los comandos `jam 2.4`, `jam 5` y `jam all` crean múltiples procesos simultáneos para saturar todos los canales de forma inmediata.

## 💾 GRABACIÓN

| Comando | Descripción | Ejemplo |
|---------|-------------|---------|
| `rec` | Activar/desactivar grabación de paquetes | `rec` |
| `add <hex-vals>` | Añadir paquete manualmente al buffer | `add AABBCCDD` |
| `show` | Mostrar contenido del buffer de grabación | `show` |
| `flush` | Limpiar buffer de grabación | `flush` |
| `play <N>` | Reproducir paquetes grabados | `play 0` (todos) o `play 3` (3er paquete) |

## 🔬 RAW MODE

| Comando | Descripción | Ejemplo |
|---------|-------------|---------|
| `rxraw <microseconds>` | Sniffer RAW con intervalo | `rxraw 100` |
| `recraw <microseconds>` | Grabar RAW con intervalo | `recraw 100` |
| `playraw <microseconds>` | Reproducir RAW grabado | `playraw 100` |
| `showraw` | Mostrar buffer en formato RAW | `showraw` |
| `showbit` | Mostrar buffer como bits | `showbit` |
| `addraw <hex-vals>` | Añadir datos RAW manualmente | `addraw AABBCC` |

## 📁 ARCHIVOS

| Comando | Descripción | Ejemplo |
|---------|-------------|---------|
| `save` | Guardar buffer a archivo | `save` |
| `load` | Cargar buffer desde archivo | `load` |
| `export <file>` | Exportar paquetes a PCAP (Wireshark) | `export captura.pcap` |

## 🔎 FILTROS

| Comando | Descripción | Ejemplo |
|---------|-------------|---------|
| `filter bssid <mac>` | Filtrar por BSSID/MAC | `filter bssid AA:BB:CC:DD:EE:FF` |
| `filter ssid <name>` | Filtrar por SSID | `filter ssid MiRed` |
| `filter type <type>` | Filtrar por tipo de paquete | `filter type beacon` |
| `filter clear` | Limpiar todos los filtros | `filter clear` |

## ⚙️ OTROS

| Comando | Descripción | Ejemplo |
|---------|-------------|---------|
| `echo <0\|1>` | Activar/desactivar echo | `echo 1` (activar) |
| `init` | Reinicializar adaptador WiFi | `init` |
| `x` | Detener todas las operaciones activas | `x` |
| `quit` | Salir del programa | `quit` |
| `help` | Mostrar ayuda completa | `help` |

## ⚡ COMANDOS ABREVIADOS (Atajos)

Puedes usar estos atajos para comandos comunes:

| Atajo | Comando Completo | Descripción |
|-------|------------------|-------------|
| `s` | `scan` | Escanear |
| `t` | `tx` | Transmitir |
| `r` | `rx` | Recibir |
| `j` | `jam` | Jamming (canal actual) |
| `j24` | `jam 2.4` | Jamming banda 2.4 GHz |
| `j5` | `jam 5` | Jamming banda 5 GHz |
| `ja` | `jam all` | Jamming todas las bandas |
| `c` | `chat` | Modo chat |
| `st` | `status` | Estado |
| `h` | `help` | Ayuda |
| `q` | `quit` | Salir |
| `x` | `x` | Detener operaciones |
| `w` | `wifiscan` | Escanear WiFi |
| `f` | `filter` | Filtrar |
| `e` | `export` | Exportar |

## 📊 EJEMPLOS DE USO

### 1. Escanear redes WiFi
```
> wifiscan
> wifiscan 5  (durante 5 segundos)
```

### 2. Saturación completa de red WiFi
```
> jam all
```

### 3. Interferir solo banda 2.4 GHz
```
> jam 2.4
```

### 4. Interferir una red específica en todas las bandas
```
> jam all AA:BB:CC:DD:EE:FF
```

### 5. Interferir un canal específico
```
> jam 6
```

### 6. Grabar y reproducir paquetes
```
> rec          (activar grabación)
> rx           (activar recepción)
> show         (ver paquetes grabados)
> play 0       (reproducir todos)
```

### 7. Filtrar por red específica
```
> filter bssid AA:BB:CC:DD:EE:FF
> rx           (solo recibirá paquetes de esa red)
```

### 8. Exportar capturas para Wireshark
```
> export mi_captura.pcap
```

## ⚠️ NOTAS IMPORTANTES

1. **Permisos:** Debes ejecutar con `sudo` para que funcionen todas las características
2. **Modo Monitor:** El programa activa automáticamente el modo monitor cuando es necesario
3. **Jamming Simultáneo:** Los comandos `jam 2.4`, `jam 5` y `jam all` crean múltiples procesos para saturar todos los canales
4. **Legal:** Solo usa en redes propias o con autorización explícita

## 🔗 COMPATIBILIDAD

- Los comandos de CC1101 (como `setmhz`, `setmodulation`) se adaptan automáticamente a WiFi
- El programa detecta automáticamente el adaptador WiFi (wlan0, wlan1, etc.)
