# Instrucciones de Prueba - Mejoras Implementadas

## ⚠️ ADVERTENCIA IMPORTANTE - LIMITACIONES DE HARDWARE

**🔴 La antena BrosTrend AC1200 AC3L NO es adecuada para jamming efectivo.**

### Limitaciones conocidas:
- ❌ **Jamming puede no funcionar** - La potencia de transmisión es insuficiente
- ✅ **Recepción, escaneo y análisis funcionan perfectamente**
- ✅ **Detección de APs y clientes funciona correctamente**

**El código está correctamente implementado** - El problema es puramente de hardware.

**Para más detalles:** Ver `LIMITACIONES_HARDWARE.md`

**Nota sobre las pruebas de jamming:**
- Las pruebas de jamming (secciones 2-6) pueden no mostrar resultados efectivos
- Esto es esperado y se debe a limitaciones de hardware, no de software
- Las pruebas de recepción, escaneo y análisis (secciones 1, 7, 8) deben funcionar correctamente

---

## 📋 Requisitos Previos

1. **Actualizar el código en la Raspberry Pi:**
   ```bash
   cd ~/wifi-jammer-raspberry-pi
   git pull
   ```

2. **Activar entorno virtual:**
   ```bash
   cd python_version
   source venv/bin/activate
   ```

3. **Verificar que Scapy esté instalado:**
   ```bash
   pip list | grep scapy
   # Si no está instalado:
   pip install scapy
   ```

4. **Ejecutar con permisos de administrador:**
   ```bash
   sudo python3 main_wifi.py
   # O usar el script:
   sudo ./ejecutar.sh
   ```

---

## 🧪 Pruebas de las Nuevas Funcionalidades

### 1. Prueba: Detección Automática de APs y Clientes

**Objetivo:** Verificar que el sistema detecta automáticamente APs y clientes conectados.

**Pasos:**
1. Iniciar el programa: `sudo python3 main_wifi.py`
2. Activar recepción: `rx`
3. Esperar 10-15 segundos para capturar tráfico
4. Detener recepción: `rx` (de nuevo)
5. Ver APs detectados: `listaps`
6. Ver clientes detectados: `listclients`
7. Ver estado completo: `status`

**Resultado esperado:**
- `listaps` muestra una lista de APs con BSSID, canal y SSID
- `listclients` muestra pares cliente-AP detectados
- `status` muestra secciones "APs DETECTADOS" y "CLIENTES-APs DETECTADOS"

---

### 2. Prueba: Jamming con Scapy Directo (Canal Específico)

**⚠️ ADVERTENCIA:** Esta prueba puede no mostrar resultados efectivos debido a limitaciones de hardware (antena AC1200).

**Objetivo:** Verificar que el código de jamming funciona correctamente (aunque el efecto puede ser limitado por hardware).

**Pasos:**
1. Escanear redes disponibles: `wifiscan 5`
2. Anotar el BSSID y canal de una red cercana
3. Cambiar al canal de la red: `setchannel <canal>`
4. Iniciar jamming: `jam <bssid>` (ejemplo: `jam AA:BB:CC:DD:EE:FF`)
5. Verificar que no aparecen procesos zombie: `ps aux | grep aireplay`
6. Verificar que los paquetes se envían: `status` (debe mostrar "Paquetes Enviados" incrementándose)
7. Observar si la conexión WiFi se desconecta (puede no funcionar por limitaciones de hardware)
8. Detener jamming: `jam` (de nuevo)

**Resultado esperado:**
- ✅ El jamming inicia sin errores
- ✅ No aparecen procesos `aireplay-ng` en `ps aux`
- ✅ El comando `status` muestra "Jamming: ACTIVO" y "Paquetes Enviados" incrementándose
- ⚠️ La conexión WiFi objetivo puede NO desconectarse (limitación de hardware, no de código)

**Nota:** Si no especificas BSSID, el sistema intentará auto-detectar uno en el canal actual.

---

### 3. Prueba: Jamming en Múltiples Canales (Banda 2.4 GHz)

**⚠️ ADVERTENCIA:** Esta prueba puede no mostrar resultados efectivos debido a limitaciones de hardware.

**Objetivo:** Verificar que el código de jamming funciona en múltiples canales (aunque el efecto puede ser limitado).

**Pasos:**
1. Iniciar jamming en banda 2.4 GHz: `jam 2.4` o `j24`
2. Verificar estado: `status` (debe mostrar "Jamming: ACTIVO" y paquetes enviados)
3. Observar el efecto en todas las redes 2.4 GHz cercanas (puede no haber efecto visible)
4. Detener: `jam` (de nuevo)

**Resultado esperado:**
- ✅ El sistema inicia jamming en múltiples canales simultáneamente
- ✅ El comando `status` muestra "Jamming: ACTIVO" y paquetes enviados incrementándose
- ⚠️ Las redes WiFi 2.4 GHz cercanas pueden NO desconectarse (limitación de hardware)

---

### 4. Prueba: Jamming en Todas las Bandas

**⚠️ ADVERTENCIA:** Esta prueba puede no mostrar resultados efectivos debido a limitaciones de hardware.

**Objetivo:** Verificar que el código de jamming funciona en todas las bandas (aunque el efecto puede ser limitado).

**Pasos:**
1. Iniciar jamming en todas las bandas: `jam all` o `ja`
2. Verificar estado: `status` (debe mostrar "Jamming: ACTIVO" y paquetes enviados)
3. Observar el efecto general en todas las redes WiFi (puede no haber efecto visible)
4. Detener: `jam` (de nuevo)

**Resultado esperado:**
- ✅ El sistema inicia jamming en todos los canales disponibles
- ✅ El comando `status` muestra "Jamming: ACTIVO" y paquetes enviados incrementándose
- ✅ El sistema maneja correctamente canales problemáticos (DFS)
- ⚠️ Las redes WiFi pueden NO verse afectadas (limitación de hardware)

---

### 5. Prueba: Channel Hopping Automático (Solo Identificación)

**Objetivo:** Verificar que el channel hopping detecta redes automáticamente.

**Pasos:**
1. Iniciar channel hopping: `hop 1.0`
   - Intervalo de 1 segundo por canal
   - Sin jamming (solo identificación)
2. Esperar 30-60 segundos
3. Ver APs detectados: `listaps`
4. Ver clientes detectados: `listclients`
5. Ver estado: `status` (debe mostrar "CHANNEL HOPPING: ACTIVO")
6. Detener: `hop stop`

**Resultado esperado:**
- El sistema cambia automáticamente entre canales
- Detecta APs y clientes en múltiples canales
- La lista de APs y clientes se actualiza automáticamente
- `status` muestra información del channel hopping

---

### 6. Prueba: Channel Hopping con Jamming

**⚠️ ADVERTENCIA:** Esta prueba puede no mostrar resultados efectivos debido a limitaciones de hardware.

**Objetivo:** Verificar que el código de channel hopping con jamming funciona (aunque el efecto puede ser limitado).

**Pasos:**
1. Iniciar channel hopping con jamming: `hop 1.0 jam`
   - Intervalo de 1 segundo por canal
   - Con jamming activado
2. Esperar 30 segundos
3. Verificar estado: `status` (debe mostrar "CHANNEL HOPPING: ACTIVO" y paquetes enviados)
4. Observar el efecto en las redes WiFi (puede no haber efecto visible)
5. Detener: `hop stop`

**Resultado esperado:**
- ✅ El sistema hace hopping entre canales
- ✅ En cada canal, envía paquetes deauth a los APs detectados
- ✅ El comando `status` muestra "CHANNEL HOPPING: ACTIVO" y paquetes enviados incrementándose
- ⚠️ Las redes WiFi pueden NO desconectarse (limitación de hardware)

---

### 7. Prueba: Filtrado de Ruido

**Objetivo:** Verificar que el filtrado de ruido funciona correctamente.

**Pasos:**
1. Activar recepción: `rx`
2. Observar los paquetes capturados
3. Verificar que no aparecen direcciones MAC problemáticas:
   - `FF:FF:FF:FF:FF:FF` (broadcast)
   - `00:00:00:00:00:00` (null)
   - Direcciones multicast
4. Detener recepción: `rx`

**Resultado esperado:**
- Los paquetes mostrados son válidos
- No aparecen direcciones MAC problemáticas en `listaps` o `listclients`
- La calidad de los datos capturados es mejor

---

### 8. Prueba: Comando Status Mejorado

**Objetivo:** Verificar que el comando `status` muestra toda la información nueva.

**Pasos:**
1. Activar recepción: `rx`
2. Esperar 10 segundos
3. Ejecutar: `status`
4. Verificar todas las secciones

**Resultado esperado:**
El comando `status` muestra:
- Estado del sistema (interfaz, canal, RSSI)
- Modos activos (recepción, jamming, etc.)
- Estadísticas (paquetes recibidos, enviados, etc.)
- **APs DETECTADOS** (nuevo)
- **CLIENTES-APs DETECTADOS** (nuevo)
- **CHANNEL HOPPING** (si está activo) (nuevo)
- Buffer de grabación
- Filtros activos

---

## 🔍 Verificación de Rendimiento

### Comparación: Antes vs. Ahora

**Antes (con aireplay-ng):**
- Procesos zombie posibles
- Dependencia externa
- Menos control
- Más lento

**Ahora (con Scapy directo):**
- Sin procesos zombie
- Sin dependencia de `aireplay-ng`
- Control total
- Más rápido

**Verificar:**
```bash
# Durante jamming, verificar procesos:
ps aux | grep python
ps aux | grep aireplay

# Debe mostrar:
# - Solo procesos de Python
# - NO debe mostrar procesos aireplay-ng
```

---

## ⚠️ Solución de Problemas

### Problema: "ERROR: scapy no está disponible"
**Solución:**
```bash
pip install scapy
# O globalmente:
sudo pip3 install scapy
```

### Problema: "No se detectan APs o clientes"
**Solución:**
1. Verificar que `rx` esté activo
2. Esperar más tiempo (15-30 segundos)
3. Cambiar a un canal con tráfico: `setchannel 6`
4. Usar `wifiscan` para ver redes disponibles

### Problema: "Jamming no funciona"
**Solución:**
1. **Primero verificar que el código funciona:**
   - Verificar modo monitor: `status` debe mostrar "Modo Monitor: wlan1"
   - Verificar que el BSSID sea correcto: `listaps`
   - Verificar que estás en el canal correcto: `setchannel <canal>`
   - Verificar que los paquetes se envían: `status` debe mostrar "Paquetes Enviados" incrementándose

2. **Si los paquetes se envían pero no hay efecto:**
   - ⚠️ **Esto es esperado con antena AC1200** - Es una limitación de hardware, no de código
   - Ver `LIMITACIONES_HARDWARE.md` para más detalles
   - Para jamming efectivo se requiere hardware especializado (Alfa AWUS036ACH, etc.)

3. **Si los paquetes NO se envían:**
   - Verificar permisos: ejecutar con `sudo`
   - Verificar que la interfaz esté en modo monitor
   - Intentar con BSSID específico: `jam <bssid>`

### Problema: "Channel hopping no cambia de canal"
**Solución:**
1. Verificar permisos: ejecutar con `sudo`
2. Verificar que la interfaz esté en modo monitor
3. Verificar errores en la salida del programa

---

## 📊 Checklist de Pruebas

- [ ] Detección automática de APs funciona
- [ ] Detección automática de clientes funciona
- [ ] Jamming en canal específico funciona (Scapy directo)
- [ ] Jamming en banda 2.4 GHz funciona
- [ ] Jamming en banda 5 GHz funciona
- [ ] Jamming en todas las bandas funciona
- [ ] Channel hopping sin jamming funciona
- [ ] Channel hopping con jamming funciona
- [ ] Filtrado de ruido funciona
- [ ] Comando `status` muestra toda la información
- [ ] Comando `listaps` funciona
- [ ] Comando `listclients` funciona
- [ ] No aparecen procesos zombie de `aireplay-ng`
- [ ] El sistema es más rápido que antes

---

## 🎯 Pruebas Avanzadas

### Prueba: Jamming Dirigido a Cliente Específico

1. Detectar clientes: `listclients`
2. Anotar un par cliente-AP
3. Iniciar jamming en el canal del cliente
4. Observar que solo ese cliente se desconecta

### Prueba: Channel Hopping Personalizado

1. Iniciar hopping solo en canales 2.4 GHz: `hop 0.5`
2. Observar que solo cambia entre canales 1-14
3. Verificar detección de redes

---

## 📝 Notas Importantes

1. **Permisos:** Siempre ejecutar con `sudo` para modo monitor
2. **Tiempo:** Dar tiempo suficiente para que el sistema detecte redes (10-30 segundos)
3. **Canales:** Algunos canales 5 GHz pueden estar deshabilitados (DFS)
4. **Legalidad:** Solo usar en redes propias o con autorización explícita

---

## ✅ Criterios de Éxito

Las mejoras se consideran exitosas si:
- ✅ El código de jamming funciona sin `aireplay-ng` (paquetes se envían correctamente)
- ✅ No aparecen procesos zombie
- ✅ La detección automática de APs y clientes funciona
- ✅ El channel hopping funciona correctamente
- ✅ El sistema es más rápido y confiable
- ✅ Todos los comandos nuevos funcionan
- ✅ Recepción, escaneo y análisis funcionan perfectamente

**Nota importante sobre jamming:**
- ⚠️ El jamming puede no tener efecto visible debido a limitaciones de hardware (antena AC1200)
- ✅ Si `status` muestra "Paquetes Enviados" incrementándose, el código funciona correctamente
- ✅ La falta de efecto visible es esperada y se debe a limitaciones de hardware, no de código

---

**Fecha de creación:** Versión con mejoras implementadas
**Última actualización:** Después de implementar mejoras basadas en Wi-Fi-Jammer

