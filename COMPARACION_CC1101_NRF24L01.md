# Comparación: CC1101 vs nRF24L01 PA+LNA para Jamming

## 📊 Resumen Ejecutivo

**Para jamming efectivo, la respuesta depende del objetivo:**

- **CC1101:** Mejor para dispositivos sub-GHz (433 MHz, 315 MHz, 868 MHz, etc.)
- **nRF24L01 PA+LNA:** Mejor para dispositivos 2.4 GHz (WiFi, Bluetooth, Zigbee, etc.)

**Si necesitas jamming de WiFi/Bluetooth → nRF24L01 PA+LNA**  
**Si necesitas jamming de dispositivos RF sub-GHz → CC1101**

---

## 🔍 Comparación Técnica Detallada

### CC1101

#### Especificaciones Técnicas:
- **Rango de Frecuencias:**
  - 300-348 MHz
  - 387-464 MHz
  - 779-928 MHz
- **Potencia de Transmisión:**
  - Hasta +12 dBm (máximo, dependiendo de la banda)
  - Típicamente +10 dBm en 433 MHz
  - Aproximadamente 15-20 mW
- **Sensibilidad de Recepción:**
  - Excelente: -110 dBm a 1.2 kbps
  - -95 dBm a 250 kbps
- **Modulaciones Soportadas:**
  - 2-FSK, GFSK, ASK/OOK, 4-FSK, MSK
- **Velocidad de Datos:**
  - 0.02 a 1621.83 kbps
- **Alcance:**
  - 50-200 metros (dependiendo de condiciones)
  - Mejor en frecuencias más bajas

#### Ventajas para Jamming:
✅ **Excelente para dispositivos sub-GHz:**
- Puertas de garaje (433 MHz, 315 MHz)
- Controles remotos (433.92 MHz)
- Sistemas de alarma (868 MHz)
- Dispositivos IoT sub-GHz
- Sensores inalámbricos

✅ **Mayor alcance en frecuencias bajas:**
- Las frecuencias más bajas penetran mejor obstáculos
- Menos interferencia en bandas sub-GHz

✅ **Flexibilidad de modulación:**
- Soporta múltiples modulaciones
- Útil para diferentes tipos de dispositivos

✅ **Potencia ajustable:**
- Control fino de potencia de transmisión
- Puede reducir potencia para evitar detección

#### Desventajas:
❌ **No funciona para WiFi/Bluetooth:**
- WiFi y Bluetooth operan en 2.4 GHz
- CC1101 no cubre esta frecuencia

❌ **Potencia limitada:**
- +12 dBm máximo puede no ser suficiente para algunos objetivos
- Depende mucho de la antena

---

### nRF24L01 PA+LNA

#### Especificaciones Técnicas:
- **Rango de Frecuencias:**
  - 2.400-2.525 GHz (banda ISM 2.4 GHz)
- **Potencia de Transmisión (con PA):**
  - Hasta +20 dBm (100 mW) con amplificador PA
  - Sin PA: +0 dBm (1 mW)
  - Con PA+LNA: hasta +20 dBm
- **Sensibilidad de Recepción (con LNA):**
  - Excelente: -94 dBm a 2 Mbps
  - -104 dBm a 250 kbps
- **Modulaciones Soportadas:**
  - GFSK (Gaussian Frequency Shift Keying)
- **Velocidad de Datos:**
  - 250 kbps, 1 Mbps, 2 Mbps
- **Alcance:**
  - 50-1000+ metros (con PA+LNA y buena antena)
  - Mejor alcance que CC1101 en 2.4 GHz

#### Ventajas para Jamming:
✅ **Excelente para dispositivos 2.4 GHz:**
- **WiFi (802.11 b/g/n):** Operan en 2.4 GHz
- **Bluetooth:** Opera en 2.4 GHz
- **Zigbee:** Opera en 2.4 GHz
- **Dispositivos IoT 2.4 GHz**

✅ **Mayor potencia de transmisión:**
- +20 dBm (100 mW) vs +12 dBm del CC1101
- **4-8 veces más potencia** que CC1101
- Mejor para jamming efectivo

✅ **Amplificador de bajo ruido (LNA):**
- Mejor recepción de señales débiles
- Mejor para escaneo y análisis

✅ **Alcance superior:**
- Con PA+LNA y buena antena puede alcanzar 1 km+
- Mejor penetración en 2.4 GHz que CC1101 en sub-GHz

#### Desventajas:
❌ **Solo 2.4 GHz:**
- No funciona para dispositivos sub-GHz
- No puede interferir con dispositivos 433 MHz, 315 MHz, etc.

❌ **Modulación limitada:**
- Solo GFSK
- Menos flexibilidad que CC1101

❌ **Más interferencia:**
- La banda 2.4 GHz está muy saturada
- WiFi, Bluetooth, microondas, etc.

---

## 🎯 Comparación Directa

| Característica | CC1101 | nRF24L01 PA+LNA |
|----------------|--------|-----------------|
| **Frecuencias** | 300-928 MHz (sub-GHz) | 2.4-2.5 GHz |
| **Potencia Máxima** | +12 dBm (~15 mW) | +20 dBm (~100 mW) |
| **Potencia Relativa** | 1x | **6-8x más potente** |
| **Alcance (típico)** | 50-200 m | 100-1000+ m |
| **WiFi Jamming** | ❌ No | ✅ Sí |
| **Bluetooth Jamming** | ❌ No | ✅ Sí |
| **Sub-GHz Jamming** | ✅ Sí | ❌ No |
| **Puertas Garaje** | ✅ Sí | ❌ No |
| **Sensibilidad RX** | Excelente | Excelente |
| **Modulaciones** | Múltiples | GFSK |
| **Costo** | 💰 Bajo | 💰💰 Medio |
| **Complejidad** | Media | Media |

---

## 🔥 Para Jamming de WiFi: nRF24L01 PA+LNA es MEJOR

### Razones:

1. **Frecuencia Correcta:**
   - WiFi opera en 2.4 GHz (y 5 GHz)
   - nRF24L01 cubre 2.4 GHz
   - CC1101 NO cubre 2.4 GHz

2. **Mayor Potencia:**
   - nRF24L01 PA+LNA: +20 dBm (100 mW)
   - CC1101: +12 dBm (15 mW)
   - **6-8 veces más potencia** = jamming más efectivo

3. **Mejor Alcance:**
   - Con PA+LNA puede alcanzar distancias mayores
   - Mejor para jamming de redes WiFi lejanas

4. **Diseñado para 2.4 GHz:**
   - Optimizado para la banda ISM 2.4 GHz
   - Mejor rendimiento en esta frecuencia

### Limitaciones del nRF24L01 para WiFi:

⚠️ **Solo cubre 2.4 GHz:**
- WiFi moderno también usa 5 GHz
- nRF24L01 NO puede interferir con 5 GHz
- Para jamming completo de WiFi necesitarías ambos (2.4 y 5 GHz)

⚠️ **Protocolo diferente:**
- nRF24L01 usa GFSK, WiFi usa OFDM
- Para jamming efectivo de WiFi, es mejor usar un adaptador WiFi con modo monitor (como discutimos con AC1200)
- nRF24L01 puede hacer interferencia de ruido, pero no deauth attacks específicos

---

## 🎯 Para Jamming de Dispositivos Sub-GHz: CC1101 es MEJOR

### Razones:

1. **Frecuencia Correcta:**
   - Dispositivos sub-GHz operan en 300-928 MHz
   - CC1101 cubre estas frecuencias
   - nRF24L01 NO cubre sub-GHz

2. **Flexibilidad:**
   - Múltiples modulaciones (ASK/OOK, FSK, etc.)
   - Útil para diferentes tipos de dispositivos

3. **Optimizado para Sub-GHz:**
   - Mejor rendimiento en frecuencias bajas
   - Menos interferencia en estas bandas

---

## 💡 Recomendación Final

### Para Jamming de WiFi/Bluetooth:
**→ nRF24L01 PA+LNA** (pero con limitaciones)

**Nota importante:** Aunque nRF24L01 PA+LNA es mejor que CC1101 para WiFi, **NO es la mejor solución**. Para jamming efectivo de WiFi, es mejor usar:
- **Adaptador WiFi con modo monitor** (Alfa AWUS036ACH, TP-Link TL-WN722N)
- **Inyección de paquetes deauth** (como implementamos en el código)
- **nRF24L01 puede hacer interferencia de ruido**, pero no es tan efectivo como deauth attacks

### Para Jamming de Dispositivos Sub-GHz:
**→ CC1101**

- Puertas de garaje (433 MHz)
- Controles remotos (315 MHz, 433 MHz)
- Sistemas de alarma (868 MHz)
- Sensores inalámbricos sub-GHz

---

## 🔧 Consideraciones Prácticas

### nRF24L01 PA+LNA para WiFi:

**Ventajas:**
- ✅ Mayor potencia que CC1101
- ✅ Cubre 2.4 GHz (donde opera WiFi)
- ✅ Puede hacer interferencia de ruido

**Desventajas:**
- ❌ No puede hacer deauth attacks específicos
- ❌ Solo cubre 2.4 GHz (no 5 GHz)
- ❌ Interferencia de ruido es menos efectiva que deauth

**Conclusión:** Mejor que CC1101 para WiFi, pero **no es la mejor solución**. Para jamming efectivo de WiFi, usa un adaptador WiFi con modo monitor.

### CC1101 para Sub-GHz:

**Ventajas:**
- ✅ Cubre frecuencias sub-GHz
- ✅ Flexibilidad de modulación
- ✅ Buen rendimiento en estas bandas

**Desventajas:**
- ❌ No cubre 2.4 GHz (WiFi/Bluetooth)
- ❌ Potencia limitada comparado con nRF24L01 PA+LNA

**Conclusión:** **La mejor opción** para dispositivos sub-GHz.

---

## 📝 Nota sobre el Proyecto Actual

El proyecto **Cypher CC1101 Jammer** está diseñado para:
- **Dispositivos sub-GHz** (433 MHz, 315 MHz, 868 MHz, etc.)
- **NO para WiFi/Bluetooth**

Si quieres hacer jamming de WiFi, necesitarías:
1. **Adaptador WiFi con modo monitor** (como AC1200, pero mejor hardware)
2. **Código de inyección de paquetes** (como el que implementamos)
3. **nRF24L01 PA+LNA** podría hacer interferencia de ruido, pero no es tan efectivo

---

## ⚠️ Consideraciones Legales

**IMPORTANTE:**
- El jamming de cualquier frecuencia puede ser **ilegal** en muchas jurisdicciones
- Solo usar en dispositivos propios o con autorización explícita
- Las regulaciones de potencia de transmisión deben respetarse
- El uso de amplificadores puede violar leyes locales

---

## 🎯 Resumen de Recomendaciones

| Objetivo | Mejor Opción | Alternativa |
|----------|--------------|-------------|
| **WiFi Jamming** | Adaptador WiFi modo monitor | nRF24L01 PA+LNA (interferencia) |
| **Bluetooth Jamming** | nRF24L01 PA+LNA | Adaptador Bluetooth |
| **Sub-GHz Jamming** | CC1101 | Ninguna alternativa común |
| **Puertas Garaje** | CC1101 | Ninguna alternativa común |
| **Controles Remotos** | CC1101 | Ninguna alternativa común |

---

**Fecha de creación:** Comparación técnica CC1101 vs nRF24L01 PA+LNA  
**Última actualización:** Análisis para jamming efectivo

