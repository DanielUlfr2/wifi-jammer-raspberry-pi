# Guía de Instalación para Raspberry Pi 4

## 💾 Capacidad de SD Card (32 GB)

### ✅ **SÍ, 32 GB es suficiente para el proyecto**

**Desglose del espacio necesario:**

1. **Raspberry Pi OS (Lite)**: ~4-5 GB
2. **Raspberry Pi OS (Full con Desktop)**: ~8-12 GB
3. **Dependencias del sistema**: ~500 MB - 1 GB
   - Python 3.x y pip
   - aircrack-ng, wireless-tools, iw
   - Librerías del sistema
4. **Dependencias Python**: ~200-500 MB
   - scapy
   - pyric
   - Otros paquetes
5. **Proyecto WiFi Jammer**: ~10-50 MB (código y datos)
6. **Espacio para logs y grabaciones**: ~1-5 GB
7. **Sistema operativo (overhead)**: ~2-3 GB

**Total estimado: 10-20 GB aproximadamente**

**Con 32 GB tendrás:**
- ✅ Suficiente espacio para el sistema operativo
- ✅ Espacio para el proyecto y dependencias
- ✅ Espacio para guardar capturas de paquetes (PCAP)
- ✅ Espacio para buffers de grabación
- ✅ Margen de seguridad (~10-15 GB libres)

**Recomendación:**
- **Mínimo**: 16 GB (funcionará, pero ajustado)
- **Recomendado**: 32 GB (ideal para este proyecto) ✅
- **Óptimo**: 64 GB o más (si planeas guardar muchas capturas)

---

## 🐧 Sistema Operativo Recomendado

### **Raspberry Pi OS (64-bit) - RECOMENDADO**

**Versión específica:**
- **Raspberry Pi OS (64-bit) Bullseye o Bookworm**
- **Versión Lite** (sin escritorio, más ligera) o **Full** (con escritorio)

#### ¿Por qué Raspberry Pi OS?

1. ✅ **Oficial y optimizado** para Raspberry Pi
2. ✅ **Soporte completo** de hardware (GPIO, SPI, USB)
3. ✅ **Comunidad grande** y documentación extensa
4. ✅ **Actualizaciones frecuentes** y soporte a largo plazo
5. ✅ **Compatible** con todas las herramientas necesarias

### Descarga e Instalación:

1. **Descargar Raspberry Pi Imager:**
   - Sitio oficial: https://www.raspberrypi.com/software/
   - Disponible para Windows, macOS y Linux

2. **Instalar Raspberry Pi OS:**
   ```bash
   # Usando Raspberry Pi Imager:
   # 1. Seleccionar "Raspberry Pi OS (64-bit)"
   # 2. Elegir "Raspberry Pi OS (64-bit) Lite" para versión sin escritorio
   #    O "Raspberry Pi OS (64-bit)" para versión completa
   # 3. Seleccionar tu SD card
   # 4. Configurar:
   #    - Habilitar SSH (si lo necesitas)
   #    - Configurar usuario y contraseña
   #    - Configurar WiFi (opcional)
   # 5. Escribir la imagen
   ```

3. **Configuraciones iniciales recomendadas:**
   ```bash
   # Después de la primera boot:
   sudo raspi-config
   
   # Recomendado configurar:
   # - Expand Filesystem (para usar toda la SD)
   # - Change User Password
   # - Enable SSH (si lo necesitas)
   # - Update (para actualizar el config tool)
   ```

---

## 🔄 Alternativas de Sistemas Operativos

Si prefieres otra distribución:

### 1. **Ubuntu 22.04 LTS (64-bit)**
   - ✅ Soporte a largo plazo
   - ✅ Muy estable
   - ⚠️ Requiere al menos 32 GB
   - ⚠️ Más pesado que Raspberry Pi OS
   - **Recomendado si:** Ya conoces Ubuntu

### 2. **DietPi**
   - ✅ Muy ligero (~2 GB)
   - ✅ Optimizado para single-board computers
   - ✅ Interfaz de configuración fácil
   - **Recomendado si:** Quieres máxima optimización

### 3. **Kali Linux (ARM)**
   - ✅ Herramientas de pentesting incluidas
   - ✅ aircrack-ng preinstalado
   - ⚠️ Más pesado
   - **Recomendado si:** Quieres herramientas de pentesting adicionales

**NOTA:** Para este proyecto específico, **Raspberry Pi OS** es la mejor opción.

---

## 📋 Requisitos del Sistema

### Hardware:
- ✅ Raspberry Pi 4 (cualquier modelo: 2GB, 4GB u 8GB RAM)
- ✅ SD Card de 32 GB (Class 10 o superior recomendado)
- ✅ Adaptador WiFi USB BrosTrend AC1200 AC3L
- ✅ Fuente de alimentación oficial (5V, 3A mínimo)

### Software:
- ✅ Raspberry Pi OS (64-bit) Bullseye o superior
- ✅ Python 3.7 o superior (incluido en Raspberry Pi OS)
- ✅ Conexión a Internet (para instalar dependencias)

---

## 🚀 Pasos de Instalación Completos

### 1. Preparar la SD Card

```bash
# Usando Raspberry Pi Imager (método recomendado)
# Descargar desde: https://www.raspberrypi.com/software/

# O usando comandos (Linux/Mac):
# 1. Descargar imagen desde raspberrypi.com
# 2. Descomprimir (si está en .zip)
# 3. Escribir a SD:
#    sudo dd if=raspios-image.img of=/dev/sdX bs=4M status=progress
#    sync
```

### 2. Primera Configuración

```bash
# Boot la Raspberry Pi por primera vez
# Login: pi / raspberry (cambiar después)

# Actualizar el sistema
sudo apt update
sudo apt upgrade -y

# Expandir filesystem para usar toda la SD
sudo raspi-config
# Seleccionar: Advanced Options → Expand Filesystem
# Reboot después
```

### 3. Instalar Dependencias del Sistema

```bash
# Instalar herramientas básicas
sudo apt update
sudo apt install -y \
    python3-pip \
    python3-venv \
    git \
    build-essential \
    libpcap-dev \
    aircrack-ng \
    wireless-tools \
    iw

# Verificar instalación
python3 --version  # Debería mostrar Python 3.9 o superior
iw --version
airmon-ng --version
```

### 4. Clonar/Transferir el Proyecto

```bash
# Opción 1: Si tienes el proyecto en GitHub
cd ~
git clone <tu-repositorio>
cd cypher-cc1101-jammer-main/python_version

# Opción 2: Transferir desde tu PC
# Usar scp, sftp, o copiar archivos manualmente
```

### 5. Instalar Dependencias Python

```bash
cd python_version

# Crear entorno virtual (recomendado)
python3 -m venv venv
source venv/bin/activate

# Instalar dependencias
pip install --upgrade pip
pip install -r requirements_wifi.txt
```

### 6. Verificar el Adaptador WiFi

```bash
# Conectar el adaptador USB
lsusb
# Deberías ver el adaptador BrosTrend

# Verificar interfaz WiFi
iw dev
# Deberías ver wlan0 o wlan1

# Verificar capacidades (debe soportar monitor mode)
iw phy | grep -A 10 "modes:"
# Debe incluir "monitor"
```

### 7. Ejecutar el Proyecto

```bash
# Con entorno virtual activado
source venv/bin/activate

# Ejecutar (con sudo, necesario para modo monitor)
sudo python3 main_wifi.py
```

---

## 💡 Consejos de Optimización

### Para maximizar el espacio disponible:

1. **Usar versión Lite** (sin escritorio):
   ```bash
   # Ahorra ~4-6 GB comparado con versión Full
   ```

2. **Limpiar paquetes innecesarios:**
   ```bash
   sudo apt autoremove -y
   sudo apt autoclean
   ```

3. **Desactivar servicios no necesarios:**
   ```bash
   # Si no usas Bluetooth:
   sudo systemctl disable bluetooth
   
   # Si no usas el escritorio:
   sudo systemctl set-default multi-user.target
   ```

4. **Usar swap en lugar de memoria extra:**
   ```bash
   # Configurar zram (swap comprimido) en lugar de archivo swap
   sudo apt install zram-tools
   ```

### Para mejor rendimiento:

1. **Usar SD Card rápida:**
   - Class 10 o superior
   - A1/A2 rating (para mejor I/O)
   - Marca confiable (SanDisk, Samsung)

2. **Overclock (opcional):**
   ```bash
   sudo raspi-config
   # Advanced Options → Overclock
   # Cuidado: puede aumentar temperatura
   ```

---

## ⚠️ Notas Importantes

1. **Siempre hacer backup:**
   - Tu proyecto funcionará bien, pero guarda copias de seguridad
   - Los logs y capturas pueden crecer

2. **Monitorear espacio:**
   ```bash
   df -h  # Ver espacio disponible
   du -sh ~/*  # Ver qué ocupa más espacio
   ```

3. **32 GB es suficiente, pero:**
   - Si guardas muchas capturas PCAP, considera más espacio
   - Los logs pueden crecer con el tiempo
   - Siempre deja al menos 10% libre

---

## ✅ Checklist de Verificación

Antes de empezar a usar el proyecto:

- [ ] SD Card de 32 GB formateada y Raspberry Pi OS instalado
- [ ] Sistema actualizado (`sudo apt update && sudo apt upgrade`)
- [ ] Filesystem expandido (usar toda la SD)
- [ ] Python 3 instalado y funcionando
- [ ] Dependencias del sistema instaladas
- [ ] Adaptador WiFi detectado (`lsusb`, `iw dev`)
- [ ] Proyecto copiado a la Raspberry Pi
- [ ] Entorno virtual creado y activado
- [ ] Dependencias Python instaladas
- [ ] Permisos configurados (sudo disponible)

---

## 📞 Solución de Problemas

### Problema: SD Card se llena rápido
```bash
# Ver qué ocupa espacio
sudo du -h --max-depth=1 / | sort -hr | head -20

# Limpiar logs antiguos
sudo journalctl --vacuum-time=7d  # Mantener solo últimos 7 días
```

### Problema: Adaptador WiFi no detectado
```bash
# Verificar USB
lsusb
dmesg | tail -20

# Puede necesitar controladores adicionales
sudo apt install linux-firmware
```

### Problema: No se puede activar modo monitor
```bash
# Verificar permisos
sudo whoami  # Debe devolver root

# Verificar capacidades del adaptador
iw phy phy0 info | grep -A 10 "modes"
```

---

**Con 32 GB y Raspberry Pi OS, estás listo para ejecutar el proyecto sin problemas! 🎉**

