# 🧹 Guía Completa: Limpiar Raspberry Pi e Instalación desde Cero

Esta guía te ayudará a limpiar completamente tu Raspberry Pi y reinstalar el proyecto desde cero.

## 📋 Tabla de Contenidos

1. [Limpiar Proyectos de la Raspberry Pi](#1-limpiar-proyectos-de-la-raspberry-pi)
2. [Instalación Automática](#2-instalación-automática-recomendado)
3. [Instalación Manual](#3-instalación-manual-paso-a-paso)
4. [Verificación y Pruebas](#4-verificación-y-pruebas)
5. [Solución de Problemas](#5-solución-de-problemas)

---

## 1. Limpiar Proyectos de la Raspberry Pi

### ⚠️ IMPORTANTE: Esto NO eliminará el Sistema Operativo

Estos comandos solo eliminarán proyectos y archivos de usuario, manteniendo el sistema operativo intacto.

### Paso 1: Conectar por SSH o Terminal

```bash
# Si usas SSH desde tu PC:
ssh pi@<IP_DE_TU_RASPBERRY_PI>

# O conecta directamente con teclado y monitor
```

### Paso 2: Detener procesos activos del proyecto

```bash
# Detener cualquier proceso del proyecto que esté corriendo
sudo pkill -f main_wifi.py
sudo pkill -f wifi_driver.py
sudo airmon-ng check kill

# Detener interfaces en modo monitor
sudo airmon-ng stop wlan0mon 2>/dev/null || true
sudo airmon-ng stop wlan1mon 2>/dev/null || true
```

### Paso 3: Eliminar proyectos y archivos relacionados

```bash
# Eliminar el proyecto actual (ambos nombres posibles)
rm -rf ~/wifi-jammer-raspberry-pi
rm -rf ~/wifi-jammer-tl-wn722n

# Eliminar controladores compilados
rm -rf ~/rtl8188eus

# Limpiar caché de pip
pip3 cache purge

# Limpiar paquetes de Python globales relacionados (opcional)
# sudo pip3 uninstall scapy pyric 2>/dev/null || true
```

### Paso 4: Limpiar espacio del sistema (opcional)

```bash
# Limpiar paquetes no utilizados
sudo apt autoremove -y
sudo apt autoclean

# Verificar espacio disponible
df -h
```

### Paso 5: Verificar que todo está limpio

```bash
# Verificar que no existen los directorios
ls -la ~ | grep wifi
# No debe mostrar nada

# Verificar que no hay procesos corriendo
ps aux | grep -i wifi
# No debe mostrar procesos del proyecto
```

---

## 2. Instalación Automática (RECOMENDADO)

El método más rápido y seguro es usar el script de instalación automática.

### Paso 1: Descargar script de instalación

```bash
cd ~
wget https://raw.githubusercontent.com/DanielUlfr2/wifi-jammer-raspberry-pi/main/install.sh
chmod +x install.sh
```

### Paso 2: Ejecutar instalación

```bash
sudo bash install.sh
```

El script hará automáticamente:
- ✅ Actualización del sistema
- ✅ Instalación de dependencias
- ✅ Instalación de controladores rtl8188eu
- ✅ Clonación del repositorio
- ✅ Configuración del entorno Python
- ✅ Instalación de dependencias Python

### Paso 3: Reiniciar (recomendado)

```bash
sudo reboot
```

Después del reinicio, continúa con la [Verificación](#4-verificación-y-pruebas).

---

## 3. Instalación Manual (Paso a Paso)

Si prefieres instalar manualmente o el script automático tiene problemas:

### Paso 1: Actualizar sistema

```bash
sudo apt update
sudo apt upgrade -y
```

### Paso 2: Instalar dependencias del sistema

```bash
sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    aircrack-ng \
    wireless-tools \
    iw \
    build-essential \
    git \
    dkms \
    linux-headers-$(uname -r)
```

### Paso 3: Verificar adaptador TP-Link TL-WN722N

```bash
# Conectar el adaptador USB
lsusb

# Debe mostrar algo como:
# Bus 001 Device 005: ID 0bda:8179 Realtek Semiconductor Corp. RTL8188EUS
```

### Paso 4: Instalar controladores rtl8188eu

```bash
cd ~
git clone https://github.com/aircrack-ng/rtl8188eus.git
cd rtl8188eus

# Compilar e instalar
sudo make clean
make
sudo make install

# Cargar módulo
sudo modprobe -r 8188eu 2>/dev/null || true
sudo modprobe 8188eu

# Instalar con DKMS (para persistencia)
sudo dkms add .
sudo dkms install rtl8188eu/1.0
```

### Paso 5: Verificar controladores

```bash
# Verificar que el módulo está cargado
lsmod | grep 8188eu

# Verificar que la interfaz existe
iw dev
# Debe mostrar una interfaz (ej: wlan1)
```

### Paso 6: Clonar proyecto

```bash
cd ~
git clone https://github.com/DanielUlfr2/wifi-jammer-raspberry-pi.git
cd wifi-jammer-raspberry-pi/python_version
```

### Paso 7: Configurar entorno Python

```bash
# Crear entorno virtual
python3 -m venv venv

# Activar entorno virtual
source venv/bin/activate

# Actualizar pip
pip install --upgrade pip

# Instalar dependencias
pip install -r requirements_wifi.txt
```

### Paso 8: Configurar permisos

```bash
chmod +x ejecutar.sh
```

---

## 4. Verificación y Pruebas

### Verificar instalación

```bash
# Verificar que el adaptador está conectado
lsusb | grep -i realtek

# Verificar que los controladores están cargados
lsmod | grep 8188eu

# Verificar que la interfaz WiFi existe
iw dev

# Verificar que Python puede importar las librerías
cd ~/wifi-jammer-raspberry-pi/python_version
source venv/bin/activate
python3 -c "import scapy; print('✓ Scapy instalado')"
python3 -c "import config_wifi; print(f'✓ Versión: {config_wifi.VERSION}')"
```

### Ejecutar el programa

```bash
cd ~/wifi-jammer-raspberry-pi/python_version
source venv/bin/activate
sudo python3 main_wifi.py
```

Deberías ver el menú principal:

```
╔══════════════════════════════════════════════════════════════╗
║      WiFi Terminal Tool - TP-Link TL-WN722N                  ║
║      Versión 2.0.0 - Optimizada para Raspberry Pi 4          ║
╚══════════════════════════════════════════════════════════════╝
```

### Prueba rápida

1. Selecciona opción `2` (Escanear Redes WiFi)
2. Selecciona opción `1` (Escanear redes WiFi rápido)
3. Espera 3-5 segundos
4. Deberías ver una lista de redes WiFi disponibles

---

## 5. Solución de Problemas

### Problema: Adaptador no detectado

```bash
# Verificar conexión USB
lsusb

# Verificar que está conectado físicamente
# Prueba desconectarlo y volver a conectar

# Verificar permisos USB
groups
# Debes estar en el grupo 'dialout' o ejecutar con sudo
```

### Problema: Controladores no cargados

```bash
# Verificar si el módulo existe
modinfo 8188eu

# Intentar cargar manualmente
sudo modprobe 8188eu

# Ver logs del kernel
dmesg | tail -20

# Reinstalar controladores
cd ~/rtl8188eus
sudo make clean
make
sudo make install
sudo modprobe 8188eu
```

### Problema: Interfaz no aparece

```bash
# Verificar que los controladores están cargados
lsmod | grep 8188eu

# Verificar interfaces disponibles
iw dev

# Verificar que no está bloqueada
sudo rfkill unblock wifi
sudo rfkill unblock all

# Reiniciar servicios de red
sudo systemctl restart NetworkManager
```

### Problema: Error al ejecutar con sudo

```bash
# Asegúrate de usar el Python correcto
which python3

# Si usas entorno virtual, desactívalo antes de usar sudo
deactivate
sudo python3 main_wifi.py

# O usa el Python del sistema directamente
sudo /usr/bin/python3 main_wifi.py
```

### Problema: No puede activar modo monitor

```bash
# Detener procesos que bloquean
sudo airmon-ng check kill

# Desbloquear interfaz
sudo rfkill unblock wifi

# Verificar que NetworkManager no gestiona la interfaz
sudo nmcli device set wlan1 managed no

# Intentar manualmente
sudo airmon-ng start wlan1
```

### Problema: Error de dependencias Python

```bash
# Reinstalar dependencias
cd ~/wifi-jammer-raspberry-pi/python_version
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements_wifi.txt --force-reinstall
```

---

## 📞 Contacto y Soporte

Si tienes problemas que no se resuelven con esta guía:

1. Revisa los logs del sistema: `dmesg | tail -50`
2. Verifica la versión del proyecto: `python3 -c "import config_wifi; print(config_wifi.VERSION)"`
3. Asegúrate de tener la última versión del repositorio

---

## ✅ Checklist Final

Antes de considerar la instalación completa, verifica:

- [ ] Adaptador TP-Link TL-WN722N conectado y detectado (`lsusb`)
- [ ] Controladores rtl8188eu instalados y cargados (`lsmod | grep 8188eu`)
- [ ] Interfaz WiFi disponible (`iw dev`)
- [ ] Proyecto clonado correctamente (`ls ~/wifi-jammer-raspberry-pi`)
- [ ] Entorno virtual creado y activado
- [ ] Dependencias Python instaladas
- [ ] Programa se ejecuta sin errores (`sudo python3 main_wifi.py`)
- [ ] Menú principal aparece correctamente

Si todos los puntos están marcados, ¡la instalación está completa! 🎉

