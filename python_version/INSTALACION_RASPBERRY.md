# Guía de Instalación en Raspberry Pi 4

## 📋 Pasos para Instalar el Proyecto en Raspberry Pi

### Paso 1: Actualizar el Sistema

```bash
# Actualizar lista de paquetes
sudo apt update

# Actualizar sistema (opcional pero recomendado)
sudo apt upgrade -y
```

---

### Paso 2: Instalar Git

```bash
# Instalar Git
sudo apt install -y git

# Verificar instalación
git --version
```

---

### Paso 3: Instalar Dependencias del Sistema

```bash
# Instalar Python, pip y herramientas de desarrollo
sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    build-essential \
    libpcap-dev

# Instalar herramientas WiFi (necesarias para modo monitor)
sudo apt install -y \
    aircrack-ng \
    wireless-tools \
    iw

# Verificar instalaciones
python3 --version
pip3 --version
iw --version
airmon-ng --version
```

---

### Paso 4: Clonar el Repositorio

```bash
# Ir a la carpeta home (o donde prefieras)
cd ~

# Clonar el repositorio
git clone https://github.com/DanielUlfr2/wifi-jammer-raspberry-pi.git

# Entrar a la carpeta del proyecto
cd wifi-jammer-raspberry-pi/python_version

# Verificar que los archivos están ahí
ls -la
```

---

### Paso 5: Crear Entorno Virtual (Recomendado)

```bash
# Crear entorno virtual
python3 -m venv venv

# Activar entorno virtual
source venv/bin/activate

# Verás (venv) al inicio de la línea de comandos
```

**Nota:** Cada vez que quieras usar el proyecto, activa el entorno virtual con:
```bash
cd ~/wifi-jammer-raspberry-pi/python_version
source venv/bin/activate
```

---

### Paso 6: Instalar Dependencias Python

```bash
# Asegúrate de estar en la carpeta python_version
cd ~/wifi-jammer-raspberry-pi/python_version

# Asegúrate de que el entorno virtual esté activado
source venv/bin/activate

# Actualizar pip
pip install --upgrade pip

# Instalar dependencias del proyecto
pip install -r requirements_wifi.txt
```

**Esto instalará:**
- `scapy` (captura e inyección de paquetes WiFi)
- `pyric` (control de interfaces WiFi)

---

### Paso 7: Verificar el Adaptador WiFi

```bash
# Conectar el adaptador USB BrosTrend AC1200 AC3L

# Verificar que está detectado
lsusb
# Deberías ver el adaptador en la lista

# Verificar interfaz WiFi
iw dev
# Deberías ver wlan0 o wlan1

# Verificar que soporta modo monitor
iw phy | grep -A 10 "modes:"
# Debe incluir "monitor" en la lista
```

---

### Paso 8: Ejecutar el Proyecto

```bash
# Asegúrate de estar en la carpeta correcta
cd ~/wifi-jammer-raspberry-pi/python_version

# Activar entorno virtual (si no está activado)
source venv/bin/activate

# Ejecutar con sudo (necesario para modo monitor)
sudo python3 main_wifi.py
```

**⚠️ IMPORTANTE:** Siempre ejecuta con `sudo` porque necesitas permisos de administrador para:
- Activar modo monitor
- Capturar paquetes WiFi
- Inyectar paquetes
- Hacer jamming

---

## 🔄 Comandos Rápidos para Uso Diario

### Activar y Ejecutar:

```bash
# Opción 1: Todo en un comando
cd ~/wifi-jammer-raspberry-pi/python_version && source venv/bin/activate && sudo python3 main_wifi.py

# Opción 2: Paso a paso
cd ~/wifi-jammer-raspberry-pi/python_version
source venv/bin/activate
sudo python3 main_wifi.py
```

### Actualizar el Proyecto (si hay cambios en GitHub):

```bash
cd ~/wifi-jammer-raspberry-pi
git pull
cd python_version
source venv/bin/activate
pip install -r requirements_wifi.txt  # Por si hay nuevas dependencias
```

---

## 📝 Script de Instalación Automática

Puedes crear un script para automatizar la instalación:

```bash
# Crear script
nano ~/instalar_wifi_jammer.sh
```

Pega este contenido:

```bash
#!/bin/bash

echo "=== Instalando WiFi Jammer en Raspberry Pi ==="

# Actualizar sistema
echo "Actualizando sistema..."
sudo apt update
sudo apt upgrade -y

# Instalar Git
echo "Instalando Git..."
sudo apt install -y git

# Instalar dependencias del sistema
echo "Instalando dependencias del sistema..."
sudo apt install -y python3 python3-pip python3-venv build-essential libpcap-dev
sudo apt install -y aircrack-ng wireless-tools iw

# Clonar repositorio
echo "Clonando repositorio..."
cd ~
if [ -d "wifi-jammer-raspberry-pi" ]; then
    echo "El repositorio ya existe. Actualizando..."
    cd wifi-jammer-raspberry-pi
    git pull
else
    git clone https://github.com/DanielUlfr2/wifi-jammer-raspberry-pi.git
    cd wifi-jammer-raspberry-pi
fi

# Crear entorno virtual
echo "Creando entorno virtual..."
cd python_version
python3 -m venv venv

# Activar y instalar dependencias
echo "Instalando dependencias Python..."
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements_wifi.txt

echo "=== Instalación completada ==="
echo "Para ejecutar:"
echo "  cd ~/wifi-jammer-raspberry-pi/python_version"
echo "  source venv/bin/activate"
echo "  sudo python3 main_wifi.py"
```

Hacer ejecutable y ejecutar:

```bash
chmod +x ~/instalar_wifi_jammer.sh
~/instalar_wifi_jammer.sh
```

---

## ⚙️ Configuración Inicial Recomendada

### 1. Habilitar SSH (si quieres acceder remotamente):

```bash
sudo raspi-config
# Interface Options → SSH → Enable
```

### 2. Expandir Filesystem (usar toda la SD):

```bash
sudo raspi-config
# Advanced Options → Expand Filesystem
sudo reboot
```

### 3. Configurar WiFi (si usas la conexión WiFi de la Pi):

```bash
sudo raspi-config
# System Options → Wireless LAN
```

---

## 🔧 Solución de Problemas

### Error: "git: command not found"
```bash
sudo apt install -y git
```

### Error: "pip: command not found"
```bash
sudo apt install -y python3-pip
```

### Error: "airmon-ng: command not found"
```bash
sudo apt install -y aircrack-ng
```

### Error: "No se puede activar modo monitor"
```bash
# Verificar permisos
sudo whoami  # Debe devolver "root"

# Verificar que no hay procesos bloqueando
sudo airmon-ng check kill

# Verificar capacidades del adaptador
iw phy phy0 info | grep -A 10 "modes"
```

### Error: "Adaptador WiFi no detectado"
```bash
# Verificar USB
lsusb

# Ver logs del sistema
dmesg | tail -20

# Puede necesitar controladores adicionales
sudo apt install linux-firmware
```

### Error al instalar scapy
```bash
# Instalar dependencias de compilación
sudo apt install -y python3-dev libpcap-dev

# Reintentar
pip install scapy
```

---

## ✅ Checklist de Verificación

Antes de ejecutar, verifica:

- [ ] Sistema actualizado (`sudo apt update && sudo apt upgrade`)
- [ ] Git instalado (`git --version`)
- [ ] Python 3 instalado (`python3 --version`)
- [ ] pip instalado (`pip3 --version`)
- [ ] aircrack-ng instalado (`airmon-ng --version`)
- [ ] Repositorio clonado (`cd ~/wifi-jammer-raspberry-pi`)
- [ ] Entorno virtual creado (`ls venv/`)
- [ ] Dependencias Python instaladas (`pip list | grep scapy`)
- [ ] Adaptador WiFi conectado (`lsusb`)
- [ ] Interfaz WiFi detectada (`iw dev`)

---

## 🚀 Primer Uso

Una vez instalado todo:

```bash
# 1. Ir a la carpeta del proyecto
cd ~/wifi-jammer-raspberry-pi/python_version

# 2. Activar entorno virtual
source venv/bin/activate

# 3. Ejecutar (con sudo)
sudo python3 main_wifi.py

# 4. Probar comandos básicos:
#    help          - Ver ayuda
#    status        - Ver estado
#    wifiscan      - Escanear redes WiFi
#    setchannel 6  - Cambiar canal
#    rx            - Activar recepción
```

---

## 📞 Comandos Útiles

```bash
# Ver espacio en disco
df -h

# Ver procesos activos
ps aux | grep python

# Ver interfaces de red
iw dev
ip link show

# Ver logs del sistema
dmesg | tail -50

# Reiniciar servicios de red (si hay problemas)
sudo systemctl restart networking
```

---

**¡Listo! Con estos pasos tendrás el proyecto funcionando en tu Raspberry Pi 4.** 🎉

