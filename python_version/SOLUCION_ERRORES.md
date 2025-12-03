# Solución de Errores Comunes

## ❌ Error: "scapy no disponible" con sudo

### Problema:
Cuando ejecutas `sudo python3 main_wifi.py`, el `sudo` hace que Python use el entorno del sistema, no el entorno virtual donde instalaste las dependencias.

### Solución 1: Usar el Python del entorno virtual con sudo

```bash
# En lugar de:
sudo python3 main_wifi.py

# Usa:
sudo venv/bin/python3 main_wifi.py
```

### Solución 2: Instalar dependencias globalmente (más simple)

```bash
# Salir del entorno virtual
deactivate

# Instalar dependencias globalmente
sudo pip3 install scapy pyric

# Luego ejecutar normalmente
sudo python3 main_wifi.py
```

### Solución 3: Crear script de ejecución (recomendado)

Crear un script que maneje esto automáticamente:

```bash
nano ~/wifi-jammer-raspberry-pi/python_version/ejecutar.sh
```

Pegar este contenido:

```bash
#!/bin/bash
cd ~/wifi-jammer-raspberry-pi/python_version
source venv/bin/activate
sudo venv/bin/python3 main_wifi.py
```

Hacer ejecutable:

```bash
chmod +x ~/wifi-jammer-raspberry-pi/python_version/ejecutar.sh
```

Ejecutar:

```bash
~/wifi-jammer-raspberry-pi/python_version/ejecutar.sh
```

---

## ❌ Error: "Device or resource busy (-16)"

### Problema:
La interfaz WiFi está siendo usada por otro proceso (NetworkManager, wpa_supplicant, etc.)

### Solución:

```bash
# 1. Detener procesos que usan la interfaz
sudo airmon-ng check kill

# 2. Desactivar NetworkManager para esa interfaz
sudo nmcli device set wlan1 managed no

# 3. O desactivar completamente NetworkManager (temporalmente)
sudo systemctl stop NetworkManager
sudo systemctl stop wpa_supplicant

# 4. Luego ejecutar el programa
sudo venv/bin/python3 main_wifi.py
```

**Para reactivar NetworkManager después:**
```bash
sudo systemctl start NetworkManager
sudo nmcli device set wlan1 managed yes
```

---

## 🔧 Solución Completa Paso a Paso

### Paso 1: Instalar dependencias globalmente

```bash
cd ~/wifi-jammer-raspberry-pi/python_version

# Salir del entorno virtual si estás dentro
deactivate

# Instalar dependencias globalmente
sudo pip3 install scapy pyric

# Verificar instalación
python3 -c "import scapy; print('scapy OK')"
```

### Paso 2: Preparar la interfaz WiFi

```bash
# Detener procesos que usan WiFi
sudo airmon-ng check kill

# Desactivar gestión de NetworkManager para wlan1
sudo nmcli device set wlan1 managed no

# Verificar que la interfaz está libre
iw dev wlan1 info
```

### Paso 3: Ejecutar el programa

```bash
cd ~/wifi-jammer-raspberry-pi/python_version
sudo python3 main_wifi.py
```

---

## 📝 Script de Solución Automática

Crear script que haga todo automáticamente:

```bash
nano ~/ejecutar_wifi_jammer.sh
```

Pegar:

```bash
#!/bin/bash

echo "=== Preparando WiFi Jammer ==="

# Detener procesos que usan WiFi
echo "Deteniendo procesos WiFi..."
sudo airmon-ng check kill > /dev/null 2>&1

# Desactivar gestión de NetworkManager
echo "Desactivando NetworkManager para wlan1..."
sudo nmcli device set wlan1 managed no 2>/dev/null || true

# Ir al directorio del proyecto
cd ~/wifi-jammer-raspberry-pi/python_version

# Verificar que scapy está instalado
if ! python3 -c "import scapy" 2>/dev/null; then
    echo "Instalando scapy..."
    sudo pip3 install scapy pyric
fi

# Ejecutar programa
echo "Ejecutando WiFi Jammer..."
sudo python3 main_wifi.py

# Restaurar NetworkManager al salir
echo "Restaurando NetworkManager..."
sudo nmcli device set wlan1 managed yes 2>/dev/null || true
sudo systemctl start NetworkManager 2>/dev/null || true
```

Hacer ejecutable:

```bash
chmod +x ~/ejecutar_wifi_jammer.sh
```

Ejecutar:

```bash
~/ejecutar_wifi_jammer.sh
```

---

## ✅ Verificación Post-Instalación

Después de instalar, verifica:

```bash
# 1. Verificar scapy
python3 -c "import scapy; print('scapy:', scapy.__version__)"

# 2. Verificar pyric
python3 -c "import pyric; print('pyric OK')"

# 3. Verificar aircrack-ng
airmon-ng --version

# 4. Verificar interfaz
iw dev wlan1 info
```

---

## 🔄 Restaurar Configuración Normal

Si quieres volver a usar WiFi normalmente:

```bash
# Reactivar NetworkManager
sudo systemctl start NetworkManager
sudo nmcli device set wlan1 managed yes

# Reiniciar servicios de red
sudo systemctl restart networking
```

---

## ⚠️ Notas Importantes

1. **Siempre usa sudo** - Necesario para modo monitor
2. **Instala dependencias globalmente** - Más fácil que lidiar con venv + sudo
3. **Detén NetworkManager** - Evita conflictos con la interfaz
4. **Usa el script** - Automatiza todo el proceso

---

## 🆘 Si Aún Tienes Problemas

### Verificar que el adaptador soporta modo monitor:

```bash
iw phy phy1 info | grep -A 10 "modes:"
```

Debe incluir "monitor" en la lista.

### Ver logs del sistema:

```bash
dmesg | tail -20
journalctl -xe | tail -20
```

### Verificar permisos:

```bash
sudo whoami  # Debe devolver "root"
```

---

**Con estos pasos deberías poder ejecutar el programa sin problemas.** 🚀

