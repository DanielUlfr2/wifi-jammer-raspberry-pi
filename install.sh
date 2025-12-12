#!/bin/bash
# Script de instalación completa para WiFi Jammer - TP-Link TL-WN722N
# Raspberry Pi 4

set -e  # Salir si hay error

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   WiFi Jammer Tool - Instalación Automática                 ║"
echo "║   TP-Link TL-WN722N - Raspberry Pi 4                        ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Verificar que se ejecuta como root
if [ "$EUID" -ne 0 ]; then 
    echo "❌ Por favor ejecuta este script con sudo:"
    echo "   sudo bash install.sh"
    exit 1
fi

echo "📦 Paso 1: Actualizando sistema..."
apt update
apt upgrade -y

echo ""
echo "📦 Paso 2: Instalando dependencias del sistema..."
apt install -y \
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

echo ""
echo "📦 Paso 3: Verificando adaptador TP-Link TL-WN722N..."
if lsusb | grep -q "0bda:8179\|Realtek.*RTL8188"; then
    echo "✓ Adaptador TL-WN722N detectado"
else
    echo "⚠️  Adaptador no detectado. Asegúrate de que esté conectado."
    echo "   Ejecuta 'lsusb' para verificar."
    read -p "¿Continuar de todas formas? (s/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Ss]$ ]]; then
        exit 1
    fi
fi

echo ""
echo "📦 Paso 4: Instalando controladores rtl8188eu..."
cd /tmp

# Verificar si ya existe el directorio
if [ -d "/tmp/rtl8188eus" ]; then
    echo "   Limpiando instalación anterior..."
    rm -rf /tmp/rtl8188eus
fi

echo "   Clonando repositorio de controladores..."
git clone https://github.com/aircrack-ng/rtl8188eus.git
cd rtl8188eus

echo "   Compilando e instalando controladores..."
make clean 2>/dev/null || true
make
make install
modprobe -r 8188eu 2>/dev/null || true
modprobe 8188eu

# Instalar con DKMS para persistencia
if [ -f "dkms.conf" ]; then
    echo "   Configurando DKMS..."
    dkms add . 2>/dev/null || true
    dkms install rtl8188eu/1.0 2>/dev/null || true
fi

echo ""
echo "📦 Paso 5: Verificando instalación de controladores..."
if lsmod | grep -q "8188eu"; then
    echo "✓ Controladores instalados correctamente"
else
    echo "⚠️  Los controladores no están cargados. Puede requerir reinicio."
fi

echo ""
echo "📦 Paso 6: Configurando entorno Python..."
cd ~

# Crear directorio del proyecto si no existe
PROJECT_DIR="$HOME/wifi-jammer-raspberry-pi"
if [ -d "$PROJECT_DIR" ]; then
    echo "   Limpiando instalación anterior del proyecto..."
    rm -rf "$PROJECT_DIR"
fi

# También limpiar nombre antiguo si existe
OLD_DIR="$HOME/wifi-jammer-tl-wn722n"
if [ -d "$OLD_DIR" ]; then
    echo "   Eliminando directorio antiguo..."
    rm -rf "$OLD_DIR"
fi

echo "   Clonando repositorio del proyecto..."
git clone https://github.com/DanielUlfr2/wifi-jammer-raspberry-pi.git "$PROJECT_DIR"
cd "$PROJECT_DIR/python_version"

echo "   Creando entorno virtual..."
python3 -m venv venv
source venv/bin/activate

echo "   Instalando dependencias Python..."
pip install --upgrade pip
pip install -r requirements_wifi.txt

echo ""
echo "📦 Paso 7: Configurando permisos..."
chmod +x "$PROJECT_DIR/python_version/ejecutar.sh"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    ✓ INSTALACIÓN COMPLETA                    ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "📋 Próximos pasos:"
echo ""
echo "1. Reiniciar el sistema (recomendado):"
echo "   sudo reboot"
echo ""
echo "2. Después del reinicio, ejecutar el programa:"
echo "   cd ~/wifi-jammer-raspberry-pi/python_version"
echo "   sudo bash ejecutar.sh"
echo ""
echo "   O directamente:"
echo "   cd ~/wifi-jammer-raspberry-pi/python_version"
echo "   source venv/bin/activate"
echo "   sudo python3 main_wifi.py"
echo ""
echo "📝 Notas importantes:"
echo "   - Siempre ejecuta con sudo para modo monitor"
echo "   - El adaptador debe estar conectado antes de ejecutar"
echo "   - Verifica que NetworkManager no esté gestionando la interfaz"
echo ""

