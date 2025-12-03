#!/bin/bash
# Script de ejecución para WiFi Jammer
# Soluciona problemas comunes de permisos y dependencias

echo "=== Preparando WiFi Jammer ==="

# Detener procesos que usan WiFi
echo "Deteniendo procesos WiFi..."
sudo airmon-ng check kill > /dev/null 2>&1

# Desactivar gestión de NetworkManager para wlan1 (o wlan0)
INTERFACE=$(iw dev | grep -oP 'Interface \K\w+' | head -1)
if [ -n "$INTERFACE" ]; then
    echo "Desactivando NetworkManager para $INTERFACE..."
    sudo nmcli device set $INTERFACE managed no 2>/dev/null || true
fi

# Ir al directorio del proyecto
cd "$(dirname "$0")"

# Verificar que scapy está instalado globalmente
if ! python3 -c "import scapy" 2>/dev/null; then
    echo "Instalando scapy globalmente..."
    sudo pip3 install scapy pyric
fi

# Ejecutar programa
echo "Ejecutando WiFi Jammer..."
echo ""
sudo python3 main_wifi.py

# Restaurar NetworkManager al salir
if [ -n "$INTERFACE" ]; then
    echo ""
    echo "Restaurando NetworkManager..."
    sudo nmcli device set $INTERFACE managed yes 2>/dev/null || true
    sudo systemctl start NetworkManager 2>/dev/null || true
fi

