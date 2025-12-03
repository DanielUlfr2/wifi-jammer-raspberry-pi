#!/usr/bin/env python3
"""
CC1101 Interactive Terminal Tool
Migrado de C++/Arduino a Python para Raspberry Pi
Permite enviar/recibir datos por RF usando el módulo CC1101

(C) Basado en trabajo de Adam Loboda 2023
Adaptado a Python para Raspberry Pi
"""

import sys
import os
import time
import select
import random
import json
import pickle
import threading
from typing import Optional

# Importar módulos locales
import config
import utils
from cc1101_driver import CC1101Driver

try:
    import RPi.GPIO as GPIO
    GPIO_AVAILABLE = True
except ImportError:
    GPIO_AVAILABLE = False
    print("ADVERTENCIA: RPi.GPIO no disponible. Funcionalidad limitada.")


class CC1101Terminal:
    """Terminal interactivo para controlar CC1101"""
    
    def __init__(self):
        """Inicializa el terminal"""
        # Estado de modos
        self.receiving_mode = False
        self.jamming_mode = False
        self.recording_mode = False
        self.chat_mode = False
        
        # Buffers
        self.cc_receiving_buffer = bytearray(config.CCBUFFERSIZE)
        self.cc_sending_buffer = bytearray(config.CCBUFFERSIZE)
        self.big_recording_buffer = bytearray(config.RECORDINGBUFFERSIZE)
        self.big_recording_buffer_pos = 0
        self.frames_in_buffer = 0
        
        # Configuración
        self.do_echo = True
        self.rxraw_active = False
        self.scan_active = False
        
        # Inicializar CC1101
        print("Inicializando CC1101...")
        self.cc1101 = CC1101Driver()
        
        if not self.cc1101.getCC1101():
            print("ERROR: No se pudo comunicar con CC1101. Verifica las conexiones.")
            sys.exit(1)
        
        # Inicializar CC1101 con configuración por defecto
        self.cc1101.Init()
        print("CC1101 inicializado correctamente.\n")
    
    def print_help(self):
        """Muestra la ayuda de comandos"""
        help_text = """
setmodulation <mode> : Set modulation mode. 0 = 2-FSK, 1 = GFSK, 2 = ASK/OOK, 3 = 4-FSK, 4 = MSK.

setmhz <frequency>   : Set basic frequency. default = 433.92). Ranges: 300-348 MHz, 387-464MHz, 779-928MHz.

setdeviation <deviation> : Set Frequency deviation in kHz. Value from 1.58 to 380.85.

setchannel <channel> : Set Channel number from 0 to 255. Default is channel 0.

setchsp <spacing>  : Channel spacing in kHz. Value from 25.39 to 405.45.

setrxbw <Receive bandwidth> : Set Receive Bandwidth in kHz. Value from 58.03 to 812.50.

setdrate <datarate> : Set Data Rate in kBaud. Value from 0.02 to 1621.83.

setpa <power value> : Set RF transmission power. (-30  -20  -15  -10  -6    0    5    7    10   11   12)

setsyncmode  <sync mode> : Sync-word qualifier mode. 0-7.

setsyncword <LOW, HIGH> : Set sync word. Default is 211,145

setadrchk <address chk> : Address check configuration. 0-3.

setaddr <address> : Address for packet filtration. 0-255.

setwhitedata <whitening> : Turn data whitening on/off. 0 = off, 1 = on.

setpktformat <pktformat> : Packet format. 0 = Normal, 1 = Sync serial, 2 = Random TX, 3 = Async serial

setlengthconfig <mode> : Packet length mode. 0 = Fixed, 1 = Variable, 2 = Infinite, 3 = Reserved

setpacketlength <mode> : Packet length (when fixed mode).

setcrc <mode> : CRC calculation. 1 = enabled, 0 = disabled.

setcrcaf <mode> : Auto-flush RX FIFO on CRC error.

setdcfilteroff <mode> : Disable DC blocking filter.

setmanchester <mode> : Manchester encoding. 0 = off, 1 = on.

setfec <mode> : Forward Error Correction. 0 = off, 1 = on.

setpre <mode> : Minimum preamble bytes. 0=2, 1=3, 2=4, 3=6, 4=8, 5=12, 6=16, 7=24

setpqt <mode> : Preamble quality estimator threshold.

setappendstatus <mode> : Append RSSI/LQI status bytes to packet.

getrssi : Display RSSI and LQI of last received frame.

scan <start> <stop> : Scan frequency range for highest signal.

chat : Enable chat mode between devices.

rx : Enable/disable receiving and printing RF packets.

tx <hex-vals> : Send packet (max 60 bytes) as hex values over RF.

jam : Enable/disable continuous jamming.

brute <microseconds> <number-of-bits> : Brute force garage gate.

rec : Enable/disable recording frames in buffer.

add <hex-vals> : Manually add frame (max 64 hex values) to buffer.

show : Show content of recording buffer.

flush : Clear the recording buffer.

play <N> : Replay all frames (0) or N-th recorded frame.

rxraw <microseconds> : Sniff radio with sampling interval.

addraw <hex-vals> : Manually add chunks (max 60 hex values) to buffer.

recraw <microseconds> : Record RAW RF data with sampling interval.

showraw : Show content of recording buffer in RAW format.

showbit : Show content as bit stream.

playraw <microseconds> : Replay previously recorded RAW data.

save : Store recording buffer to file.

load : Load recording buffer from file.

echo <mode> : Enable/disable echo. 1 = enabled, 0 = disabled.

x : Stop jamming/receiving/recording.

init : Restart CC1101 with default parameters.

help : Show this help message.
"""
        print(help_text)
    
    def exec_command(self, cmdline: str):
        """Ejecuta un comando"""
        parts = cmdline.strip().split(None, 1)
        if not parts:
            return
        
        command = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""
        
        try:
            if command == "help":
                self.print_help()
            
            elif command == "setmodulation":
                mode = int(args)
                self.cc1101.setModulation(mode)
                mod_names = ["2-FSK", "GFSK", "ASK/OOK", "4-FSK", "MSK"]
                print(f"\r\nModulation: {mod_names[mode] if 0 <= mode < len(mod_names) else 'Unknown'}\r\n")
            
            elif command == "setmhz":
                freq = float(args)
                if self.cc1101.setMHZ(freq):
                    print(f"\r\nFrequency: {freq} MHz\r\n")
                else:
                    print("Error: Frequency out of valid range\r\n")
            
            elif command == "setdeviation":
                dev = float(args)
                self.cc1101.setDeviation(dev)
                print(f"\r\nDeviation: {dev} kHz\r\n")
            
            elif command == "setchannel":
                chan = int(args)
                self.cc1101.setChannel(chan)
                print(f"\r\nChannel: {chan}\r\n")
            
            elif command == "setchsp":
                spacing = float(args)
                self.cc1101.setChsp(spacing)
                print(f"\r\nChannel spacing: {spacing} kHz\r\n")
            
            elif command == "setrxbw":
                bw = float(args)
                self.cc1101.setRxBW(bw)
                print(f"\r\nRX bandwidth: {bw} kHz\r\n")
            
            elif command == "setdrate":
                rate = float(args)
                self.cc1101.setDRate(rate)
                print(f"\r\nData rate: {rate} kbaud\r\n")
            
            elif command == "setpa":
                power = int(args)
                self.cc1101.setPA(power)
                print(f"\r\nTX Power: {power} dBm\r\n")
            
            elif command == "setsyncmode":
                mode = int(args)
                self.cc1101.setSyncMode(mode)
                sync_modes = [
                    "No preamble", "16 sync bits", "16/16 sync bits", "30/32 sync bits",
                    "No preamble/sync, carrier-sense", "15/16 + carrier-sense",
                    "16/16 + carrier-sense", "30/32 + carrier-sense"
                ]
                mode_name = sync_modes[mode] if 0 <= mode < len(sync_modes) else "Unknown"
                print(f"\r\nSynchronization: {mode_name}\r\n")
            
            elif command == "setsyncword":
                parts = args.split()
                if len(parts) >= 2:
                    low = int(parts[0])
                    high = int(parts[1])
                    self.cc1101.setSyncWord(high, low)
                    print(f"\r\nSynchronization:\r\nhigh = {high}\r\nlow = {low}\r\n")
            
            elif command == "setadrchk":
                mode = int(args)
                self.cc1101.setAdrChk(mode)
                adr_modes = [
                    "No adr chk", "Adr chk, no bcast", "Adr chk and 0 bcast",
                    "Adr chk and 0 and FF bcast"
                ]
                mode_name = adr_modes[mode] if 0 <= mode < len(adr_modes) else "Unknown"
                print(f"\r\nAddress checking: {mode_name}\r\n")
            
            elif command == "setaddr":
                addr = int(args)
                self.cc1101.setAddr(addr)
                print(f"\r\nAddress: {addr}\r\n")
            
            elif command == "setwhitedata":
                enable = int(args)
                self.cc1101.setWhiteData(enable)
                print(f"\r\nWhitening {'ON' if enable else 'OFF'}\r\n")
            
            elif command == "setpktformat":
                fmt = int(args)
                self.cc1101.setPktFormat(fmt)
                formats = ["Normal mode", "Synchronous serial mode", "Random TX mode", "Asynchronous serial mode"]
                format_name = formats[fmt] if 0 <= fmt < len(formats) else "Unknown"
                print(f"\r\nPacket format: {format_name}\r\n")
            
            elif command == "setlengthconfig":
                mode = int(args)
                self.cc1101.setLengthConfig(mode)
                modes = ["Fixed", "Variable", "Infinite", "Reserved"]
                mode_name = modes[mode] if 0 <= mode < len(modes) else "Unknown"
                print(f"\r\nPacket length mode: {mode_name}\r\n")
            
            elif command == "setpacketlength":
                length = int(args)
                self.cc1101.setPacketLength(length)
                print(f"\r\nPacket length: {length} bytes\r\n")
            
            elif command == "setcrc":
                enable = int(args)
                self.cc1101.setCrc(enable)
                print(f"\r\nCRC checking: {'Enabled' if enable else 'Disabled'}\r\n")
            
            elif command == "setcrcaf":
                enable = int(args)
                self.cc1101.setCRC_AF(enable)
                print(f"\r\nCRC Autoflush: {'Enabled' if enable else 'Disabled'}\r\n")
            
            elif command == "setdcfilteroff":
                disable = int(args)
                self.cc1101.setDcFilterOff(disable)
                print(f"\r\nDC filter: {'Disabled' if disable else 'Enabled'}\r\n")
            
            elif command == "setmanchester":
                enable = int(args)
                self.cc1101.setManchester(enable)
                print(f"\r\nManchester coding: {'Enabled' if enable else 'Disabled'}\r\n")
            
            elif command == "setfec":
                enable = int(args)
                self.cc1101.setFEC(enable)
                print(f"\r\nForward Error Correction: {'Enabled' if enable else 'Disabled'}\r\n")
            
            elif command == "setpre":
                mode = int(args)
                self.cc1101.setPRE(mode)
                pre_values = [2, 3, 4, 6, 8, 12, 16, 24]
                pre_val = pre_values[mode] if 0 <= mode < len(pre_values) else 0
                print(f"\r\nMinimum preamble bytes: {mode} = {pre_val} bytes\r\n")
            
            elif command == "setpqt":
                pqt = int(args)
                self.cc1101.setPQT(pqt)
                print(f"\r\nPQT: {pqt}\r\n")
            
            elif command == "setappendstatus":
                enable = int(args)
                self.cc1101.setAppendStatus(enable)
                print(f"\r\nStatus bytes appending: {'Enabled' if enable else 'Disabled'}\r\n")
            
            elif command == "getrssi":
                rssi = self.cc1101.getRssi()
                lqi = self.cc1101.getLqi()
                print(f"Rssi: {rssi}")
                print(f"LQI: {lqi}\r\n")
            
            elif command == "scan":
                parts = args.split()
                if len(parts) >= 2:
                    start_freq = float(parts[0])
                    stop_freq = float(parts[1])
                    self._cmd_scan(start_freq, stop_freq)
                else:
                    print("Error: Wrong parameters.\r\n")
            
            elif command == "rx":
                if self.receiving_mode:
                    self.receiving_mode = False
                    print("\r\nReceiving and printing RF packet changed to Disabled\r\n")
                else:
                    self.cc1101.SetRx()
                    self.receiving_mode = True
                    self.jamming_mode = False
                    self.recording_mode = False
                    print("\r\nReceiving and printing RF packet changed to Enabled\r\n")
            
            elif command == "tx":
                if not args:
                    print("Error: Wrong parameters.\r\n")
                elif utils.validate_hex_string(args):
                    data = utils.hex_to_bytes(args)
                    print("\r\nTransmitting RF packets.\r\n")
                    self.cc1101.SendData(data, len(data))
                    hex_str = utils.bytes_to_hex(data)
                    print(f"Sent frame: {hex_str}\r\n")
                else:
                    print("Error: Invalid hex string.\r\n")
            
            elif command == "jam":
                self.jamming_mode = not self.jamming_mode
                status = "Enabled" if self.jamming_mode else "Disabled"
                if self.jamming_mode:
                    self.receiving_mode = False
                print(f"\r\nJamming changed to {status}\r\n")
            
            elif command == "brute":
                parts = args.split()
                if len(parts) >= 2:
                    usec = int(parts[0])
                    bits = int(parts[1])
                    self._cmd_brute(usec, bits)
                else:
                    print("Error: Wrong parameters.\r\n")
            
            elif command == "rec":
                if self.recording_mode:
                    self.recording_mode = False
                    self.big_recording_buffer_pos = 0
                    print("\r\nRecording mode set to Disabled\r\n")
                else:
                    self.cc1101.SetRx()
                    self.recording_mode = True
                    self.jamming_mode = False
                    self.receiving_mode = False
                    self.big_recording_buffer_pos = 0
                    self.frames_in_buffer = 0
                    # Limpiar buffer
                    self.big_recording_buffer = bytearray(config.RECORDINGBUFFERSIZE)
                    print("\r\nRecording mode set to Enabled\r\n")
            
            elif command == "add":
                if not args or not utils.validate_hex_string(args):
                    print("Error: Wrong parameters.\r\n")
                else:
                    data = utils.hex_to_bytes(args)
                    self._add_frame(data)
            
            elif command == "show":
                self._cmd_show()
            
            elif command == "flush":
                self.big_recording_buffer = bytearray(config.RECORDINGBUFFERSIZE)
                self.big_recording_buffer_pos = 0
                self.frames_in_buffer = 0
                print("\r\nRecording buffer cleared.\r\n")
            
            elif command == "play":
                frame_num = int(args) if args else 0
                self._cmd_play(frame_num)
            
            elif command == "rxraw":
                if args:
                    usec = int(args)
                    if usec > 0:
                        self._cmd_rxraw(usec)
                    else:
                        print("Error: Wrong parameters.\r\n")
                else:
                    print("Error: Wrong parameters.\r\n")
            
            elif command == "recraw":
                if args:
                    usec = int(args)
                    if usec > 0:
                        self._cmd_recraw(usec)
                    else:
                        print("Error: Wrong parameters.\r\n")
                else:
                    print("Error: Wrong parameters.\r\n")
            
            elif command == "playraw":
                if args:
                    usec = int(args)
                    if usec > 0:
                        self._cmd_playraw(usec)
                    else:
                        print("Error: Wrong parameters.\r\n")
                else:
                    print("Error: Wrong parameters.\r\n")
            
            elif command == "showraw":
                self._cmd_showraw()
            
            elif command == "showbit":
                self._cmd_showbit()
            
            elif command == "addraw":
                if not args or not utils.validate_hex_string(args):
                    print("Error: Wrong parameters.\r\n")
                else:
                    data = utils.hex_to_bytes(args)
                    self._add_raw(data)
            
            elif command == "save":
                self._cmd_save()
            
            elif command == "load":
                self._cmd_load()
            
            elif command == "echo":
                self.do_echo = bool(int(args)) if args else True
            
            elif command == "chat":
                self.chat_mode = True
                self.jamming_mode = False
                self.receiving_mode = False
                self.recording_mode = False
                print("\r\nEntering chat mode:\r\n\r\n")
            
            elif command == "x":
                self.receiving_mode = False
                self.jamming_mode = False
                self.recording_mode = False
                self.rxraw_active = False
                self.scan_active = False
                print("\r\n")
            
            elif command == "init":
                self.cc1101.Init()
                print("CC1101 initialized\r\n")
            
            else:
                print(f"Error: Unknown command: {command}\r\n")
        
        except Exception as e:
            print(f"Error executing command: {e}\r\n")
    
    def _add_frame(self, data: bytes):
        """Añade un frame al buffer de grabación"""
        data_len = len(data)
        if (self.big_recording_buffer_pos + data_len + 1) < config.RECORDINGBUFFERSIZE:
            self.big_recording_buffer[self.big_recording_buffer_pos] = data_len
            self.big_recording_buffer_pos += 1
            self.big_recording_buffer[self.big_recording_buffer_pos:self.big_recording_buffer_pos + data_len] = data
            self.big_recording_buffer_pos += data_len
            self.frames_in_buffer += 1
            print(f"\r\nAdded frame number {self.frames_in_buffer}\r\n")
        else:
            print("\r\nBuffer is full. The frame does not fit.\r\n")
    
    def _cmd_show(self):
        """Muestra el contenido del buffer de grabación"""
        if self.frames_in_buffer > 0:
            print("\r\nFrames stored in the recording buffer:\r\n")
            pos = 0
            for i in range(1, self.frames_in_buffer + 1):
                if pos >= config.RECORDINGBUFFERSIZE:
                    break
                frame_len = self.big_recording_buffer[pos]
                pos += 1
                if 0 < frame_len <= 60 and pos + frame_len <= config.RECORDINGBUFFERSIZE:
                    frame_data = bytes(self.big_recording_buffer[pos:pos + frame_len])
                    hex_str = utils.bytes_to_hex(frame_data)
                    print(f"\r\nFrame {i} : {hex_str}\r\n")
                    pos += frame_len
            print("\r\n")
        else:
            print("Error: Wrong parameters.\r\n")
    
    def _cmd_play(self, frame_num: int):
        """Reproduce frames del buffer"""
        if frame_num <= self.frames_in_buffer:
            print("\r\nReplaying recorded frames.\r\n")
            pos = 0
            for i in range(1, self.frames_in_buffer + 1):
                if pos >= config.RECORDINGBUFFERSIZE:
                    break
                frame_len = self.big_recording_buffer[pos]
                pos += 1
                if 0 < frame_len <= 60 and (i == frame_num or frame_num == 0):
                    frame_data = bytes(self.big_recording_buffer[pos:pos + frame_len])
                    self.cc1101.SendData(frame_data, frame_len)
                pos += frame_len
            print("Done.\r\n")
        else:
            print("Error: Wrong parameters.\r\n")
    
    def _cmd_scan(self, start_freq: float, stop_freq: float):
        """Escanea rango de frecuencias"""
        print(f"\r\nScanning frequency range from {start_freq} MHz to {stop_freq} MHz, press Enter to stop...\r\n")
        self.scan_active = True
        
        # Configurar para escaneo
        self.cc1101.Init()
        self.cc1101.setRxBW(58.0)
        self.cc1101.SetRx()
        
        freq = start_freq
        mark_rssi = -100
        mark_freq = 0.0
        compare_freq = 0
        
        while self.scan_active:
            # Verificar si hay entrada del usuario
            if sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
                sys.stdin.readline()
                break
            
            self.cc1101.setMHZ(freq)
            time.sleep(0.01)  # Pequeña pausa para estabilización
            rssi = self.cc1101.getRssi()
            
            if rssi > -75:
                if rssi > mark_rssi:
                    mark_rssi = rssi
                    mark_freq = freq
            
            freq += 0.01
            
            if freq > stop_freq:
                freq = start_freq
                
                if mark_rssi > -75:
                    fr = int(mark_freq * 100)
                    if fr == compare_freq:
                        print(f"\r\nSignal found at Freq: {mark_freq} Rssi: {mark_rssi}\r\n")
                        mark_rssi = -100
                        compare_freq = 0
                        mark_freq = 0.0
                    else:
                        compare_freq = fr
                        freq = mark_freq - 0.10
                        mark_freq = 0.0
                        mark_rssi = -100
        
        self.scan_active = False
        print("\r\n")
    
    def _cmd_brute(self, usec: int, bits: int):
        """Brute force attack"""
        if usec <= 0:
            print("Error: Wrong parameters.\r\n")
            return
        
        print("\r\nStarting Brute Forcing, press Enter to stop...\r\n")
        
        # Configurar modo RAW
        self.cc1101.setCCMode(0)
        self.cc1101.setPktFormat(3)
        self.cc1101.SetTx()
        
        if GPIO_AVAILABLE:
            GPIO.setup(self.cc1101.gdo0, GPIO.OUT)
        
        power_of_two = 1 << bits
        
        for brute_val in range(power_of_two):
            # Verificar si hay entrada
            if sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
                sys.stdin.readline()
                break
            
            # Enviar 5 veces cada código
            for k in range(5):
                for j in range(bits - 1, -1, -1):
                    bit_value = (brute_val >> j) & 1
                    if GPIO_AVAILABLE:
                        GPIO.output(self.cc1101.gdo0, bit_value)
                    time.sleep(usec / 1000000.0)
        
        # Restaurar modo normal
        self.cc1101.setCCMode(1)
        self.cc1101.setPktFormat(0)
        self.cc1101.SetTx()
        
        print("\r\nBrute forcing complete.\r\n\r\n")
    
    def _cmd_rxraw(self, usec: int):
        """RX RAW mode - sniffer"""
        print("\r\nSniffer enabled...\r\n")
        self.rxraw_active = True
        
        # Configurar modo RAW
        self.cc1101.setCCMode(0)
        self.cc1101.setPktFormat(3)
        self.cc1101.SetRx()
        
        if GPIO_AVAILABLE:
            GPIO.setup(self.cc1101.gdo0, GPIO.IN)
        
        buffer = bytearray(32)
        
        while self.rxraw_active:
            # Verificar si hay entrada
            if sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
                sys.stdin.readline()
                break
            
            # Leer 32 bytes
            for i in range(32):
                byte_val = 0
                for j in range(7, -1, -1):
                    if GPIO_AVAILABLE:
                        bit_val = GPIO.input(self.cc1101.gdo0)
                    else:
                        bit_val = 0
                    byte_val |= (bit_val << j)
                    time.sleep(usec / 1000000.0)
                buffer[i] = byte_val
            
            # Mostrar en hex
            hex_str = utils.bytes_to_hex(buffer)
            print(hex_str, end='', flush=True)
        
        # Restaurar modo normal
        self.cc1101.setCCMode(1)
        self.cc1101.setPktFormat(0)
        self.cc1101.SetRx()
        print("\r\nStopping the sniffer.\r\n\r\n")
    
    def _cmd_recraw(self, usec: int):
        """Record RAW data"""
        print("\r\nWaiting for radio signal to start RAW recording...\r\n")
        
        # Configurar modo RAW
        self.cc1101.setCCMode(0)
        self.cc1101.setPktFormat(3)
        self.cc1101.SetRx()
        
        if GPIO_AVAILABLE:
            GPIO.setup(self.cc1101.gdo0, GPIO.IN)
            # Esperar señal
            initial_state = GPIO.input(self.cc1101.gdo0)
            time.sleep(0.001)
            while GPIO.input(self.cc1101.gdo0) == GPIO.LOW:
                time.sleep(0.001)
        
        print("\r\nStarting RAW recording to the buffer...\r\n")
        
        # Grabar
        for i in range(config.RECORDINGBUFFERSIZE):
            byte_val = 0
            for j in range(7, -1, -1):
                if GPIO_AVAILABLE:
                    bit_val = GPIO.input(self.cc1101.gdo0)
                else:
                    bit_val = 0
                byte_val |= (bit_val << j)
                time.sleep(usec / 1000000.0)
            self.big_recording_buffer[i] = byte_val
        
        # Restaurar modo normal
        self.cc1101.setCCMode(1)
        self.cc1101.setPktFormat(0)
        self.cc1101.SetRx()
        print("\r\nRecording RAW data complete.\r\n\r\n")
    
    def _cmd_playraw(self, usec: int):
        """Play RAW data"""
        print("\r\nReplaying RAW data from the buffer...\r\n")
        
        # Configurar modo RAW
        self.cc1101.setCCMode(0)
        self.cc1101.setPktFormat(3)
        self.cc1101.SetTx()
        
        if GPIO_AVAILABLE:
            GPIO.setup(self.cc1101.gdo0, GPIO.OUT)
        
        # Reproducir
        for i in range(1, config.RECORDINGBUFFERSIZE):
            byte_val = self.big_recording_buffer[i]
            for j in range(7, -1, -1):
                bit_val = (byte_val >> j) & 1
                if GPIO_AVAILABLE:
                    GPIO.output(self.cc1101.gdo0, bit_val)
                time.sleep(usec / 1000000.0)
        
        # Restaurar modo normal
        self.cc1101.setCCMode(1)
        self.cc1101.setPktFormat(0)
        self.cc1101.SetTx()
        print("\r\nReplaying RAW data complete.\r\n\r\n")
    
    def _cmd_showraw(self):
        """Show RAW data"""
        print("\r\nRecorded RAW data:\r\n")
        for i in range(0, config.RECORDINGBUFFERSIZE, 32):
            chunk = bytes(self.big_recording_buffer[i:i + 32])
            hex_str = utils.bytes_to_hex(chunk)
            print(hex_str, end='', flush=True)
        print("\r\n\r\n")
    
    def _cmd_showbit(self):
        """Show RAW data as bit stream"""
        print("\r\nRecorded RAW data as bit stream:\r\n")
        for i in range(0, config.RECORDINGBUFFERSIZE, 32):
            chunk = bytes(self.big_recording_buffer[i:i + 32])
            bit_stream = utils.format_bit_stream(chunk)
            print(bit_stream, end='', flush=True)
        print("\r\n\r\n")
    
    def _add_raw(self, data: bytes):
        """Añade datos RAW al buffer"""
        data_len = len(data)
        if (self.big_recording_buffer_pos + data_len) < config.RECORDINGBUFFERSIZE:
            self.big_recording_buffer[self.big_recording_buffer_pos:self.big_recording_buffer_pos + data_len] = data
            self.big_recording_buffer_pos += data_len
            print("\r\nChunk added to recording buffer\r\n\r\n")
        else:
            print("\r\nBuffer is full. The frame does not fit.\r\n")
    
    def _cmd_save(self):
        """Guarda el buffer a archivo"""
        print("\r\nSaving recording buffer content to file...\r\n")
        try:
            data = {
                'buffer': list(self.big_recording_buffer),
                'position': self.big_recording_buffer_pos,
                'frames': self.frames_in_buffer
            }
            with open(config.EEPROM_FILE, 'wb') as f:
                pickle.dump(data, f)
            print("\r\nSaving complete.\r\n\r\n")
        except Exception as e:
            print(f"Error saving: {e}\r\n")
    
    def _cmd_load(self):
        """Carga el buffer desde archivo"""
        print("\r\nLoading content from file into recording buffer...\r\n")
        try:
            with open(config.EEPROM_FILE, 'rb') as f:
                data = pickle.load(f)
            self.big_recording_buffer = bytearray(data['buffer'])
            self.big_recording_buffer_pos = data.get('position', 0)
            self.frames_in_buffer = data.get('frames', 0)
            print("\r\nLoading complete. Enter 'show' or 'showraw' to see the buffer content.\r\n\r\n")
        except FileNotFoundError:
            print("No saved buffer found.\r\n")
        except Exception as e:
            print(f"Error loading: {e}\r\n")
    
    def process_rf(self):
        """Procesa paquetes RF recibidos"""
        if self.cc1101.CheckReceiveFlag() and (self.receiving_mode or self.recording_mode or self.chat_mode):
            if self.cc1101.CheckCRC():
                # Limpiar buffer
                self.cc_receiving_buffer = bytearray(config.CCBUFFERSIZE)
                length = self.cc1101.ReceiveData(self.cc_receiving_buffer)
                
                if length > 0 and length < config.CCBUFFERSIZE:
                    # Modo Chat
                    if self.chat_mode:
                        try:
                            text = bytes(self.cc_receiving_buffer[:length]).decode('utf-8', errors='ignore')
                            print(text, end='', flush=True)
                        except:
                            pass
                    
                    # Modo Recepción
                    elif self.receiving_mode and not self.recording_mode:
                        hex_str = utils.bytes_to_hex(bytes(self.cc_receiving_buffer[:length]))
                        print(hex_str, end='', flush=True)
                        self.cc1101.SetRx()
                    
                    # Modo Grabación
                    elif self.recording_mode and not self.receiving_mode:
                        if (self.big_recording_buffer_pos + length + 1) < config.RECORDINGBUFFERSIZE:
                            self.big_recording_buffer[self.big_recording_buffer_pos] = length
                            self.big_recording_buffer_pos += 1
                            self.big_recording_buffer[self.big_recording_buffer_pos:self.big_recording_buffer_pos + length] = self.cc_receiving_buffer[:length]
                            self.big_recording_buffer_pos += length
                            self.frames_in_buffer += 1
                            self.cc1101.SetRx()
                        else:
                            print(f"\r\nRecording buffer full! Stopping..\r\nFrames stored: {self.frames_in_buffer}\r\n")
                            self.big_recording_buffer_pos = 0
                            self.recording_mode = False
    
    def process_jamming(self):
        """Procesa modo jamming"""
        if self.jamming_mode:
            # Generar datos aleatorios
            random_data = bytearray([random.randint(0, 255) for _ in range(60)])
            self.cc1101.SendData(random_data, 60)
            time.sleep(0.01)
    
    def run(self):
        """Bucle principal"""
        print("CC1101 terminal tool connected, use 'help' for list of commands...\n\r")
        print("(C) Basado en Adam Loboda 2023\n\r")
        print()
        
        # Configurar stdin para no bloquear (solo en Linux/Unix)
        try:
            import fcntl
            flags = fcntl.fcntl(sys.stdin.fileno(), fcntl.F_GETFL)
            fcntl.fcntl(sys.stdin.fileno(), fcntl.F_SETFL, flags | os.O_NONBLOCK)
        except (ImportError, AttributeError):
            # En Windows o sistemas sin fcntl, usar threading
            pass
        
        try:
            while True:
                # Procesar comandos de entrada
                try:
                    if sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
                        line = sys.stdin.readline()
                        if line:
                            if self.chat_mode:
                                # En modo chat, enviar directamente
                                data = line.encode('utf-8')
                                self.cc1101.SendData(data, len(data))
                                if self.do_echo:
                                    print(line, end='', flush=True)
                            else:
                                # Procesar comando
                                if self.do_echo:
                                    print(line, end='', flush=True)
                                self.exec_command(line.strip())
                except (IOError, OSError):
                    pass
                
                # Procesar RF
                self.process_rf()
                
                # Procesar jamming
                self.process_jamming()
                
                # Pequeña pausa para no saturar CPU
                time.sleep(0.001)
        
        except KeyboardInterrupt:
            print("\n\r\nShutting down...")
        finally:
            self.cc1101.cleanup()


def main():
    """Función principal"""
    terminal = CC1101Terminal()
    terminal.run()


if __name__ == "__main__":
    main()

