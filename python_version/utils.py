"""
Utilidades y funciones auxiliares
Migrado de C++/Arduino a Python
"""


def bytes_to_hex(data):
    """
    Convierte bytes a string hexadecimal
    Equivalente a asciitohex() en C++
    
    Args:
        data: bytes o bytearray a convertir
        
    Returns:
        str: String hexadecimal en mayúsculas
    """
    return ''.join(f'{byte:02X}' for byte in data)


def hex_to_bytes(hex_string):
    """
    Convierte string hexadecimal a bytes
    Equivalente a hextoascii() en C++
    
    Args:
        hex_string: String hexadecimal (ej: "AABBCC")
        
    Returns:
        bytes: Bytes convertidos
    """
    # Limpiar espacios y asegurar longitud par
    hex_string = hex_string.strip().replace(' ', '')
    if len(hex_string) % 2 != 0:
        raise ValueError("Hex string debe tener longitud par")
    
    try:
        return bytes.fromhex(hex_string)
    except ValueError as e:
        raise ValueError(f"Hex string inválido: {e}")


def validate_hex_string(hex_string, max_length=120):
    """
    Valida que un string hexadecimal sea válido
    
    Args:
        hex_string: String a validar
        max_length: Longitud máxima permitida
        
    Returns:
        bool: True si es válido
    """
    if not hex_string or len(hex_string) > max_length:
        return False
    if len(hex_string) % 2 != 0:
        return False
    try:
        bytes.fromhex(hex_string)
        return True
    except ValueError:
        return False


def format_bit_stream(data):
    """
    Convierte bytes a representación de bits visual
    Usado en showbit command
    
    Args:
        data: bytes o bytearray
        
    Returns:
        str: Representación visual de bits
    """
    hex_str = bytes_to_hex(data)
    bit_map = {
        '0': '____', '1': '___-', '2': '__-_', '3': '__--',
        '4': '_-__', '5': '_-_-', '6': '_--_', '7': '_---',
        '8': '-___', '9': '-__-', 'A': '-_-_', 'B': '-_--',
        'C': '--__', 'D': '--_-', 'E': '---_', 'F': '----'
    }
    
    result = []
    for char in hex_str:
        result.append(bit_map.get(char.upper(), '____'))
    
    return ''.join(result)


def chunk_data(data, chunk_size=32):
    """
    Divide datos en chunks para mostrar
    
    Args:
        data: bytes o bytearray
        chunk_size: Tamaño del chunk
        
    Returns:
        list: Lista de chunks
    """
    chunks = []
    for i in range(0, len(data), chunk_size):
        chunks.append(data[i:i + chunk_size])
    return chunks


def validate_frequency(freq):
    """
    Valida que la frecuencia esté en un rango válido del CC1101
    
    Args:
        freq: Frecuencia en MHz
        
    Returns:
        bool: True si es válida
    """
    valid_ranges = [
        (300.0, 348.0),
        (387.0, 464.0),
        (779.0, 928.0)
    ]
    
    for min_freq, max_freq in valid_ranges:
        if min_freq <= freq <= max_freq:
            return True
    return False

