#!/usr/bin/env python3
"""
Génère des chaînes de caractères encodées en little-endian pour le shellcode
Usage: python3 gen_strings.py
"""

def encode_string(text):
    """Encode une chaîne en tableau de uint64 little-endian"""
    data = text.encode('latin-1')
    # Padding pour aligner sur 8 bytes
    if len(data) % 8 != 0:
        data = data + b'\x00' * (8 - (len(data) % 8))
    
    # Convertir en uint64 little-endian
    result = []
    for i in range(0, len(data), 8):
        chunk = data[i:i+8]
        value = int.from_bytes(chunk, byteorder='little')
        result.append(f"0x{value:016x}")
    
    return result

def generate_c_array(name, text):
    """Génère le code C pour un tableau volatile"""
    encoded = encode_string(text)
    
    print(f"    volatile unsigned long long {name}[{len(encoded)}];")
    for i, val in enumerate(encoded):
        print(f"    {name}[{i}] = {val};")
    print()

print("// Messages pour le shellcode")
print("// Copie ce code dans Shellcode.c\n")

# Messages existants
print("// Message de bienvenue")
generate_c_array("Hello_Game", "Hello from BO6")

print("// Message d'erreur de chargement de bibliothèque")
generate_c_array("Lib_Error", "Hib err lib load")

print("// Message de succès")
generate_c_array("Success_Msg", "PRX loaded ok")

print("\n// Messages additionnels utiles:\n")

print("// Retry automatique")
generate_c_array("Retry_Msg", "Retry in 3s")

print("// PRX introuvable")
generate_c_array("NotFound_Msg", "PRX not found")

print("// Chargement...")
generate_c_array("Loading_Msg", "Loading PRX...")
