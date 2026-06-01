#!/usr/bin/env python3
"""
Rebuild Helper pour GTRDLoader
Compile le shellcode et extrait les bytes automatiquement
"""

import subprocess
import sys
import os
import re
from pathlib import Path

class ShellcodeBuilder:
    def __init__(self):
        self.clang_cmd = [
            "clang",
            "--target=x86_64-freebsd-pc-elf",
            "-fPIC",
            "-fPIE",
            "-fomit-frame-pointer",
            "-Wall",
            "-Werror",
            "-gfull",
            "-gdwarf-2",
            "-O3",
            "-march=znver2",
            "-mavx2",
        ]
    
    def compile_shellcode(self, source_file, output_file):
        """Compile le fichier shellcode C"""
        cmd = self.clang_cmd + ["-c", source_file, "-o", output_file]
        
        print(f"🔨 Compiling {source_file}...")
        print(f"Command: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            print(f"✅ Compilation successful: {output_file}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Compilation failed!")
            print(f"STDERR: {e.stderr}")
            return False
    
    def extract_shellcode(self, obj_file):
        """Extrait le shellcode depuis le fichier objet"""
        print(f"\n📦 Extracting shellcode from {obj_file}...")
        
        # Utiliser objdump pour désassembler
        cmd = ["objdump", "-d", obj_file]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            # Parser la sortie pour extraire les bytes
            bytes_data = []
            in_function = False
            
            for line in result.stdout.split('\n'):
                # Détecter le début de la fonction
                if 'scePadReadState_Hook' in line:
                    in_function = True
                    continue
                
                if not in_function:
                    continue
                
                # Ligne vide ou nouvelle section = fin
                if line.strip() == '' or line.startswith('Disassembly'):
                    break
                
                # Parser les bytes hex
                # Format: "  40: 48 89 d3              mov    %rdx,%rbx"
                match = re.match(r'\s+[0-9a-f]+:\s+([0-9a-f\s]+)', line)
                if match:
                    hex_bytes = match.group(1).split()
                    bytes_data.extend(hex_bytes)
            
            if not bytes_data:
                print("❌ No shellcode bytes found!")
                return None
            
            print(f"✅ Extracted {len(bytes_data)} bytes")
            return bytes_data
            
        except subprocess.CalledProcessError as e:
            print(f"❌ objdump failed: {e.stderr}")
            return None
    
    def format_cpp_array(self, bytes_data, name="SHELLCODE", bytes_per_line=16):
        """Formate les bytes en array C++ lisible"""
        output = f"static constexpr GameBuilder {name} {{\n"
        
        for i in range(0, len(bytes_data), bytes_per_line):
            chunk = bytes_data[i:i+bytes_per_line]
            formatted = ", ".join([f"0x{b}" for b in chunk])
            output += f"    {formatted}"
            if i + bytes_per_line < len(bytes_data):
                output += ","
            output += "\n"
        
        output += "};"
        return output
    
    def update_utils_hpp(self, bytes_data, template_name):
        """Met à jour utils.hpp avec le nouveau shellcode"""
        hpp_file = Path("utils.hpp")
        
        if not hpp_file.exists():
            print(f"⚠️  utils.hpp not found at {hpp_file.absolute()}")
            return False
        
        # Lire le fichier
        content = hpp_file.read_text()
        
        # Générer le nouveau template
        new_size = len(bytes_data)
        formatted_array = ", ".join([f"0x{b}" for b in bytes_data])
        
        new_template = f"static constexpr GameBuilder {template_name} {{\n    {formatted_array}\n}};"
        
        # Pattern pour trouver l'ancien template
        pattern = rf"static constexpr GameBuilder {template_name}\s*{{[^}}]+}};"
        
        if re.search(pattern, content):
            # Remplacer
            new_content = re.sub(pattern, new_template, content, flags=re.DOTALL)
            
            # Mettre à jour la taille aussi
            if template_name == "BUILDER_TEMPLATE":
                size_pattern = r"static constexpr size_t SHELLCODE_SIZE = \d+;"
                new_content = re.sub(size_pattern, f"static constexpr size_t SHELLCODE_SIZE = {new_size};", new_content)
            elif template_name == "BUILDER_TEMPLATE_AUTO":
                size_pattern = r"static constexpr size_t SHELLCODE_SIZE_AUTO = \d+;"
                new_content = re.sub(size_pattern, f"static constexpr size_t SHELLCODE_SIZE_AUTO = {new_size};", new_content)
            
            hpp_file.write_text(new_content)
            print(f"✅ Updated {template_name} in utils.hpp ({new_size} bytes)")
            return True
        else:
            print(f"⚠️  Template {template_name} not found in utils.hpp")
            return False

def main():
    print("=" * 60)
    print("GTRDLoader Shellcode Rebuild Tool")
    print("=" * 60)
    
    builder = ShellcodeBuilder()
    
    # Déterminer quel fichier compiler
    if len(sys.argv) > 1:
        source_file = sys.argv[1]
    else:
        # Par défaut, compiler Shellcode_optimized.c
        if Path("Shellcode_optimized.c").exists():
            source_file = "Shellcode_optimized.c"
        elif Path("Shellcode.c").exists():
            source_file = "Shellcode.c"
        else:
            print("❌ No shellcode source file found!")
            print("Usage: python3 rebuild_shellcode.py [source_file.c]")
            sys.exit(1)
    
    source_path = Path(source_file)
    if not source_path.exists():
        print(f"❌ Source file not found: {source_file}")
        sys.exit(1)
    
    # Fichier de sortie
    output_file = "Game_Shellcode.o"
    
    # Compiler
    if not builder.compile_shellcode(str(source_path), output_file):
        sys.exit(1)
    
    # Extraire les bytes
    bytes_data = builder.extract_shellcode(output_file)
    if not bytes_data:
        sys.exit(1)
    
    # Afficher le résultat formaté
    print("\n" + "=" * 60)
    print("📋 Formatted C++ array:")
    print("=" * 60)
    formatted = builder.format_cpp_array(bytes_data, "BUILDER_TEMPLATE")
    print(formatted)
    
    # Sauvegarder dans un fichier
    output_txt = Path("shellcode_output.txt")
    output_txt.write_text(formatted)
    print(f"\n💾 Saved to {output_txt}")
    
    # Proposer de mettre à jour utils.hpp
    print("\n" + "=" * 60)
    response = input("Update utils.hpp with this shellcode? [y/N]: ")
    
    if response.lower() == 'y':
        # Déterminer quel template mettre à jour
        if "auto" in source_file.lower() or "optimized" in source_file.lower():
            template = "BUILDER_TEMPLATE_AUTO"
        else:
            template = "BUILDER_TEMPLATE"
        
        print(f"\nWhich template to update?")
        print(f"1. BUILDER_TEMPLATE (standard, with controller check)")
        print(f"2. BUILDER_TEMPLATE_AUTO (auto-load, immediate)")
        choice = input("Choice [1]: ").strip() or "1"
        
        template = "BUILDER_TEMPLATE" if choice == "1" else "BUILDER_TEMPLATE_AUTO"
        
        builder.update_utils_hpp(bytes_data, template)
    
    print("\n✨ Done!")
    print("=" * 60)

if __name__ == "__main__":
    main()
