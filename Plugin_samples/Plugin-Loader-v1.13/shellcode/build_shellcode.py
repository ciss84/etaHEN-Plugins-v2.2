#!/usr/bin/env python3
"""
build_shellcode.py
Compile Shellcode.c et met a jour utils.hpp automatiquement.
Lance depuis le dossier shellcode/ : python build_shellcode.py
"""

import subprocess
import sys
import os
import re
import shutil
from pathlib import Path

CLANG_FLAGS = [
    "--target=x86_64-freebsd-pc-elf",
    "-ffreestanding",
    "-fPIC", "-fPIE", "-fomit-frame-pointer",
    "-Wall", "-Werror",
    "-O3", "-march=znver2", "-mavx2",
]

SOURCE_FILE   = "Shellcode.c"
OBJ_FILE      = "Game_Shellcode.o"
UTILS_HPP     = Path(__file__).parent.parent / "source" / "utils.hpp"
TEMPLATE_NAME = "BUILDER_TEMPLATE"
SIZE_NAME     = "SHELLCODE_SIZE"

def find_clang():
    if shutil.which("clang"):
        return "clang"
    candidates = [
        r"C:\Program Files\LLVM\bin\clang.exe",
        r"C:\Program Files (x86)\LLVM\bin\clang.exe",
    ]
    for c in candidates:
        if Path(c).exists():
            return c
    return None

def compile_shellcode(clang, src, obj):
    cmd = [clang] + CLANG_FLAGS + ["-c", src, "-o", obj]
    print(f"[1/3] Compilation...")
    print(f"      {' '.join(cmd)}")
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"[ERREUR] Compilation echouee !")
        print(r.stderr)
        return False
    print(f"[OK] {obj} genere")
    return True

def find_objdump():
    for tool in ["llvm-objdump", "objdump"]:
        if shutil.which(tool):
            return tool
    # Cherche dans LLVM
    candidates = [
        r"C:\Program Files\LLVM\bin\llvm-objdump.exe",
        r"C:\Program Files (x86)\LLVM\bin\llvm-objdump.exe",
    ]
    for c in candidates:
        if Path(c).exists():
            return c
    return None

def extract_bytes(obj):
    print(f"[2/3] Extraction des bytes...")
    
    objdump = find_objdump()
    if not objdump:
        print("[ERREUR] objdump/llvm-objdump introuvable")
        return None

    r = subprocess.run([objdump, "-d", obj], capture_output=True, text=True)
    if r.returncode != 0:
        print(f"[ERREUR] objdump echoue : {r.stderr}")
        return None

    bytes_data = []
    in_func = False
    for line in r.stdout.splitlines():
        if "scePadReadState_Hook" in line:
            in_func = True
            continue
        if not in_func:
            continue
        if line.strip() == "" or line.startswith("Disassembly"):
            break
        m = re.match(r"\s+[0-9a-f]+:\t([0-9a-f][0-9a-f ]*)", line)
        if m:
            bytes_data.extend(m.group(1).split())

    if not bytes_data:
        print("[ERREUR] Aucun byte extrait — scePadReadState_Hook introuvable")
        print("Sortie objdump :")
        print(r.stdout[:500])
        return None

    print(f"[OK] {len(bytes_data)} bytes extraits")
    return bytes_data

def update_utils_hpp(bytes_data):
    if not UTILS_HPP.exists():
        print(f"[ERREUR] utils.hpp introuvable : {UTILS_HPP.resolve()}")
        return False

    print(f"[3/3] Mise a jour de utils.hpp...")
    content = UTILS_HPP.read_text(encoding="utf-8")

    new_size  = len(bytes_data)
    formatted = ", ".join(f"0x{b}" for b in bytes_data)
    new_template = f"static constexpr GameBuilder {TEMPLATE_NAME} {{\n    {formatted}\n}};"

    pattern = rf"static constexpr GameBuilder {TEMPLATE_NAME}\s*{{[^}}]+}};"
    if not re.search(pattern, content, re.DOTALL):
        print(f"[ERREUR] {TEMPLATE_NAME} introuvable dans utils.hpp")
        return False

    content = re.sub(pattern, new_template, content, flags=re.DOTALL)
    size_pat = rf"static constexpr size_t {SIZE_NAME} = \d+;"
    content  = re.sub(size_pat, f"static constexpr size_t {SIZE_NAME} = {new_size};", content)

    UTILS_HPP.write_text(content, encoding="utf-8")
    print(f"[OK] {TEMPLATE_NAME} mis a jour ({new_size} bytes)")
    return True

def main():
    print("=" * 50)
    print(" PS5 Shellcode Builder")
    print("=" * 50)

    os.chdir(Path(__file__).parent)
    print(f"[INFO] Dossier : {Path.cwd()}")

    clang = find_clang()
    if not clang:
        print("[ERREUR] clang introuvable.")
        print("Telecharge LLVM : https://releases.llvm.org")
        return

    print(f"[OK] clang : {clang}")

    if not compile_shellcode(clang, SOURCE_FILE, OBJ_FILE):
        return

    bytes_data = extract_bytes(OBJ_FILE)
    if not bytes_data:
        return

    if not update_utils_hpp(bytes_data):
        return

    print("=" * 50)
    print(" DONE - utils.hpp mis a jour !")
    print(" Relance ton build CMake.")
    print("=" * 50)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n[EXCEPTION] {e}")
        import traceback
        traceback.print_exc()
    input("\nAppuie sur Entree pour fermer...")
