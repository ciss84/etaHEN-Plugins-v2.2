#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "=================================================="
echo " PS5 Shellcode Builder (WSL/bash)"
echo "=================================================="
echo "[INFO] Dossier : $SCRIPT_DIR"

# Verifier clang
if ! command -v clang &>/dev/null; then
    echo "[ERREUR] clang introuvable."
    echo "Lance : sudo apt install clang"
    read -p "Appuie sur Entree..."
    exit 1
fi

CLANG_VER=$(clang --version | grep -oP '\d+\.\d+\.\d+' | head -1 | cut -d. -f1)
echo "[OK] clang version : $CLANG_VER"

if [ "$CLANG_VER" -lt 6 ]; then
    echo "[ERREUR] clang $CLANG_VER trop vieux, faut >= 6"
    echo "Lance : sudo apt install clang-14"
    read -p "Appuie sur Entree..."
    exit 1
fi

# znver2 dispo depuis clang 8, mais utilise x86-64 si < 9 pour compat
if [ "$CLANG_VER" -ge 9 ]; then
    CPU="-march=znver2 -mavx2"
else
    CPU="-march=x86-64"
fi

echo "[1/3] Compilation de Shellcode.c..."
clang --target=x86_64-freebsd-pc-elf \
      -fPIC -fPIE -fomit-frame-pointer \
      -Wall -Werror \
      -O3 $CPU \
      -c Shellcode.c -o Game_Shellcode.o

if [ $? -ne 0 ]; then
    echo "[ERREUR] Compilation echouee"
    read -p "Appuie sur Entree..."
    exit 1
fi
echo "[OK] Game_Shellcode.o genere"

echo "[2/3] Extraction bytes + mise a jour utils.hpp..."
python3 build_shellcode.py

echo "=================================================="
echo " DONE - Relance ton build CMake"
echo "=================================================="
read -p "Appuie sur Entree..."
