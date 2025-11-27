# encoderc.py (v51.7 - Bit a Bit / Corrected Authorship)
import os
import pickle
import numpy as np
from PIL import Image
from pathlib import Path
import sys
import argparse
import zlib
import time
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import json
from datetime import datetime

TILE_SIZE = 128

# --- FUNCIONES DE ENCRIPTACIÓN ---
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_data(data_to_pickle: dict, password: str) -> bytes:
    salt = os.urandom(16)
    key = derive_key(password, salt)
    fernet = Fernet(key)
    pickled_data = pickle.dumps(data_to_pickle)
    encrypted_data = fernet.encrypt(pickled_data)
    final_crs_data = {
        'is_encrypted': True,
        'salt': salt,
        'encrypted_data': encrypted_data
    }
    return pickle.dumps(final_crs_data)

def report_progress(percentage):
    print(f"PROGRESS:{percentage}")
    sys.stdout.flush()

def paeth_predictor(a, b, c):
    p = a + b - c
    pa = abs(p - a)
    pb = abs(p - b)
    pc = abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    elif pb <= pc:
        return b
    else:
        return c

# --- FUNCIÓN PARA LECTURA SEGURA ---
def get_tracker_author(tracker_path: Path) -> str | None:
    if not tracker_path or not tracker_path.is_file():
        return None
    try:
        with open(tracker_path, 'r') as f:
            tracker_data = json.load(f)
            return str(tracker_data.get('author', None)).strip()
    except Exception:
        return None

# --- FUNCIÓN PRINCIPAL ---
def create_lexicon_paeth_crs(
    image_path: Path, 
    output_base_name: str, 
    crs_dir: Path, 
    models_dir: Path, 
    password: str = None, 
    author: str = None, 
    tracker_path: Path = None, 
    password_mode: str = 'none',
    user_ip: str = "Unknown",       
    user_location: str = "Unknown"  
):
    start_time = time.time()
    report_progress(0)
    print(f"--- XtremeRTX Encoder v51.7 (Bit-a-Bit / User Data) ---")
    
    # 1. AUTORÍA EXTERNA (LENTES)
    # Si viene del S4, 'author' será el usuario logueado.
    tracker_author_code = get_tracker_author(tracker_path)
    public_author_value = tracker_author_code if tracker_author_code else (author if author else 'NANO-XtremeRTX')
    
    try:
        lexicon_path = models_dir / "khipu_lexicon.npy"
        if not lexicon_path.exists():
            sys.exit(f"FATAL: No se encontró 'khipu_lexicon.npy' en {models_dir}")
        khipu_lexicon = np.load(lexicon_path)
        lexicon_dict = {tuple(pattern): i for i, pattern in enumerate(khipu_lexicon)}
        print(f"- Léxico Khipu cargado ({len(khipu_lexicon)} patrones).")

        original_pil = Image.open(image_path).convert('RGB')
        original_w, original_h = original_pil.size
        original_array = np.array(original_pil).astype(np.int16)
        report_progress(5)
        
        compressed_tiles = []
        tile_count = 0
        total_tiles = len(range(0, original_h, TILE_SIZE)) * len(range(0, original_w, TILE_SIZE))
        
        print(f"- Iniciando procesamiento por bloques de {TILE_SIZE}x{TILE_SIZE}...")
        border_pixel = np.array([0, 0, 0], dtype=np.int16)

        for y in range(0, original_h, TILE_SIZE):
            for x in range(0, original_w, TILE_SIZE):
                tile = original_array[y:y+TILE_SIZE, x:x+TILE_SIZE]
                h, w, _ = tile.shape
                
                residual_tile = np.zeros_like(tile, dtype=np.int16)
                for tile_y in range(h):
                    for tile_x in range(w):
                        abs_y, abs_x = y + tile_y, x + tile_x
                        
                        a = original_array[abs_y, abs_x - 1] if abs_x > 0 else border_pixel
                        b = original_array[abs_y - 1, abs_x] if abs_y > 0 else border_pixel
                        c = original_array[abs_y - 1, abs_x - 1] if abs_y > 0 and abs_x > 0 else border_pixel
                        
                        prediction = np.array([paeth_predictor(a[i], b[i], c[i]) for i in range(3)], dtype=np.int16)
                        
                        real_value = tile[tile_y, tile_x]
                        residual_tile[tile_y, tile_x] = real_value - prediction

                flat_residual = residual_tile.flatten()
                LEXICON_MARKER = 32767
                encoded_stream = []
                i = 0
                while i < len(flat_residual):
                    found_match = False
                    for length in range(8, 2, -1):
                        if i + length <= len(flat_residual):
                            sequence = tuple(flat_residual[i:i+length])
                            if sequence in lexicon_dict:
                                encoded_stream.append(LEXICON_MARKER)
                                encoded_stream.append(lexicon_dict[sequence])
                                i += length
                                found_match = True
                                break
                    if not found_match:
                        encoded_stream.append(flat_residual[i])
                        i += 1
                        
                encoded_array = np.array(encoded_stream, dtype=np.int16)
                compressed_chunk = zlib.compress(encoded_array.tobytes(), level=9)
                compressed_tiles.append(compressed_chunk)
                
                tile_count += 1
                if total_tiles > 0:
                    report_progress(5 + int((tile_count / total_tiles) * 85))

        print("- Todos los bloques procesados.")
        report_progress(90)

        # 4. DATOS INTERNOS (AUTORÍA NANO FIJA)
        crs_data = {
            "version": "51.7_LexiconPaeth",
            "payload_list": compressed_tiles,
            "original_shape": original_array.shape,
            "tile_size": TILE_SIZE,
            "original_format": original_pil.format,
            "author": "NANO XTREMERTX 1.0" # <-- INTERNA FIJA
        }

        # 5. METADATOS PÚBLICOS (AUTORÍA USUARIO + Q-DNA)
        creation_timestamp = datetime.now().isoformat()

        public_metadata = {
            'public_author': public_author_value, # <-- USUARIO LOGUEADO
            'version_id': "51.7_LexiconPaeth",
            'password_mode': password_mode,
            'created_at': creation_timestamp,
            'creation_ip': user_ip,             # <--- IP
            'creation_location': user_location, # <--- LOC
            'qdna': "NANO XTREMERTX 1.0"        # <--- FIRMA
        }
        
        os.makedirs(crs_dir, exist_ok=True)
        crs_path = crs_dir / f"{output_base_name}.crs"
        final_data_to_save = {}

        # Lógica de Guardado
        if password_mode == 'full' and password:
            print(f"INFO: Encriptando CRS (Modo: {password_mode})")
            encrypted_block_binary = encrypt_data(crs_data, password)
            final_data_to_save = pickle.loads(encrypted_block_binary) 
            final_data_to_save.update(public_metadata) 
        
        elif password_mode == 'evoke_only' and password:
            print(f"INFO: Guardando CRS con candado de Evocación (Modo: {password_mode})")
            salt = os.urandom(16)
            key_hash = derive_key(password, salt)
            final_data_to_save = crs_data.copy()
            final_data_to_save.update(public_metadata)
            final_data_to_save['is_encrypted'] = False
            final_data_to_save['evoke_salt'] = salt
            final_data_to_save['evoke_key_hash'] = key_hash

        else:
            print(f"INFO: Guardando CRS sin encriptar (Modo: {password_mode})")
            final_data_to_save = crs_data.copy()
            final_data_to_save.update(public_metadata)
            final_data_to_save['is_encrypted'] = False
        
        try:
            with open(crs_path, "wb") as f:
                f.write(pickle.dumps(final_data_to_save))
        except Exception as e:
            print(f"Error Crítico: No se pudo escribir el archivo CRS. Error: {e}")
            sys.exit(1)

        total_size = os.path.getsize(crs_path) / 1024
        end_time = time.time()
        print(f"-> Archivo CRS (Léxico-Paeth) generado: {crs_path} ({total_size:.2f} KB)")
        print(f"   Metadatos: IP={user_ip}, Loc={user_location}, QDNA=NANO 1.0")
        report_progress(100)
        
    except Exception as e:
        sys.exit(f"FATAL: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Encoder v51.7 - Bit a Bit")
    parser.add_argument("input_file", type=Path)
    parser.add_argument("output_name", type=str)
    parser.add_argument("--crs_dir", type=Path, required=True)
    parser.add_argument("--models_dir", type=Path, required=True)
    parser.add_argument("--password", type=str, default=None)
    parser.add_argument("--author", type=str, default=None)
    parser.add_argument("--tracker_path", type=Path, default=None)
    parser.add_argument("--password_mode", type=str, default="none")
    
    # Nuevos Argumentos
    parser.add_argument("--user_ip", type=str, default="Unknown")
    parser.add_argument("--user_location", type=str, default="Unknown")

    args = parser.parse_args()
    create_lexicon_paeth_crs(
        args.input_file, args.output_name, args.crs_dir, args.models_dir, 
        args.password, args.author, args.tracker_path, args.password_mode,
        args.user_ip, args.user_location
    )