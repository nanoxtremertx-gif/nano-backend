# encoderc.py (v51.3 - Léxico-Paeth Definitivo, Encriptación y Autoría)
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
import json # <--- AGREGADO: Necesario para leer usage_tracker.json

TILE_SIZE = 128

# --- FUNCIONES DE ENCRIPTACIÓN (Sin cambios) ---
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

# --- NUEVA FUNCIÓN PARA LECTURA SEGURA (No rompe la API) ---
def get_tracker_author(tracker_path: Path) -> str | None:
    """Lee el campo 'author' de usage_tracker.json de forma segura."""
    if not tracker_path or not tracker_path.is_file():
        return None
    try:
        with open(tracker_path, 'r') as f:
            tracker_data = json.load(f)
            return str(tracker_data.get('author', None)).strip()
    except Exception:
        # Silenciamos cualquier error de JSON o lectura para evitar que la API se rompa
        return None

# --- FUNCIÓN PRINCIPAL DE CREACIÓN DEL CRS (Modificada) ---
def create_lexicon_paeth_crs(image_path: Path, output_base_name: str, crs_dir: Path, models_dir: Path, password: str = None, author: str = None, tracker_path: Path = None):
    start_time = time.time()
    report_progress(0)
    print(f"--- XtremeRTX Encoder v51.3 (Léxico-Paeth y Autoría) ---")
    
    # 1. OBTENER EL CÓDIGO DE AUTOR PARA LOS LENTES
    # Se prioriza el ID de la API del tracker. Si falla, se usa el argumento --author.
    tracker_author_code = get_tracker_author(tracker_path)
    public_author_value = tracker_author_code if tracker_author_code else (author if author else 'NANO-XtremeRTX')
    
    if tracker_author_code:
        print(f"INFO: Código de autor de la API (Lentes) obtenido del Tracker: {tracker_author_code}")
    elif author:
        print(f"INFO: Usando argumento --author para los Lentes (Tracker no encontrado/fallido).")
    else:
        print(f"WARN: No se proporcionó Tracker ni --author. Usando valor por defecto para Lentes.")
        
    # --- (El resto de la lógica de codificación se mantiene sin cambios) ---
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

        # El crs_data es el diccionario que va encriptado/sellado (Autor interno)
        crs_data = {
            "version": "51.3_LexiconPaeth",
            "payload_list": compressed_tiles,
            "original_shape": original_array.shape,
            "tile_size": TILE_SIZE,
            "original_format": original_pil.format
        }

        if author:
            # La autoría sensible (argumento --author) se añade DENTRO del bloque encriptado
            crs_data['author'] = author
            print(f"- Marca de autoría añadida (Interna/Sensible): {author}")
            
        # --- LENTES: METADATOS PÚBLICOS (El ID derivado o Fallback) ---
        public_metadata = {
            'public_author': public_author_value, 
            'version_id': crs_data.get('version', 'Legacy') 
        }
        # -----------------------------------------------------------
        
        os.makedirs(crs_dir, exist_ok=True)
        crs_path = crs_dir / f"{output_base_name}.crs"

        if password:
            # --- CASO ENCRIPTADO: Modificar el diccionario EXTERNO ---
            print("INFO: Se detectó contraseña. Encriptando archivo CRS...")
            encrypted_block_binary = encrypt_data(crs_data, password)
            outer_crs_data = pickle.loads(encrypted_block_binary) 
            outer_crs_data.update(public_metadata) 
            final_data_to_write = pickle.dumps(outer_crs_data)
        else:
            # --- CASO NO ENCRIPTADO: Modificar el diccionario INTERNO ---
            print("INFO: No se proporcionó contraseña. Guardando sin encriptar.")
            crs_data.update(public_metadata)
            final_data_to_write = pickle.dumps(crs_data)
        
        try:
            with open(crs_path, "wb") as f:
                f.write(final_data_to_write)
        except Exception as e:
            print(f"Error Crítico: No se pudo escribir el archivo CRS. Error: {e}")
            sys.exit(1)

        total_size = os.path.getsize(crs_path) / 1024
        end_time = time.time()
        print(f"-> Archivo CRS (Léxico-Paeth) generado: {crs_path} ({total_size:.2f} KB)")
        print(f"   - Tiempo total del proceso: {end_time - start_time:.2f} segundos.")
        report_progress(100)
        
    except Exception as e:
        sys.exit(f"FATAL: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Encoder v51.3")
    parser.add_argument("input_file", type=Path)
    parser.add_argument("output_name", type=str)
    parser.add_argument("--crs_dir", type=Path, required=True)
    parser.add_argument("--models_dir", type=Path, required=True)
    parser.add_argument("--password", type=str, default=None)
    parser.add_argument("--author", type=str, default=None)
    parser.add_argument("--tracker_path", type=Path, default=None, help="Ruta opcional al usage_tracker.json para obtener el author ID de la API (para los Lentes).") # <-- ARGUMENTO OPCIONAL

    args = parser.parse_args()
    create_lexicon_paeth_crs(args.input_file, args.output_name, args.crs_dir, args.models_dir, args.password, args.author, args.tracker_path)