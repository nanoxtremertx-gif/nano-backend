# encoder.py (v13.0 - Perceptual + Metadatos de Usuario Integrados)
import os
import pickle
import numpy as np
import tensorflow as tf
from PIL import Image
from pathlib import Path
import sys
import argparse
import io
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import json
from datetime import datetime

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

# --- CONSTANTES ---
IMG_SIZE = 128
ATOMIZER_NAME = 'kiphu_atomizer.keras'
GENESIS_NAME = 'kiphu_genesis_engine.keras'
ODIN_NAME = 'odin_corrector.keras'

# --- FUNCIONES DE ENCRIPTACIÓN ---
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_data(data_to_pickle: dict, password: str) -> bytes:
    salt = os.urandom(16)
    key = derive_key(password, salt)
    fernet = Fernet(key)
    pickled_data = pickle.dumps(data_to_pickle)
    encrypted_data = fernet.encrypt(pickled_data)
    final_crs_data = {'is_encrypted': True, 'salt': salt, 'encrypted_data': encrypted_data}
    return pickle.dumps(final_crs_data)

def report_progress(percentage):
    print(f"PROGRESS:{percentage}")
    sys.stdout.flush()

def get_tracker_author(tracker_path: Path) -> str | None:
    if not tracker_path or not tracker_path.is_file(): return None
    try:
        with open(tracker_path, 'r') as f: return str(json.load(f).get('author', None)).strip()
    except Exception: return None

# --- FUNCIÓN PRINCIPAL ---
def create_genesis_crs(
    image_path: Path, 
    output_base_name: str, 
    crs_dir: Path, 
    models_dir: Path, 
    password: str = None, 
    author: str = None, 
    fidelity_quality: int = 0, # Por defecto 0 (Máxima compresión Perceptual)
    tracker_path: Path = None, 
    password_mode: str = 'none',
    user_ip: str = "Unknown",       # <--- NUEVO
    user_location: str = "Unknown"  # <--- NUEVO
):
    report_progress(0)
    print(f"--- XtremeRTX Encoder v13.0 (Perceptual + User Metadata) ---")

    # 1. AUTORÍA
    tracker_author_code = get_tracker_author(tracker_path)
    public_author_value = tracker_author_code if tracker_author_code else (author if author else 'NANO-XtremeRTX')
    
    # 2. CARGA DE MODELOS
    try:
        atomizer = tf.keras.models.load_model(str(models_dir / ATOMIZER_NAME), compile=False)
        genesis = tf.keras.models.load_model(str(models_dir / GENESIS_NAME), compile=False)
        odin = tf.keras.models.load_model(str(models_dir / ODIN_NAME), compile=False)
        report_progress(10)
    except Exception as e:
        sys.exit(f"FATAL: Error cargando los modelos: {e}.")

    # 3. PROCESAMIENTO IA (Atomizer -> Genesis -> Odin)
    original_pil = Image.open(image_path).convert('RGB')
    original_w, original_h = original_pil.size
    img_resized_pil = original_pil.resize((IMG_SIZE, IMG_SIZE), Image.Resampling.LANCZOS)
    img_batch = np.expand_dims(np.array(img_resized_pil, dtype='float32') / 255.0, axis=0)
    
    core_seed = atomizer.predict(img_batch, verbose=0)
    report_progress(30)

    base_evoked_norm_small = genesis.predict(core_seed, verbose=0)
    base_perfected_small = odin.predict(base_evoked_norm_small, verbose=0).squeeze()
    report_progress(60)

    # 4. RESIDUALES
    base_perfected_pil = Image.fromarray((np.clip(base_perfected_small, 0, 1) * 255).astype(np.uint8))
    base_perfected_large = base_perfected_pil.resize((original_w, original_h), Image.Resampling.LANCZOS)
    original_array = np.array(original_pil)
    base_perfected_array = np.array(base_perfected_large)
    residual_map = original_array.astype(np.int16) - base_perfected_array.astype(np.int16)
    report_progress(75)

    # 5. COMPRESIÓN DE FIDELIDAD (WebP)
    # Soporta modos 0, 50, 100 según el argumento fidelity_quality passed
    residual_for_image = (residual_map.astype(np.float32) / 2.0) + 128.0
    residual_img_array = np.clip(residual_for_image, 0, 255).astype(np.uint8)
    residual_pil = Image.fromarray(residual_img_array)
    buffer = io.BytesIO()
    residual_pil.save(buffer, format='WEBP', quality=fidelity_quality)
    fidelity_seed = buffer.getvalue()
    report_progress(90)

    # 6. EMPAQUETADO FINAL CON METADATOS EXTENDIDOS
    crs_data = {
        "version": "13.0_PerceptualFinal",
        "core_seed": core_seed,
        "fidelity_seed": fidelity_seed,
        "true_original_shape": (original_w, original_h),
        "original_format": original_pil.format,
        "fidelity_quality": fidelity_quality,
        "author": author # Autoría interna sensible
    }

    # Metadatos Públicos (Leíbles sin evocar)
    creation_timestamp = datetime.now().isoformat()

    public_metadata = { 
        'public_author': public_author_value, 
        'version_id': "13.0_PerceptualFinal",
        'password_mode': password_mode,
        'created_at': creation_timestamp,
        'creation_ip': user_ip,             # <--- IP DEL SOLICITANTE
        'creation_location': user_location, # <--- UBICACIÓN
        'qdna': "NANO XTREMERTX 1.0"        # <--- FIRMA Q-DNA
    }
    
    crs_path = crs_dir / f"{output_base_name}.crs"
    final_data_to_save = {}

    # Lógica de Guardado
    if password_mode == 'full' and password:
        print(f"INFO: Encriptando CRS (Modo: {password_mode})")
        encrypted_block = encrypt_data(crs_data, password)
        final_data_to_save = pickle.loads(encrypted_block)
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

    with open(crs_path, "wb") as f:
        f.write(pickle.dumps(final_data_to_save))
        
    total_size = os.path.getsize(crs_path) / 1024
    print(f"-> Archivo CRS Generado: {crs_path} ({total_size:.2f} KB)")
    print(f"   Metadatos: IP={user_ip}, Loc={user_location}, QDNA=NANO 1.0")
    report_progress(100)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Encoder v13.0 - Perceptual")
    parser.add_argument("input_file", type=Path)
    parser.add_argument("output_name", type=str)
    parser.add_argument("--crs_dir", type=Path, required=True)
    parser.add_argument("--models_dir", type=Path, required=True)
    parser.add_argument("--password", type=str, default=None)
    parser.add_argument("--author", type=str, default=None)
    
    # Por defecto 0 (Máxima compresión)
    parser.add_argument("--fidelity_quality", type=int, default=0) 
    
    parser.add_argument("--tracker_path", type=Path, default=None)
    parser.add_argument("--password_mode", type=str, default="none")
    
    # Nuevos Argumentos para Metadatos de Usuario
    parser.add_argument("--user_ip", type=str, default="Unknown")
    parser.add_argument("--user_location", type=str, default="Unknown")

    args = parser.parse_args()
    
    create_genesis_crs(
        args.input_file, args.output_name, args.crs_dir, args.models_dir, 
        args.password, args.author, args.fidelity_quality, args.tracker_path, args.password_mode,
        args.user_ip, args.user_location
    )