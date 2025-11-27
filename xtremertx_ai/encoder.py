# encoder.py (v13.1 - Perceptual / Corrected Authorship)
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

IMG_SIZE = 128
ATOMIZER_NAME = 'kiphu_atomizer.keras'
GENESIS_NAME = 'kiphu_genesis_engine.keras'
ODIN_NAME = 'odin_corrector.keras'

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
    except: return None

def create_genesis_crs(image_path, output_base_name, crs_dir, models_dir, password=None, author=None, fidelity_quality=0, tracker_path=None, password_mode='none', user_ip="Unknown", user_location="Unknown"):
    report_progress(0)
    print(f"--- XtremeRTX Encoder v13.1 (Q-DNA NANO / Ext User) ---")

    # 1. Autoría Externa (Lentes) = USUARIO
    tracker_author_code = get_tracker_author(tracker_path)
    public_author_value = tracker_author_code if tracker_author_code else (author if author else 'NANO-XtremeRTX')
    
    # 2. Carga Modelos
    try:
        atomizer = tf.keras.models.load_model(str(models_dir / ATOMIZER_NAME), compile=False)
        genesis = tf.keras.models.load_model(str(models_dir / GENESIS_NAME), compile=False)
        odin = tf.keras.models.load_model(str(models_dir / ODIN_NAME), compile=False)
        report_progress(10)
    except Exception as e: sys.exit(f"FATAL: {e}")

    # 3. Procesamiento
    original_pil = Image.open(image_path).convert('RGB')
    original_w, original_h = original_pil.size
    img_resized_pil = original_pil.resize((IMG_SIZE, IMG_SIZE), Image.Resampling.LANCZOS)
    img_batch = np.expand_dims(np.array(img_resized_pil, dtype='float32') / 255.0, axis=0)
    core_seed = atomizer.predict(img_batch, verbose=0)
    report_progress(30)

    base_evoked_norm_small = genesis.predict(core_seed, verbose=0)
    base_perfected_small = odin.predict(base_evoked_norm_small, verbose=0).squeeze()
    report_progress(60)

    base_perfected_pil = Image.fromarray((np.clip(base_perfected_small, 0, 1) * 255).astype(np.uint8))
    base_perfected_large = base_perfected_pil.resize((original_w, original_h), Image.Resampling.LANCZOS)
    residual_map = np.array(original_pil).astype(np.int16) - np.array(base_perfected_large).astype(np.int16)
    report_progress(75)

    residual_for_image = (residual_map.astype(np.float32) / 2.0) + 128.0
    residual_img_array = np.clip(residual_for_image, 0, 255).astype(np.uint8)
    residual_pil = Image.fromarray(residual_img_array)
    buffer = io.BytesIO()
    residual_pil.save(buffer, format='WEBP', quality=fidelity_quality)
    fidelity_seed = buffer.getvalue()
    report_progress(90)

    # 4. Datos Internos (Autoría Interna = NANO)
    crs_data = {
        "version": "13.1_Perceptual",
        "core_seed": core_seed,
        "fidelity_seed": fidelity_seed,
        "true_original_shape": (original_w, original_h),
        "original_format": original_pil.format,
        "fidelity_quality": fidelity_quality,
        "author": "NANO XTREMERTX 1.0" # <-- INTERNA FIJA
    }

    # 5. Metadatos Públicos (Autoría Externa = Usuario)
    public_metadata = { 
        'public_author': public_author_value, # <-- USUARIO LOGUEADO
        'version_id': "13.1_Perceptual",
        'password_mode': password_mode,
        'created_at': datetime.now().isoformat(),
        'creation_ip': user_ip,
        'creation_location': user_location,
        'qdna': "NANO XTREMERTX 1.0" # <-- Q-DNA FIJO
    }
    
    crs_path = crs_dir / f"{output_base_name}.crs"
    final_data_to_save = {}

    if password_mode == 'full' and password:
        encrypted_block = encrypt_data(crs_data, password)
        final_data_to_save = pickle.loads(encrypted_block)
        final_data_to_save.update(public_metadata)
    elif password_mode == 'evoke_only' and password:
        salt = os.urandom(16)
        final_data_to_save = crs_data.copy()
        final_data_to_save.update(public_metadata)
        final_data_to_save['is_encrypted'] = False
        final_data_to_save['evoke_salt'] = salt
        final_data_to_save['evoke_key_hash'] = derive_key(password, salt)
    else:
        final_data_to_save = crs_data.copy()
        final_data_to_save.update(public_metadata)
        final_data_to_save['is_encrypted'] = False

    with open(crs_path, "wb") as f:
        f.write(pickle.dumps(final_data_to_save))
    report_progress(100)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input_file", type=Path)
    parser.add_argument("output_name", type=str)
    parser.add_argument("--crs_dir", type=Path, required=True)
    parser.add_argument("--models_dir", type=Path, required=True)
    parser.add_argument("--password", type=str, default=None)
    parser.add_argument("--author", type=str, default=None)
    parser.add_argument("--fidelity_quality", type=int, default=0) # Default 0%
    parser.add_argument("--tracker_path", type=Path, default=None)
    parser.add_argument("--password_mode", type=str, default="none")
    parser.add_argument("--user_ip", type=str, default="Unknown")
    parser.add_argument("--user_location", type=str, default="Unknown")
    args = parser.parse_args()
    create_genesis_crs(args.input_file, args.output_name, args.crs_dir, args.models_dir, args.password, args.author, args.fidelity_quality, args.tracker_path, args.password_mode, args.user_ip, args.user_location)