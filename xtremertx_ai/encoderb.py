# encoderb.py (v20.4 - Lógica de Clave Corregida)
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
from datetime import datetime # <-- MODIFICACIÓN

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

# --- CONSTANTES ---
IMG_SIZE = 128
GENERALISTA_NAME = 'generalista_hd_best.keras'
WEBP_QUALITY = 95

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

def create_generalista_crs(image_path: Path, output_base_name: str, crs_dir: Path, models_dir: Path, password: str = None, author: str = None, tracker_path: Path = None, password_mode: str = 'none'):
    report_progress(0)
    print(f"--- XtremeRTX Encoder v20.4 (Lógica de Clave Corregida) ---")
    
    # 1. OBTENER EL CÓDIGO DE AUTOR PARA LOS LENTES (Lógica de Lentes Seguros)
    tracker_author_code = get_tracker_author(tracker_path)
    public_author_value = tracker_author_code if tracker_author_code else (author if author else 'NANO-XtremeRTX')
    
    if tracker_author_code:
        print(f"INFO: Código de autor de la API (Lentes) obtenido del Tracker: {tracker_author_code}")
    elif author:
        print(f"INFO: Usando argumento --author para los Lentes (Tracker no encontrado/fallido).")
    else:
        print(f"WARN: No se proporcionó Tracker ni --author. Usando valor por defecto para Lentes.")

    # Resto de la lógica del encoder (sin cambios)
    try:
        print(f"INFO: Cargando modelo desde: {models_dir}")
        generalist_ae = tf.keras.models.load_model(str(models_dir / GENERALISTA_NAME), compile=False)
        
        encoder_g = tf.keras.models.Model(inputs=generalist_ae.input, outputs=generalist_ae.get_layer('max_pooling2d_2').output)
        encoder_output_shape = generalist_ae.get_layer('max_pooling2d_2').output.shape[1:]
        decoder_input = tf.keras.Input(shape=encoder_output_shape)
        x = generalist_ae.layers[7](decoder_input)
        for i in range(8, len(generalist_ae.layers)): x = generalist_ae.layers[i](x)
        decoder_g = tf.keras.models.Model(decoder_input, x)
        
        report_progress(10)
    except Exception as e:
        print(f"FATAL: Error cargando el modelo Generalista: {e}. Verifica que la ruta '{models_dir}' es correcta.")
        sys.exit(1)

    original_pil = Image.open(image_path).convert('RGB')
    original_w, original_h = original_pil.size
    original_array = np.array(original_pil)
    report_progress(20)
    
    img_resized = original_pil.resize((IMG_SIZE, IMG_SIZE), Image.Resampling.LANCZOS)
    img_array_norm = (np.array(img_resized).astype('float32') / 255.0)
    img_batch = np.expand_dims(img_array_norm, axis=0)
    
    print("- Extrayendo semilla estructural con Generalista...")
    structural_seed = encoder_g.predict(img_batch, verbose=0)
    report_progress(50)

    base_evoked_norm = decoder_g.predict(structural_seed, verbose=0).squeeze()
    print("- Calculando mapa de residuos...")
    base_evoked_pil = Image.fromarray((base_evoked_norm * 255).astype(np.uint8))
    base_evoked_resized = base_evoked_pil.resize((original_w, original_h), Image.Resampling.LANCZOS)
    base_evoked_array = np.array(base_evoked_resized)
    residual_map = original_array.astype(np.int16) - base_evoked_array.astype(np.int16)
    report_progress(75)

    print(f"- Comprimiendo semilla de fidelidad (WebP Calidad: {WEBP_QUALITY})...")
    residual_img_array = np.clip(residual_map + 128, 0, 255).astype(np.uint8)
    residual_pil = Image.fromarray(residual_img_array)
    buffer = io.BytesIO()
    residual_pil.save(buffer, format='WEBP', quality=WEBP_QUALITY)
    fidelity_seed = buffer.getvalue()
    report_progress(90)
    
    # crs_data es el diccionario que va encriptado/sellado
    crs_data = {
        "version": "20.2_GeneralistaPerceptual",
        "core_seed": structural_seed,
        "fidelity_seed": fidelity_seed,
        "true_original_shape": (original_w, original_h),
        "original_format": original_pil.format
    }

    if author:
        # La autoría sensible se añade DENTRO del bloque encriptado
        crs_data['author'] = author
        print(f"- Marca de autoría añadida (Interna/Sensible): {author}")
    
    # --- LENTES: METADATOS PÚBLICOS (El ID derivado o Fallback) ---
    creation_timestamp = datetime.now().isoformat() # <-- MODIFICACIÓN

    public_metadata = {
        'public_author': public_author_value, 
        'version_id': crs_data.get('version', 'Legacy'),
        'password_mode': password_mode,
        'created_at': creation_timestamp # <-- MODIFICACIÓN
    }
    # -----------------------------------------------------------
    
    os.makedirs(crs_dir, exist_ok=True)
    crs_path = crs_dir / f"{output_base_name}.crs"
    final_data_to_save = {}

    # --- MODIFICACIÓN: LÓGICA DE GUARDADO CORREGIDA ---
    if password_mode == 'full' and password:
        # MODO "Evocar y Leer": Encriptar todo.
        print(f"INFO: Encriptando CRS (Modo: {password_mode})")
        encrypted_block_binary = encrypt_data(crs_data, password)
        final_data_to_save = pickle.loads(encrypted_block_binary) 
        final_data_to_save.update(public_metadata) 
    
    elif password_mode == 'evoke_only' and password:
        # MODO "Solo Evocar": NO encriptar. Guardar hash de la clave.
        print(f"INFO: Guardando CRS con candado de Evocación (Modo: {password_mode})")
        salt = os.urandom(16)
        key_hash = derive_key(password, salt)
        
        final_data_to_save = crs_data.copy()
        final_data_to_save.update(public_metadata)
        final_data_to_save['is_encrypted'] = False
        final_data_to_save['evoke_salt'] = salt
        final_data_to_save['evoke_key_hash'] = key_hash

    else:
        # MODO "Sin clave"
        print(f"INFO: Guardando CRS sin encriptar (Modo: {password_mode})")
        final_data_to_save = crs_data.copy()
        final_data_to_save.update(public_metadata)
        final_data_to_save['is_encrypted'] = False
    # --- FIN DE MODIFICACIÓN ---

    try:
        with open(crs_path, "wb") as f:
            f.write(pickle.dumps(final_data_to_save))
        total_size = os.path.getsize(crs_path) / 1024
        print(f"-> Archivo CRS (Generalista) generado: {crs_path} ({total_size:.2f} KB)")
    except Exception as e:
        print(f"Error Crítico: No se pudo escribir el archivo CRS. Error: {e}")
        sys.exit(1)

    report_progress(100)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Encoder v20.4")
    parser.add_argument("input_file", type=Path)
    parser.add_argument("output_name", type=str)
    parser.add_argument("--crs_dir", type=Path, required=True)
    parser.add_argument("--models_dir", type=Path, required=True)
    parser.add_argument("--password", type=str, default=None)
    parser.add_argument("--author", type=str, default=None)
    parser.add_argument("--tracker_path", type=Path, default=None, help="Ruta opcional al usage_tracker.json para obtener el author ID de la API (para los Lentes).")
    parser.add_argument("--password_mode", type=str, default="none", help="Modo de protección de contraseña ('full', 'evoke_only', 'none')")
    args = parser.parse_args()
    create_generalista_crs(args.input_file, args.output_name, args.crs_dir, args.models_dir, args.password, args.author, args.tracker_path, args.password_mode)
