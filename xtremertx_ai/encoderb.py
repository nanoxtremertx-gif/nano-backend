# encoderb.py (v20.6 - UltraV / Corrected Authorship)
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
GENERALISTA_NAME = 'generalista_hd_best.keras'
WEBP_QUALITY = 95

def derive_key(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_data(data, password):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    return pickle.dumps({'is_encrypted': True, 'salt': salt, 'encrypted_data': Fernet(key).encrypt(pickle.dumps(data))})

def report_progress(p):
    print(f"PROGRESS:{p}")
    sys.stdout.flush()

def get_tracker_author(path):
    if not path or not path.is_file(): return None
    try:
        with open(path, 'r') as f: return str(json.load(f).get('author', None)).strip()
    except: return None

def create_generalista_crs(image_path, output_base_name, crs_dir, models_dir, password=None, author=None, tracker_path=None, password_mode='none', user_ip="Unknown", user_location="Unknown"):
    report_progress(0)
    print(f"--- XtremeRTX Encoder v20.6 (UltraV / Corrected Authorship) ---")
    
    tracker_author_code = get_tracker_author(tracker_path)
    public_author_value = tracker_author_code if tracker_author_code else (author if author else 'NANO-XtremeRTX')
    
    try:
        generalist_ae = tf.keras.models.load_model(str(models_dir / GENERALISTA_NAME), compile=False)
        encoder_g = tf.keras.models.Model(inputs=generalist_ae.input, outputs=generalist_ae.get_layer('max_pooling2d_2').output)
        out_shape = generalist_ae.get_layer('max_pooling2d_2').output.shape[1:]
        dec_in = tf.keras.Input(shape=out_shape)
        x = generalist_ae.layers[7](dec_in)
        for i in range(8, len(generalist_ae.layers)): x = generalist_ae.layers[i](x)
        decoder_g = tf.keras.models.Model(dec_in, x)
        report_progress(10)
    except Exception as e: sys.exit(1)

    orig_pil = Image.open(image_path).convert('RGB')
    orig_w, orig_h = orig_pil.size
    orig_arr = np.array(orig_pil)
    report_progress(20)
    
    img_resized = orig_pil.resize((IMG_SIZE, IMG_SIZE), Image.Resampling.LANCZOS)
    img_batch = np.expand_dims(np.array(img_resized).astype('float32') / 255.0, axis=0)
    structural_seed = encoder_g.predict(img_batch, verbose=0)
    report_progress(50)

    base_evoked = decoder_g.predict(structural_seed, verbose=0).squeeze()
    base_evoked_pil = Image.fromarray((base_evoked * 255).astype(np.uint8))
    base_evoked_resized = base_evoked_pil.resize((orig_w, orig_h), Image.Resampling.LANCZOS)
    residual_map = orig_arr.astype(np.int16) - np.array(base_evoked_resized).astype(np.int16)
    report_progress(75)

    residual_img = Image.fromarray(np.clip(residual_map + 128, 0, 255).astype(np.uint8))
    buf = io.BytesIO()
    residual_img.save(buf, format='WEBP', quality=WEBP_QUALITY)
    fidelity_seed = buf.getvalue()
    report_progress(90)
    
    crs_data = {
        "version": "20.6_Generalista",
        "core_seed": structural_seed,
        "fidelity_seed": fidelity_seed,
        "true_original_shape": (orig_w, orig_h),
        "original_format": orig_pil.format,
        "author": "NANO XTREMERTX 1.0" # <-- INTERNA FIJA
    }

    public_metadata = {
        'public_author': public_author_value, # <-- USUARIO
        'version_id': "20.6_Generalista",
        'password_mode': password_mode,
        'created_at': datetime.now().isoformat(),
        'creation_ip': user_ip,
        'creation_location': user_location,
        'qdna': "NANO XTREMERTX 1.0" # <-- Q-DNA FIJO
    }
    
    crs_path = crs_dir / f"{output_base_name}.crs"
    final_data_to_save = {}

    if password_mode == 'full' and password:
        final_data_to_save = pickle.loads(encrypt_data(crs_data, password))
        final_data_to_save.update(public_metadata) 
    elif password_mode == 'evoke_only' and password:
        salt = os.urandom(16)
        final_data_to_save = crs_data.copy()
        final_data_to_save.update(public_metadata)
        final_data_to_save.update({'is_encrypted': False, 'evoke_salt': salt, 'evoke_key_hash': derive_key(password, salt)})
    else:
        final_data_to_save = crs_data.copy()
        final_data_to_save.update(public_metadata)
        final_data_to_save['is_encrypted'] = False

    try:
        with open(crs_path, "wb") as f: f.write(pickle.dumps(final_data_to_save))
    except: sys.exit(1)
    report_progress(100)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input_file", type=Path)
    parser.add_argument("output_name", type=str)
    parser.add_argument("--crs_dir", type=Path, required=True)
    parser.add_argument("--models_dir", type=Path, required=True)
    parser.add_argument("--password", type=str, default=None)
    parser.add_argument("--author", type=str, default=None)
    parser.add_argument("--tracker_path", type=Path, default=None)
    parser.add_argument("--password_mode", type=str, default="none")
    parser.add_argument("--user_ip", type=str, default="Unknown")
    parser.add_argument("--user_location", type=str, default="Unknown")
    args = parser.parse_args()
    create_generalista_crs(args.input_file, args.output_name, args.crs_dir, args.models_dir, args.password, args.author, args.tracker_path, args.password_mode, args.user_ip, args.user_location)