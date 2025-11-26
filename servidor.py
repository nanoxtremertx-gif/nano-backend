# --- servidor.py --- (v22.2 - FIX CRASH TKINTER)
from flask import Flask, jsonify, request, send_from_directory
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
import datetime
from datetime import timedelta
import uuid
import os
import pickle
import json 
from urllib.parse import urlparse, urlunparse
from sqlalchemy import text

# --- 1. IMPORTAR MODELOS Y DB ---
from models import db, User, UserFile, HistoricalLog, IncidentReport, UpdateFile, DocGestion

# --- 2. INICIALIZAR EXTENSIONES ---
cors = CORS()
bcrypt = Bcrypt()
socketio = SocketIO()

# --- 3. Memoria RAM (Global) ---
ONLINE_USERS = {}
ADMIN_SECRET_KEY = "NANO_MASTER_KEY_2025"
db_status = "Desconocido"

# --- 4. DEFINIR LA FÁBRICA DE LA APLICACIÓN ---
def create_app():
    global db_status
    
    app = Flask(__name__)
    print(">>> INICIANDO SERVIDOR MAESTRO (v22.2 - Headless Fix) <<<")

    # --- 5. CONFIGURACIÓN DE APP ---
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        "pool_pre_ping": True,
        "pool_recycle": 300,
        "pool_timeout": 30,
        "pool_size": 10,
        "max_overflow": 20
    }

    try:
        # Intenta leer variable de entorno (Hugging Face)
        raw_url = os.environ.get('NEON_URL')
        
        # SI LA NUBE FALLA, DESCOMENTA LA LINEA DE ABAJO Y PEGA TU URL DE NEON AHI:
        # raw_url = "postgres://TU_USUARIO:PASSWORD@ENDPOINT.aws.neon.tech/neondb?sslmode=require"

        if not raw_url:
            raise ValueError("NEON_URL no encontrada.")
        
        parsed = urlparse(raw_url)
        scheme = 'postgresql' if parsed.scheme == 'postgres' else parsed.scheme
        clean_url = urlunparse((scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, parsed.fragment)).strip("'").strip()
        
        if 'postgresql' in clean_url and 'sslmode' not in clean_url:
            clean_url += "?sslmode=require"
        
        app.config['SQLALCHEMY_DATABASE_URI'] = clean_url
        db_status = "Neon PostgreSQL (REAL)"
        print(f"Base de datos configurada: {db_status}")

    except Exception as e:
        print(f"!!! ERROR CRÍTICO DB: {e}")
        app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///fallback.db"
        db_status = "SQLite (FALLBACK)"

    # --- 6. INICIALIZACIÓN ---
    cors.init_app(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)
    socketio.init_app(app, cors_allowed_origins="*")
    bcrypt.init_app(app)
    db.init_app(app) 

    # --- 7. DIRECTORIOS ---
    BASE_DIR = os.getcwd()
    FOLDERS = ['uploads', 'uploads/avatars', 'logs_historical', 'updates', 'logs_incidents', 'documentos_gestion', 'biblioteca_publica']
    
    for f in FOLDERS:
        os.makedirs(os.path.join(BASE_DIR, f), exist_ok=True)

    DOCS_FOLDER = os.path.join(BASE_DIR, 'documentos_gestion')
    for sub in ['desarrollo', 'gestion', 'operaciones']:
        os.makedirs(os.path.join(DOCS_FOLDER, sub), exist_ok=True)

    # --- HELPERS ---
    def get_file_url(filename, folder_route='uploads'):
        if not filename: return None
        return f"{request.host_url}{folder_route}/{filename}"

    def format_file_size(size_bytes):
        if size_bytes is None: return "N/A" 
        if size_bytes < 1024: return f"{size_bytes} Bytes"
        elif size_bytes < 1048576: return f"{size_bytes / 1024:.1f} KB"
        else: return f"{size_bytes / 1048576:.2f} MB"

    # --- RUTAS DE SALUD ---
    @app.route('/')
    @app.route('/health')
    def health_check(): 
        return jsonify({"status": "ONLINE", "db": db_status}), 200

    # --- RUTAS DE ARCHIVOS (DESCARGAS) ---
    @app.route('/uploads/<path:filename>')
    def dl_file(filename): return send_from_directory(os.path.join(BASE_DIR, 'uploads'), filename)
    
    @app.route('/uploads/avatars/<path:filename>')
    def dl_avatar(filename): return send_from_directory(os.path.join(BASE_DIR, 'uploads/avatars'), filename)
    
    @app.route('/updates/<path:filename>')
    def dl_update(filename): return send_from_directory(os.path.join(BASE_DIR, 'updates'), filename)

    # --- SOCKETS ---
    @socketio.on('connect')
    def handle_connect():
        emit('update_online_count', {'count': len(ONLINE_USERS)})

    # --- AUTH ---
    @app.route('/api/register', methods=['POST'])
    def register():
        d = request.get_json()
        if User.query.filter_by(username=d.get('username')).first(): return jsonify({"message": "Usuario ocupado"}), 409
        
        new_user = User(
            username=d.get('username'), 
            hash=bcrypt.generate_password_hash(d.get('password')).decode('utf-8'), 
            email=d.get('email'), 
            identificador=d.get('identificador'), 
            role="gratis", 
            fingerprint=d.get('username').lower(),
            avatar="/user.ico"
        )
        try:
            db.session.add(new_user); db.session.commit()
            # Crear carpeta raíz
            nf = UserFile(owner_username=d['username'], name="Archivos de Usuario", type='folder', parent_id=None, size_bytes=0)
            db.session.add(nf); db.session.commit()
            return jsonify({"message": "Registrado"}), 201
        except Exception as e: 
            db.session.rollback()
            return jsonify({"message": str(e)}), 500

    @app.route('/api/login', methods=['POST'])
    def login():
        d = request.get_json()
        u = User.query.filter_by(username=d.get('username')).first()
        if u and bcrypt.check_password_hash(u.hash, d.get('password')):
            ONLINE_USERS[u.username] = datetime.datetime.utcnow()
            return jsonify({
                "message": "OK", 
                "user": {
                    "username": u.username, "email": u.email, "role": u.role, "identificador": u.identificador,
                    "avatar": getattr(u, 'avatar', '/user.ico')
                }
            }), 200
        return jsonify({"message": "Credenciales inválidas"}), 401

    @app.route('/api/heartbeat', methods=['POST'])
    def heartbeat():
        d = request.get_json(); u = d.get('username')
        if u: ONLINE_USERS[u] = datetime.datetime.utcnow(); return jsonify({"status": "alive"}), 200
        return jsonify({"msg": "No user"}), 400

    # --- UPDATES ---
    @app.route('/api/updates/check', methods=['GET'])
    def chk_updates():
        latest = UpdateFile.query.order_by(UpdateFile.date.desc()).first()
        if not latest: return jsonify({"message":"No updates"}), 404
        return jsonify({"version": latest.version, "download_url": get_file_url(latest.storage_path, 'updates')}), 200

    @app.route('/api/updates/upload', methods=['POST'])
    def upload_update():
        if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg": "Acceso denegado"}), 403
        f = request.files['file'] if 'file' in request.files else None
        if not f: 
            # Fallback para subida cruda (como lo hace el script de actualizacion)
            filename = secure_filename(request.headers.get('X-Vercel-Filename', 'update.bin'))
            save_path = os.path.join(BASE_DIR, 'updates', filename)
            with open(save_path, 'wb') as file: file.write(request.data)
        else:
            filename = secure_filename(f.filename)
            save_path = os.path.join(BASE_DIR, 'updates', filename)
            f.save(save_path)

        existing = UpdateFile.query.filter_by(filename=filename).first()
        if existing: db.session.delete(existing)
        
        new_upd = UpdateFile(filename=filename, version="1.0", size=os.path.getsize(save_path), storage_path=filename)
        db.session.add(new_upd); db.session.commit()
        return jsonify({"message": "Subido"}), 201

    # --- LOGS & INCIDENTES ---
    @app.route('/api/logs/historical', methods=['POST'])
    def upload_log():
        u = request.headers.get('X-Username', 'Anon')
        log_name = f"LOG_{u}_{uuid.uuid4().hex[:6]}.txt"
        path = os.path.join(BASE_DIR, 'logs_historical', log_name)
        with open(path, 'wb') as f: f.write(request.data)
        
        db_log = HistoricalLog(user=u, ip=request.headers.get('X-IP'), quality="Auto", filename=log_name, storage_path=log_name, date=datetime.datetime.utcnow())
        db.session.add(db_log); db.session.commit()
        return jsonify({"status": "OK"}), 201

    @app.route('/api/logs/incident', methods=['POST'])
    def upload_incident():
        u = request.form.get('X-Username', 'Anon')
        msg = request.form.get('message', '')
        file = request.files.get('log_file')
        filename = "N/A"
        
        if file:
            filename = secure_filename(file.filename)
            unique = f"INC_{u}_{uuid.uuid4().hex[:6]}_{filename}"
            file.save(os.path.join(BASE_DIR, 'logs_incidents', unique))
            filename = unique

        inc = IncidentReport(user=u, ip=request.form.get('X-IP'), message=msg, filename=filename, storage_path=filename, date=datetime.datetime.utcnow())
        db.session.add(inc); db.session.commit()
        return jsonify({"status": "OK"}), 201

    # --- WORKER S4 (Desbloqueo) ---
    @app.route('/api/worker/check-permission', methods=['POST'])
    def worker_perm():
        return jsonify({"allow": True}), 200

    @app.route('/api/admin/create_tables', methods=['GET'])
    def init_db():
        if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg": "Denegado"}), 403
        try: 
            with app.app_context(): db.create_all()
            return jsonify({"msg": "Tablas creadas"}), 200
        except Exception as e: return jsonify({"error": str(e)}), 500

    return app

if __name__ == '__main__': 
    app = create_app()
    socketio.run(app, host='0.0.0.0', port=7860)
