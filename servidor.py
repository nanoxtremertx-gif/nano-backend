# --- servidor.py --- (v10.4 - Full Systems + Log Fix + RUT Validation + Size Bytes Fix)
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
import datetime
import uuid
import os
import pickle
from urllib.parse import urlparse, urlunparse

# Soporte Numpy
try:
    import numpy
except ImportError:
    print("!!! WARN: Numpy no detectado.")

app = Flask(__name__)
print(">>> INICIANDO SERVIDOR MAESTRO (v10.4 - Size Fix) <<<")

CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)
bcrypt = Bcrypt(app)
# CLAVE MAESTRA: Si va a cambiarla, DEBE CAMBIARLA también en consola_admin.py
ADMIN_SECRET_KEY = "NANO_MASTER_KEY_2025" 

# --- DIRECTORIOS ---
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- CONEXIÓN DB ---
db_status = "Desconocido"
try:
    raw_url = os.environ.get('NEON_URL')
    if not raw_url:
        app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///fallback.db"
        db_status = "SQLite (TEMPORAL - FALTA NEON_URL)"
    else:
        parsed = urlparse(raw_url)
        scheme = 'postgresql' if parsed.scheme == 'postgres' else parsed.scheme
        clean_url = urlunparse((scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, parsed.fragment)).strip("'").strip()
        if 'postgresql' in clean_url and 'sslmode' not in clean_url:
             clean_url += "?sslmode=require"
        app.config['SQLALCHEMY_DATABASE_URI'] = clean_url
        db_status = "Neon PostgreSQL (REAL)"
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db = SQLAlchemy(app)
except Exception as e:
    print(f"!!! ERROR CRÍTICO DB: {e}")
    db = None

# --- MODELOS ---
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    identificador = db.Column(db.String(120), nullable=False) # RUT
    role = db.Column(db.String(20), default="gratis")
    fingerprint = db.Column(db.String(80), nullable=True)
    subscription_end = db.Column(db.String(50), nullable=True)
    files = db.relationship('UserFile', backref='owner', lazy=True)

class UserFile(db.Model):
    __tablename__ = 'user_file'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    owner_username = db.Column(db.String(80), db.ForeignKey('user.username'), nullable=False)
    parent_id = db.Column(db.String(36), nullable=True)
    name = db.Column(db.String(255), nullable=False)
    type = db.Column(db.String(20), nullable=False)
    size_bytes = db.Column(db.BigInteger, default=0)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    storage_path = db.Column(db.String(500), nullable=True)
    is_published = db.Column(db.Boolean, default=False)
    description = db.Column(db.Text, nullable=True)
    tags = db.Column(db.String(500), nullable=True)
    price = db.Column(db.Float, default=0.0)

# Modelos Legacy
class HistoricalLog(db.Model):
    __tablename__ = 'historical_log'
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(80)); ip = db.Column(db.String(50)); quality = db.Column(db.String(50))
    filename = db.Column(db.String(255)); date = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class IncidentReport(db.Model):
    __tablename__ = 'incident_report'
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(80)); ip = db.Column(db.String(50)); message = db.Column(db.Text)
    filename = db.Column(db.String(255)); date = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class UpdateFile(db.Model):
    __tablename__ = 'update_file'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), unique=True); version = db.Column(db.String(50))
    size = db.Column(db.Integer); date = db.Column(db.DateTime, default=datetime.datetime.utcnow)

with app.app_context():
    if db: db.create_all()

# --- ÚTILES ---
def get_file_url(filename):
    if not filename: return None
    # Esta URL permite descargar el archivo del servidor de Hugging Face
    return f"{request.host_url}uploads/{filename}"

# --- RUTAS ---
@app.route('/')
def health_check(): return jsonify({"status": "v10.4 ONLINE (Size Fix)", "db": db_status}), 200

@app.route('/uploads/<path:filename>')
def download_file(filename): return send_from_directory(UPLOAD_FOLDER, filename)

# --- 1. AUTENTICACIÓN (CREA CARPETA RAÍZ AL REGISTRAR) ---
@app.route('/api/register', methods=['POST'])
def register():
    d = request.get_json()
    if User.query.filter_by(username=d.get('username')).first(): return jsonify({"message": "Usuario ocupado"}), 409
    if User.query.filter_by(email=d.get('email')).first(): return jsonify({"message": "Email ocupado"}), 409
    
    # --- NUEVA VALIDACIÓN DE IDENTIFICADOR/RUT ---
    if User.query.filter_by(identificador=d.get('identificador')).first(): 
        return jsonify({"message": "Este Identificador/RUT ya está registrado"}), 409
    # ---------------------------------------------
    
    new_user = User(
        username=d.get('username'), hash=bcrypt.generate_password_hash(d.get('password')).decode('utf-8'),
        email=d.get('email'), identificador=d.get('identificador'), role="gratis",
        fingerprint=d.get('username').lower()
    )
    
    try:
        db.session.add(new_user)
        
        # --- FIX: CREAR CARPETA RAÍZ POR DEFECTO ---
        root_folder = UserFile(
            owner_username=d.get('username'),
            name="Archivos de Usuario",
            type='folder',
            parent_id=None, # La raíz es NULL
            size_bytes=0
        )
        db.session.add(root_folder)
        # ---------------------------------------------
        
        db.session.commit()
        return jsonify({"message": "Registrado"}), 201
    except Exception as e: 
        db.session.rollback()
        return jsonify({"message": str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    d = request.get_json()
    u = User.query.filter_by(username=d.get('username')).first()
    if u and bcrypt.check_password_hash(u.hash, d.get('password')):
        return jsonify({"message": "OK", "user": {"username": u.username, "email": u.email, "role": u.role, "identificador": u.identificador, "isAdmin": u.role == 'admin'}}), 200
    return jsonify({"message": "Credenciales inválidas"}), 401

# --- 2. ADMIN API (VIP) ---
@app.route('/api/admin/users', methods=['GET'])
def admin_list():
    if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg": "Acceso denegado"}), 403
    try:
        users = User.query.all()
        return jsonify([{
            "username": u.username, "email": u.email, "role": u.role, 
            "identificador": u.identificador, "subscriptionEndDate": u.subscription_end
        } for u in users]), 200
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route('/api/admin/users/<username>', methods=['PUT'])
def admin_update(username):
    if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg": "No"}), 403
    u = User.query.filter_by(username=username).first()
    if not u: return jsonify({"msg": "404"}), 404
    d = request.get_json()
    if 'role' in d: u.role = d['role']
    if 'subscriptionEndDate' in d: u.subscription_end = d['subscriptionEndDate']
    db.session.commit()
    return jsonify({"message": "Actualizado"}), 200

@app.route('/api/admin/users/<username>', methods=['DELETE'])
def admin_delete(username):
    if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg": "No"}), 403
    u = User.query.filter_by(username=username).first()
    if u: db.session.delete(u); db.session.commit()
    return jsonify({"message": "Eliminado"}), 200

# --- 3. ARCHIVOS (CORREGIDO PARA ENVIAR BYTES) ---
@app.route('/api/my-files/<username>', methods=['GET'])
def get_files(username):
    try:
        files = UserFile.query.filter_by(owner_username=username).all()
        return jsonify([
            {
                "id": f.id, 
                "name": f.name, 
                "type": f.type, 
                "parentId": f.parent_id, 
                "size": f"{f.size_bytes/1048576:.2f} MB", 
                "size_bytes": f.size_bytes,  # <--- NUEVO CAMPO IMPORTANTE
                "path": f.storage_path, 
                "isPublished": f.is_published
            } 
            for f in files
        ]), 200
    except: return jsonify([]), 200

@app.route('/api/upload-file', methods=['POST'])
def upload_user_file():
    try:
        if 'file' not in request.files: return jsonify({"message": "Falta archivo"}), 400
        file = request.files['file']; user_id = request.form.get('userId'); parent_id = request.form.get('parentId')
        
        user = User.query.filter_by(username=user_id).first()
        if not user: return jsonify({"message": "Usuario inválido"}), 403

        filename = secure_filename(file.filename)
        unique_name = f"{uuid.uuid4().hex[:8]}_{filename}"
        save_path = os.path.join(UPLOAD_FOLDER, unique_name)
        file.save(save_path)
        
        file_size = os.path.getsize(save_path)
        if parent_id == 'null' or parent_id == 'undefined': parent_id = None
        
        new_file = UserFile(owner_username=user_id, name=filename, type='file', parent_id=parent_id, size_bytes=file_size, storage_path=unique_name)
        db.session.add(new_file); db.session.commit()
        
        # RESPUESTA MEJORADA PARA ACTUALIZAR FRONTEND AL INSTANTE
        return jsonify({
            "message": "Subido", 
            "newFile": {
                "id": new_file.id, 
                "name": new_file.name,
                "type": "file",
                "parentId": parent_id,
                "size": f"{file_size/1048576:.2f} MB",
                "size_bytes": file_size, # <--- NECESARIO PARA EL CONTADOR
                "isPublished": False
            }
        }), 201
    except Exception as e: return jsonify({"message": str(e)}), 500

@app.route('/api/create-folder', methods=['POST'])
def create_folder():
    try:
        d = request.get_json()
        nf = UserFile(owner_username=d.get('userId'), name=d.get('name'), type='folder', parent_id=d.get('parentId'), size_bytes=0)
        db.session.add(nf); db.session.commit()
        return jsonify({"newFolder": {"id": nf.id, "name": nf.name, "type": "folder", "parentId": nf.parent_id}}), 201
    except Exception as e: return jsonify({"message": str(e)}), 500

@app.route('/api/delete-file', methods=['DELETE'])
def delete_f():
    try:
        d = request.get_json(); f = UserFile.query.get(d.get('fileId'))
        if f: db.session.delete(f); db.session.commit()
        return jsonify({"message": "Deleted"}), 200
    except: return jsonify({"message": "Error"}), 500

@app.route('/api/update-file', methods=['POST'])
def upd_file():
    try:
        d = request.get_json(); f = UserFile.query.get(d.get('fileId'))
        if f:
            u = d.get('updates', {})
            if 'name' in u: f.name = u['name']
            if 'isPublished' in u: f.is_published = u['isPublished']
            db.session.commit()
            return jsonify({"updatedFile": {"id": f.id}}), 200
        return jsonify({"msg": "404"}), 404
    except: return jsonify({"message": "Error"}), 500

@app.route('/get-crs-author', methods=['POST'])
def inspect_crs_author():
    try:
        file = request.files['file']; temp_path = os.path.join(UPLOAD_FOLDER, f"temp_{uuid.uuid4().hex}.crs"); file.save(temp_path)
        author_id = "N/A"
        try:
            with open(temp_path, 'rb') as f: data = pickle.load(f)
            author_id = data.get('public_author', 'N/A')
        except: pass
        finally: 
            if os.path.exists(temp_path): os.remove(temp_path)
        return jsonify({"authorId": str(author_id)}), 200
    except: return jsonify({"error": "Error"}), 500

# =========================================================================
# --- 4. CONSOLAS (LÓGICA CORREGIDA) ---
# =========================================================================

@app.route('/api/logs/historical', methods=['POST', 'GET'])
def logs(): 
    # LOGICA DE LECTURA (GET) - Leer logs históricos
    if request.method == 'GET':
        # 1. AUTENTICACIÓN ADMIN
        if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: 
            return jsonify({"msg": "Acceso denegado. Clave incorrecta."}), 403
        
        # 2. LECTURA DE DATOS DESDE DB
        try:
            # Ordenamos por fecha descendente y limitamos a los 100 más recientes
            logs = HistoricalLog.query.order_by(HistoricalLog.date.desc()).limit(100).all()
            return jsonify([{
                "id": log.id,
                "user": log.user,
                "ip": log.ip,
                "quality": log.quality,
                # La URL referencia el archivo que debe estar en /uploads
                "url": get_file_url(log.filename) if log.filename else 'Sin URL',
                "date": log.date.isoformat()
            } for log in logs]), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # LOGICA DE ESCRITURA (POST) - Guardar log enviado por el cliente
    if request.method == 'POST':
        user = request.headers.get('X-Username')
        ip = request.headers.get('X-IP')
        quality = request.headers.get('X-Quality')
        
        if not user or not ip or not quality:
            return jsonify({"message": "Faltan encabezados (Username, IP, Quality)"}), 400

        # Crear un nombre de archivo de referencia único
        filename_ref = f"{user}_{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}.log"
        
        # 1. CREAR ENTRADA EN DB (Metadatos)
        new_log = HistoricalLog(
            user=user, ip=ip, quality=quality, 
            filename=filename_ref,
            date=datetime.datetime.utcnow()
        )
        
        # 2. Guardar a DB
        try:
            db.session.add(new_log)
            db.session.commit()
            # La respuesta 201 es la que el cliente necesita para decir "LOG ENVIADO EXITOSAMENTE"
            return jsonify({"status": "Log registrado en DB", "filename": filename_ref}), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({"status": f"Error DB al guardar log: {str(e)}"}), 500

@app.route('/api/logs/incident', methods=['POST'])
def inc(): 
    # Lógica para incidentes. Se deja como stub para no afectar funcionalidad de files.
    return jsonify({"status":"OK"}), 201

@app.route('/api/logs/incidents', methods=['GET'])
def incs(): 
    # Lógica para leer incidentes. Se deja como lista vacía, pero con autenticación.
    if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: 
        return jsonify({"msg": "Acceso denegado"}), 403
    return jsonify([]), 200


@app.route('/api/updates/check', methods=['GET'])
def chk(): return jsonify({"message":"No updates"}), 404

if __name__ == '__main__': 
    app.run(host='0.0.0.0', port=7860)
