# --- servidor.py --- (v10.7 - Full Console & Update System Fixed)
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
import datetime
from datetime import timedelta
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
print(">>> INICIANDO SERVIDOR MAESTRO (v10.7 - Update/Log Fix) <<<")

CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)
bcrypt = Bcrypt(app)
ADMIN_SECRET_KEY = "NANO_MASTER_KEY_2025" 

# --- 🧠 MEMORIA RAM DE USUARIOS CONECTADOS (INTACTO) ---
ONLINE_USERS = {} 
# --------------------------------------------------------

# --- 📂 DIRECTORIOS DE DATOS (NUEVO) 📂 ---
# Tu `UserFile` (Carpeta 1: PDFs/Archivos de Usuario) usa UPLOAD_FOLDER
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
# Tu `HistoricalLog` (Carpeta 2: Consola Logs) se guarda en la DB, el archivo se sube a LOGS_FOLDER
LOGS_FOLDER = os.path.join(os.getcwd(), 'logs_historical')
# Tu `UpdateFile` (Carpeta 3: Consola Actualizaciones) usa UPDATES_FOLDER
UPDATES_FOLDER = os.path.join(os.getcwd(), 'updates')
# Tu `IncidentReport` (Carpeta 4: Consola Incidentes) usa INCIDENTS_FOLDER
INCIDENTS_FOLDER = os.path.join(os.getcwd(), 'logs_incidents')

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(LOGS_FOLDER, exist_ok=True)
os.makedirs(UPDATES_FOLDER, exist_ok=True)
os.makedirs(INCIDENTS_FOLDER, exist_ok=True)
# ----------------------------------------------------

# --- DB SETUP ---
db_status = "Desconocido"
try:
    raw_url = os.environ.get('NEON_URL')
    if not raw_url:
        app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///fallback.db"
        db_status = "SQLite (TEMPORAL)"
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
    identificador = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), default="gratis")
    fingerprint = db.Column(db.String(80), nullable=True)
    subscription_end = db.Column(db.String(50), nullable=True)
    files = db.relationship('UserFile', backref='owner', lazy=True)

# Carpeta 1: Archivos de Gestión (PDFs) y Archivos de Usuario (CRS)
class UserFile(db.Model):
    __tablename__ = 'user_file'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    owner_username = db.Column(db.String(80), db.ForeignKey('user.username'), nullable=False)
    parent_id = db.Column(db.String(36), nullable=True)
    name = db.Column(db.String(255), nullable=False)
    type = db.Column(db.String(20), nullable=False)
    size_bytes = db.Column(db.BigInteger, default=0)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    storage_path = db.Column(db.String(500), nullable=True) # Guarda en UPLOAD_FOLDER
    is_published = db.Column(db.Boolean, default=False)
    description = db.Column(db.Text, nullable=True)
    tags = db.Column(db.String(500), nullable=True)
    price = db.Column(db.Float, default=0.0)

# Carpeta 2: Consola Logs Históricos
class HistoricalLog(db.Model):
    __tablename__ = 'historical_log'
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(80)); ip = db.Column(db.String(50)); quality = db.Column(db.String(50))
    filename = db.Column(db.String(255)); date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    storage_path = db.Column(db.String(500), nullable=True) # Guarda en LOGS_FOLDER

# Carpeta 4: Consola Reporte de Incidentes
class IncidentReport(db.Model):
    __tablename__ = 'incident_report'
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(80)); ip = db.Column(db.String(50)); message = db.Column(db.Text)
    filename = db.Column(db.String(255)); date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    storage_path = db.Column(db.String(500), nullable=True) # Guarda en INCIDENTS_FOLDER

# --- 📦 NUEVO MODELO 📦 ---
# Carpeta 3: Consola Actualizaciones
class UpdateFile(db.Model):
    __tablename__ = 'update_file'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), unique=True)
    version = db.Column(db.String(50)) # Extraído del nombre, ej: "001"
    size = db.Column(db.Integer)
    date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    storage_path = db.Column(db.String(500), nullable=True) # Guarda en UPDATES_FOLDER

with app.app_context():
    if db: db.create_all()

# --- ÚTILES ---
# Modificado para servir archivos de diferentes carpetas
def get_file_url(filename, folder_type='uploads'):
    if not filename: return None
    return f"{request.host_url}{folder_type}/{filename}"

# --- RUTAS DE SERVICIO DE ARCHIVOS ---
@app.route('/')
def health_check(): return jsonify({"status": "v10.7 (Update/Log Fix) ONLINE", "db": db_status}), 200

@app.route('/uploads/<path:filename>')
def download_file(filename): return send_from_directory(UPLOAD_FOLDER, filename)

@app.route('/logs_historical/<path:filename>')
def download_log_file(filename): return send_from_directory(LOGS_FOLDER, filename)

@app.route('/logs_incidents/<path:filename>')
def download_incident_file(filename): return send_from_directory(INCIDENTS_FOLDER, filename)

@app.route('/updates/<path:filename>')
def download_update_file(filename): return send_from_directory(UPDATES_FOLDER, filename)


# --- AUTH (Sin cambios) ---
@app.route('/api/register', methods=['POST'])
def register():
    d = request.get_json()
    if User.query.filter_by(username=d.get('username')).first(): return jsonify({"message": "Usuario ocupado"}), 409
    if User.query.filter_by(email=d.get('email')).first(): return jsonify({"message": "Email ocupado"}), 409
    if User.query.filter_by(identificador=d.get('identificador')).first(): return jsonify({"message": "ID ocupado"}), 409
    new_user = User(username=d.get('username'), hash=bcrypt.generate_password_hash(d.get('password')).decode('utf-8'), email=d.get('email'), identificador=d.get('identificador'), role="gratis", fingerprint=d.get('username').lower())
    try:
        db.session.add(new_user)
        db.session.add(UserFile(owner_username=d.get('username'), name="Archivos de Usuario", type='folder', parent_id=None, size_bytes=0))
        db.session.commit()
        ONLINE_USERS[d.get('username')] = datetime.datetime.utcnow()
        return jsonify({"message": "Registrado"}), 201
    except Exception as e: db.session.rollback(); return jsonify({"message": str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    d = request.get_json()
    u = User.query.filter_by(username=d.get('username')).first()
    if u and bcrypt.check_password_hash(u.hash, d.get('password')):
        ONLINE_USERS[u.username] = datetime.datetime.utcnow()
        return jsonify({"message": "OK", "user": {"username": u.username, "email": u.email, "role": u.role, "identificador": u.identificador, "isAdmin": u.role == 'admin'}}), 200
    return jsonify({"message": "Credenciales inválidas"}), 401

# --- SISTEMA DE SEÑALES (Sin cambios) ---
@app.route('/api/heartbeat', methods=['POST'])
def heartbeat():
    d = request.get_json(); username = d.get('username')
    if username: ONLINE_USERS[username] = datetime.datetime.utcnow(); return jsonify({"status": "alive"}), 200
    return jsonify({"msg": "No user"}), 400

@app.route('/api/logout-signal', methods=['POST'])
def logout_signal():
    username = None
    try:
        d = request.get_json(silent=True)
        if d: username = d.get('username')
        else: username = request.form.get('username')
    except: pass
    if username and username in ONLINE_USERS:
        del ONLINE_USERS[username]
        return jsonify({"status": "disconnected"}), 200
    return jsonify({"status": "ignored"}), 200

@app.route('/api/online-users', methods=['GET'])
def get_online_users():
    now = datetime.datetime.utcnow(); limit = now - timedelta(seconds=45)
    active_list = []; users_to_remove = []
    for user, last_time in ONLINE_USERS.items():
        if last_time > limit: active_list.append({"username": user, "last_seen": last_time.isoformat()})
        else: users_to_remove.append(user)
    for u in users_to_remove: del ONLINE_USERS[u]
    return jsonify({"count": len(active_list), "users": active_list}), 200

# --- ADMIN API (Sin cambios) ---
@app.route('/api/admin/users', methods=['GET'])
def admin_list():
    if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg": "Acceso denegado"}), 403
    try:
        users = User.query.all()
        return jsonify([{"username": u.username, "email": u.email, "role": u.role, "identificador": u.identificador, "subscriptionEndDate": u.subscription_end} for u in users]), 200
    except Exception as e: return jsonify({"error": str(e)}), 500
@app.route('/api/admin/users/<username>', methods=['PUT'])
def admin_update(username):
    if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg": "No"}), 403
    u = User.query.filter_by(username=username).first(); d = request.get_json()
    if not u: return jsonify({"msg": "404"}), 404
    if 'role' in d: u.role = d['role']
    if 'subscriptionEndDate' in d: u.subscription_end = d['subscriptionEndDate']
    db.session.commit(); return jsonify({"message": "Actualizado"}), 200
@app.route('/api/admin/users/<username>', methods=['DELETE'])
def admin_delete(username):
    if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg": "No"}), 403
    u = User.query.filter_by(username=username).first()
    if u: db.session.delete(u); db.session.commit()
    if username in ONLINE_USERS: del ONLINE_USERS[username]
    return jsonify({"message": "Eliminado"}), 200

# --- GESTIÓN DE ARCHIVOS (Carpeta 1: PDFs y CRS) (Sin cambios) ---
@app.route('/api/my-files/<username>', methods=['GET'])
def get_files(username):
    try:
        files = UserFile.query.filter_by(owner_username=username).all()
        return jsonify([{"id": f.id, "name": f.name, "type": f.type, "parentId": f.parent_id, "size": f.size_bytes, "size_bytes": f.size_bytes, "path": f.storage_path, "isPublished": f.is_published} for f in files]), 200
    except: return jsonify([]), 200
@app.route('/api/upload-file', methods=['POST'])
def upload_user_file():
    try:
        if 'file' not in request.files: return jsonify({"message": "Falta archivo"}), 400
        file = request.files['file']; user_id = request.form.get('userId'); parent_id = request.form.get('parentId')
        user = User.query.filter_by(username=user_id).first()
        if not user: return jsonify({"message": "Usuario inválido"}), 403
        filename = secure_filename(file.filename); unique_name = f"{uuid.uuid4().hex[:8]}_{filename}"
        save_path = os.path.join(UPLOAD_FOLDER, unique_name)
        file.save(save_path); file_size = os.path.getsize(save_path)
        if parent_id == 'null' or parent_id == 'undefined': parent_id = None
        new_file = UserFile(owner_username=user_id, name=filename, type='file', parent_id=parent_id, size_bytes=file_size, storage_path=unique_name)
        db.session.add(new_file); db.session.commit()
        return jsonify({"message": "Subido", "newFile": {"id": new_file.id, "name": new_file.name, "type": "file", "parentId": parent_id, "size": file_size, "size_bytes": file_size, "isPublished": False}}), 201
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
    try: d = request.get_json(); f = UserFile.query.get(d.get('fileId'));
    if f: db.session.delete(f); db.session.commit()
    return jsonify({"message": "Deleted"}), 200
    except: return jsonify({"message": "Error"}), 500
@app.route('/api/update-file', methods=['POST'])
def upd_file():
    try:
        d = request.get_json(); f = UserFile.query.get(d.get('fileId'))
        if f: u = d.get('updates', {});
        if 'name' in u: f.name = u['name']
        if 'isPublished' in u: f.is_published = u['isPublished']
        db.session.commit(); return jsonify({"updatedFile": {"id": f.id}}), 200
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


# =========================================================
# --- 🛠️ RUTAS DE CONSOLAS (ARREGLADAS) 🛠️ ---
# =========================================================

# --- CONSOLA 1: LOGS HISTÓRICOS (Carpeta 2) ---
@app.route('/api/logs/historical', methods=['POST', 'GET'])
def logs(): 
    if request.method == 'GET':
        if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg": "Acceso denegado"}), 403
        try:
            logs = HistoricalLog.query.order_by(HistoricalLog.date.desc()).limit(100).all()
            return jsonify([{
                "id": log.id, "user": log.user, "ip": log.ip, "quality": log.quality,
                # Usa la nueva URL para apuntar a /logs_historical/
                "url": get_file_url(log.storage_path, 'logs_historical') if log.storage_path else None, 
                "date": log.date.isoformat()
            } for log in logs]), 200
        except Exception as e: return jsonify({"error": str(e)}), 500

    if request.method == 'POST':
        user = request.headers.get('X-Username'); ip = request.headers.get('X-IP'); quality = request.headers.get('X-Quality')
        if not user or not ip or not quality: return jsonify({"message": "Faltan datos"}), 400
        
        filename_ref = f"{user}_{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}.log"
        save_path = os.path.join(LOGS_FOLDER, filename_ref)
        
        try:
            # Guarda el cuerpo del POST (el archivo de log)
            with open(save_path, 'wb') as f:
                f.write(request.data)
                
            new_log = HistoricalLog(user=user, ip=ip, quality=quality, filename=filename_ref, storage_path=filename_ref, date=datetime.datetime.utcnow())
            db.session.add(new_log); db.session.commit()
            return jsonify({"status": "Log registrado", "filename": filename_ref}), 201
        except Exception as e: return jsonify({"status": f"Error DB: {str(e)}"}), 500

# --- CONSOLA 2: INCIDENTES (Carpeta 4) (ARREGLADO) ---
@app.route('/api/logs/incident', methods=['POST'])
def inc(): 
    try:
        user = request.form.get('X-Username', request.headers.get('X-Username'))
        ip = request.form.get('X-IP', request.headers.get('X-IP'))
        message = request.form.get('message', 'Sin mensaje')
        
        if not user or not ip: return jsonify({"message": "Faltan datos de cabecera"}), 400

        file = request.files.get('log_file')
        storage_name = None
        filename = "N/A"

        if file:
            filename = secure_filename(file.filename)
            storage_name = f"INCIDENT_{user}_{uuid.uuid4().hex[:8]}_{filename}.log"
            save_path = os.path.join(INCIDENTS_FOLDER, storage_name)
            file.save(save_path)

        new_incident = IncidentReport(
            user=user, ip=ip, message=message, 
            filename=filename, storage_path=storage_name, 
            date=datetime.datetime.utcnow()
        )
        db.session.add(new_incident)
        db.session.commit()
        return jsonify({"status":"Reporte de incidente recibido"}), 201
        
    except Exception as e:
        return jsonify({"status": f"Error al procesar incidente: {str(e)}"}), 500

@app.route('/api/logs/incidents', methods=['GET'])
def incs(): 
    if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg": "Acceso denegado"}), 403
    try:
        reports = IncidentReport.query.order_by(IncidentReport.date.desc()).limit(100).all()
        return jsonify([{
            "id": r.id, "user": r.user, "ip": r.ip, "message": r.message,
            "url": get_file_url(r.storage_path, 'logs_incidents') if r.storage_path else None,
            "logFile": r.filename, "date": r.date.isoformat()
        } for r in reports]), 200
    except Exception as e: return jsonify({"error": str(e)}), 500


# --- CONSOLA 3: ACTUALIZACIONES (Carpeta 3) (ARREGLADO) ---
@app.route('/api/updates/upload', methods=['POST'])
def upload_update_file():
    # Esta ruta es para 'documentos.jsx'
    try:
        # Vercel/HuggingFace envía el archivo en el body, no como 'file'
        filename = request.headers.get('X-Vercel-Filename')
        if not filename: return jsonify({"message": "Falta X-Vercel-Filename"}), 400
        
        filename = secure_filename(filename)
        # Extraer versión del nombre, ej: "actualizacion003.py" -> "003"
        version_str = "".join(filter(str.isdigit, filename)) or "0"
        
        save_path = os.path.join(UPDATES_FOLDER, filename)
        
        with open(save_path, 'wb') as f:
            f.write(request.data)
        
        file_size = os.path.getsize(save_path)
        
        # Borrar la versión vieja si existe
        existing = UpdateFile.query.filter_by(filename=filename).first()
        if existing: db.session.delete(existing); db.session.commit()

        new_update = UpdateFile(
            filename=filename, version=version_str, 
            size=file_size, storage_path=filename
        )
        db.session.add(new_update)
        db.session.commit()
        return jsonify({"message": "Actualización subida"}), 201

    except Exception as e:
        return jsonify({"message": f"Error: {str(e)}"}), 500

@app.route('/api/updates/list', methods=['GET'])
def list_update_files():
    # Esta ruta es para 'documentos.jsx'
    try:
        updates = UpdateFile.query.order_by(UpdateFile.date.desc()).all()
        return jsonify([{
            "id": u.id, "name": u.filename, "version": u.version,
            "size": u.size, "date": u.date.isoformat()
        } for u in updates]), 200
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route('/api/updates/check', methods=['GET'])
def chk():
    # Esta ruta es para 'actualizacion.py'
    try:
        # Buscar la actualización más reciente por fecha
        latest_update = UpdateFile.query.order_by(UpdateFile.date.desc()).first()
        
        if not latest_update:
            return jsonify({"message":"No updates"}), 404
        
        # Devolver la URL de descarga y la versión
        return jsonify({
            "version": latest_update.version,
            "file_name": latest_update.filename,
            "download_url": get_file_url(latest_update.storage_path, 'updates'),
            "date": latest_update.date.isoformat()
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__': 
    app.run(host='0.0.0.0', port=7860)
