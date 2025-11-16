# --- servidor.py --- (v15.2 - CORRECCIÓN FINAL DE verificationStatus)
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
from sqlalchemy import text 

app = Flask(__name__)
print(">>> INICIANDO SERVIDOR MAESTRO (v15.2 - Arranque Estable) <<<")

CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)
bcrypt = Bcrypt(app)
ADMIN_SECRET_KEY = "NANO_MASTER_KEY_2025" 

# --- 🧠 MEMORIA RAM (Usuarios Online) ---
ONLINE_USERS = {} 

# --- 📂 DIRECTORIOS UNIVERSALES ---
BASE_DIR = os.getcwd()
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
LOGS_FOLDER = os.path.join(BASE_DIR, 'logs_historical')
UPDATES_FOLDER = os.path.join(BASE_DIR, 'updates')
INCIDENTS_FOLDER = os.path.join(BASE_DIR, 'logs_incidents')
DOCS_FOLDER = os.path.join(BASE_DIR, 'documentos_gestion')
BIBLIOTECA_PUBLIC_FOLDER = os.path.join(BASE_DIR, 'biblioteca_publica') 

for folder in [UPLOAD_FOLDER, LOGS_FOLDER, UPDATES_FOLDER, INCIDENTS_FOLDER, DOCS_FOLDER, BIBLIOTECA_PUBLIC_FOLDER]:
    os.makedirs(folder, exist_ok=True)

SUB_DOC_FOLDERS = ['desarrollo', 'gestion', 'operaciones']
for sub in SUB_DOC_FOLDERS:
    os.makedirs(os.path.join(DOCS_FOLDER, sub), exist_ok=True)


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
    
    # --- ¡¡AÑADIDO!! (CAMBIO 1 de 3) ---
    # Esta columna faltaba en tu versión anterior.
    verification_status = db.Column(db.String(20), nullable=True, default='N/A') 

class HistoricalLog(db.Model):
    __tablename__ = 'historical_log'
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(80)); ip = db.Column(db.String(50)); quality = db.Column(db.String(50))
    filename = db.Column(db.String(255))
    storage_path = db.Column(db.String(500))
    date = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class IncidentReport(db.Model):
    __tablename__ = 'incident_report'
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(80)); ip = db.Column(db.String(50)); message = db.Column(db.Text)
    filename = db.Column(db.String(255))
    storage_path = db.Column(db.String(500))
    date = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class UpdateFile(db.Model):
    __tablename__ = 'update_file'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255)) 
    version = db.Column(db.String(50))
    size = db.Column(db.Integer)
    date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    storage_path = db.Column(db.String(500), nullable=True)

class DocGestion(db.Model):
    __tablename__ = 'doc_gestion'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    section = db.Column(db.String(50), nullable=False) 
    storage_path = db.Column(db.String(500), nullable=True)
    size = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)


with app.app_context():
    if db: db.create_all()

# --- ÚTILES ---
def get_file_url(filename, folder_route='uploads'):
    if not filename: return None
    return f"{request.host_url}{folder_route}/{filename}"

def format_file_size(size_bytes):
    if size_bytes < 1048576: # Menos de 1 MB
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1073741824: # Menos de 1 GB
        return f"{size_bytes / 1048576:.2f} MB"
    else:
        return f"{size_bytes / 1073741824:.2f} GB"

# --- RUTAS DE DESCARGA ---
@app.route('/')
def health_check(): return jsonify({"status": "v15.2 ONLINE (Arranque Estable)", "db": db_status}), 200

# ... (todas las otras rutas de descarga, auth, admin, etc. van aquí sin cambios) ...
@app.route('/uploads/<path:filename>')
def download_user_file(filename): return send_from_directory(UPLOAD_FOLDER, filename)
@app.route('/logs_historical/<path:filename>')
def download_log_file(filename): return send_from_directory(LOGS_FOLDER, filename)
@app.route('/logs_incidents/<path:filename>')
def download_incident_file(filename): return send_from_directory(INCIDENTS_FOLDER, filename)
@app.route('/updates/<path:filename>')
def download_update_file(filename): return send_from_directory(UPDATES_FOLDER, filename)
@app.route('/documentos_gestion/<path:section>/<path:filename>')
def download_doc_gestion(section, filename): 
    if section not in SUB_DOC_FOLDERS: return jsonify({"msg": "Sección inválida"}), 400
    return send_from_directory(os.path.join(DOCS_FOLDER, section), filename)
@app.route('/biblioteca_publica/<path:filename>')
def download_biblioteca_file(filename): 
    return send_from_directory(BIBLIOTECA_PUBLIC_FOLDER, filename)

@app.route('/api/register', methods=['POST'])
def register():
    d = request.get_json()
    if User.query.filter_by(username=d.get('username')).first(): return jsonify({"message": "Usuario ocupado"}), 409
    if User.query.filter_by(email=d.get('email')).first(): return jsonify({"message": "Email ocupado"}), 409
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


@app.route('/api/my-files/<username>', methods=['GET'])
def get_files(username):
    try:
        files = UserFile.query.filter_by(owner_username=username).all()
        
        # --- ¡¡AÑADIDO!! (CAMBIO 2 de 3) ---
        # Ahora enviamos todos los datos que 'misarchivos.jsx' necesita
        file_list = []
        for f in files:
            file_list.append({
                "id": f.id,
                "name": f.name,
                "type": f.type,
                "parentId": f.parent_id,
                "size_bytes": f.size_bytes,
                "size": format_file_size(f.size_bytes), # Usamos la función de formato
                "path": get_file_url(f.storage_path, 'uploads'),
                "isPublished": f.is_published,
                "date": f.created_at.strftime('%Y-%m-%d'),
                "verificationStatus": f.verification_status, # <-- ¡EL DATO CLAVE!
                "monetization": {"enabled": f.price > 0, "price": f.price},
                "description": f.description,
                "tags": f.tags.split(',') if f.tags else []
            })
        return jsonify(file_list), 200
        # --- FIN DEL CAMBIO ---
        
    except Exception as e: 
        print(f"Error en get_files: {e}")
        return jsonify([]), 200

@app.route('/api/upload-file', methods=['POST'])
def upload_user_file():
    try:
        if 'file' not in request.files: return jsonify({"message": "Falta archivo"}), 400
        file = request.files['file']
        user_id = request.form.get('userId')
        parent_id = request.form.get('parentId')
        
        # --- ¡¡AÑADIDO!! (CAMBIO 3 de 3) ---
        # Leemos el verificationStatus que envía 'subir.jsx'
        verification_status = request.form.get('verificationStatus', 'N/A')
        # --- FIN AÑADIDO ---

        user = User.query.filter_by(username=user_id).first()
        if not user: return jsonify({"message": "Usuario inválido"}), 403
        
        filename = secure_filename(file.filename); unique_name = f"{uuid.uuid4().hex[:8]}_{filename}"
        save_path = os.path.join(UPLOAD_FOLDER, unique_name)
        file.save(save_path); file_size = os.path.getsize(save_path)
        
        if parent_id == 'null' or parent_id == 'undefined': 
            parent_id = None
        
        new_file = UserFile(
            owner_username=user_id, 
            name=filename, 
            type='file', 
            parent_id=parent_id, 
            size_bytes=file_size, 
            storage_path=unique_name,
            # --- ¡¡AÑADIDO!! ---
            verification_status=verification_status # Lo guardamos en la DB
        )
        
        db.session.add(new_file); db.session.commit()
        
        # Devolvemos el objeto completo para que 'misarchivos' lo pueda añadir al estado
        return jsonify({"message": "Subido", "newFile": {
            "id": new_file.id, 
            "name": new_file.name, 
            "type": "file", 
            "parentId": parent_id, 
            "size_bytes": file_size,
            "size": format_file_size(file_size),
            "isPublished": False,
            "date": new_file.created_at.strftime('%Y-%m-%d'),
            "verificationStatus": new_file.verification_status,
            "path": get_file_url(new_file.storage_path, 'uploads'),
            "monetization": {"enabled": False, "price": 0.0},
            "description": "",
            "tags": []
        }}), 201
    except Exception as e: 
        db.session.rollback()
        print(f"Error en upload-file: {e}")
        return jsonify({"message": str(e)}), 500

@app.route('/api/create-folder', methods=['POST'])
def create_folder():
    try:
        d = request.get_json()
        nf = UserFile(owner_username=d.get('userId'), name=d.get('name'), type='folder', parent_id=d.get('parentId'), size_bytes=0)
        db.session.add(nf); db.session.commit()
        return jsonify({"newFolder": {
            "id": nf.id, "name": nf.name, "type": "folder", "parentId": nf.parent_id, 
            "date": nf.created_at.strftime('%Y-%m-%d'), 
            "size": "0 KB", "size_bytes": 0, "isPublished": False, "verificationStatus": None
            }}), 201
    except Exception as e: return jsonify({"message": str(e)}), 500

@app.route('/api/delete-file', methods=['DELETE'])
def delete_f():
    try: 
        d = request.get_json()
        f = UserFile.query.get(d.get('fileId'))
        if f: 
            if f.type == 'file' and f.storage_path:
                try:
                    file_path = os.path.join(UPLOAD_FOLDER, f.storage_path)
                    if os.path.exists(file_path):
                        os.remove(file_path)
                except Exception as e:
                    print(f"Error al borrar archivo físico: {e}")
            db.session.delete(f)
            db.session.commit()
            return jsonify({"message": "Deleted"}), 200
        return jsonify({"message": "File not found"}), 404
    except Exception: 
        db.session.rollback()
        return jsonify({"message": "Error deleting file"}), 500

@app.route('/api/update-file', methods=['POST'])
def upd_file():
    try: 
        d = request.get_json()
        f = UserFile.query.get(d.get('fileId'))
        if f: 
            u = d.get('updates', {})
            if 'name' in u: f.name = u['name']
            if 'isPublished' in u: f.is_published = u['isPublished']
            if 'description' in u: f.description = u['description']
            if 'tags' in u: f.tags = ",".join(u['tags'])
            if 'monetization' in u:
                f.price = float(u['monetization'].get('price', 0.0)) if u['monetization'].get('enabled', False) else 0.0

            db.session.commit()
            
            return jsonify({"updatedFile": {
                "id": f.id, "name": f.name, "type": f.type, "parentId": f.parent_id, 
                "size_bytes": f.size_bytes, 
                "size": format_file_size(f.size_bytes),
                "path": get_file_url(f.storage_path, 'uploads'),
                "isPublished": f.is_published, "date": f.created_at.strftime('%Y-%m-%d'),
                "verificationStatus": f.verification_status,
                "monetization": {"enabled": f.price > 0, "price": f.price},
                "description": f.description,
                "tags": f.tags.split(',') if f.tags else []
            }}), 200
        return jsonify({"msg": "404"}), 404
    except Exception as e: 
        db.session.rollback()
        print(f"Error en update-file: {e}")
        return jsonify({"message": "Error updating file"}), 500

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
# --- GESTIÓN DE DOCUMENTOS UNIVERSALES (Sin Cambios) ---
# =========================================================
@app.route('/api/documentos/<section>', methods=['GET'])
def get_gestion_docs(section):
# ... (código existente)
    pass
@app.route('/api/documentos/upload', methods=['POST'])
def upload_gestion_doc():
# ... (código existente)
    pass
# =========================================================
# --- CONSOLAS (Sin Cambios) ---
# =========================================================
@app.route('/api/logs/historical', methods=['POST', 'GET'])
def logs(): 
# ... (código existente)
    pass
@app.route('/api/logs/incident', methods=['POST'])
def inc(): 
# ... (código existente)
    pass
@app.route('/api/logs/incidents', methods=['GET'])
def incs(): 
# ... (código existente)
    pass
@app.route('/api/updates/upload', methods=['POST'])
def upload_update_file_route():
# ... (código existente)
    pass
@app.route('/api/updates/list', methods=['GET'])
def list_update_files():
# ... (código existente)
    pass
@app.route('/api/updates/check', methods=['GET'])
def chk():
# ... (código existente)
    pass
# ... (Fin de las rutas) ...

if __name__ == '__main__': 
    app.run(host='0.0.0.0', port=7860)
