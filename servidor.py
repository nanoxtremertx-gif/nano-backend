# --- servidor.py --- (v17.1 - FINAL con DELETE de Docs y Vencimiento de Subs)
from flask import Flask, jsonify, request, send_from_directory
from flask_socketio import SocketIO, emit
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
print(">>> INICIANDO SERVIDOR MAESTRO (v17.1 - Arranque Estable con Sockets y Delete) <<<")

# --- Configuración de Sockets ---
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)
socketio = SocketIO(app, cors_allowed_origins="*")
bcrypt = Bcrypt(app)
ADMIN_SECRET_KEY = "NANO_MASTER_KEY_2025" 

# --- Memoria RAM (Usuarios Online) ---
ONLINE_USERS = {} 

def emit_online_count():
    """ Emite el recuento actual de usuarios a TODOS los clientes conectados. """
    try:
        count = len(ONLINE_USERS)
        socketio.emit('update_online_count', {'count': count})
        print(f"EMITIENDO CONTEO: {count} usuarios")
    except Exception as e:
        print(f"Error al emitir conteo: {e}")

# --- Directorios Universales ---
BASE_DIR = os.getcwd()
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
LOGS_FOLDER = os.path.join(BASE_DIR, 'logs_historical')
UPDATES_FOLDER = os.path.join(BASE_DIR, 'updates')
INCIDENTS_FOLDER = os.path.join(BASE_DIR, 'logs_incidents')
DOCS_FOLDER = os.path.join(BASE_DIR, 'documentos_gestion')
BIBLIOTECA_PUBLIC_FOLDER = os.path.join(BASE_DIR, 'biblioteca_publica') 

for folder in [UPLOAD_FOLDER, LOGS_FOLDER, UPDATES_FOLDER, INCIDENTS_FOLDER, DOCS_FOLDER, BIBLIOTECA_PUBLIC_FOLDER]:
    os.makedirs(folder, exist_ok=True)

# Aseguramos que existan las carpetas que 'vip.py' y 'consola_admin.py' esperan
SUB_DOC_FOLDERS = ['desarrollo', 'gestion', 'operaciones']
for sub in SUB_DOC_FOLDERS:
    os.makedirs(os.path.join(DOCS_FOLDER, sub), exist_ok=True)


# --- DB Setup ---
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

# --- Modelos ---
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    identificador = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), default="gratis")
    fingerprint = db.Column(db.String(80), nullable=True)
    subscription_end = db.Column(db.String(50), nullable=True) # vip.py usa esto
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

# --- Útiles ---
def get_file_url(filename, folder_route='uploads'):
    if not filename: return None
    return f"{request.host_url}{folder_route}/{filename}"

def format_file_size(size_bytes):
    if size_bytes < 1024:
        return f"{size_bytes} Bytes"
    if size_bytes < 1048576: return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1073741824: return f"{size_bytes / 1048576:.2f} MB"
    else: return f"{size_bytes / 1073741824:.2f} GB"

# --- Rutas de Descarga ---
@app.route('/')
def health_check(): return jsonify({"status": "v17.1 ONLINE (Sockets Activos)", "db": db_status}), 200

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

# --- Manejadores de Socket.IO ---
@socketio.on('connect')
def handle_connect():
    print(f"Cliente conectado: {request.sid}")
    emit('update_online_count', {'count': len(ONLINE_USERS)})

@socketio.on('disconnect')
def handle_disconnect():
    print(f"Cliente desconectado: {request.sid}")

# --- Rutas de Autenticación (con Sockets) ---
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
        emit_online_count() # <-- Avisa a todos
        return jsonify({"message": "Registrado"}), 201
    except Exception as e: db.session.rollback(); return jsonify({"message": str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    d = request.get_json()
    u = User.query.filter_by(username=d.get('username')).first()
    if u and bcrypt.check_password_hash(u.hash, d.get('password')):
        ONLINE_USERS[u.username] = datetime.datetime.utcnow()
        emit_online_count() # <-- Avisa a todos
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
        emit_online_count() # <-- Avisa a todos
        return jsonify({"status": "disconnected"}), 200
    return jsonify({"status": "ignored"}), 200

@app.route('/api/online-users', methods=['GET'])
def get_online_users():
    now = datetime.datetime.utcnow(); limit = now - timedelta(seconds=45)
    active_list = []; users_to_remove = []
    for user, last_time in ONLINE_USERS.items():
        if last_time > limit: active_list.append({"username": user, "last_seen": last_time.isoformat()})
        else: users_to_remove.append(user)
    
    if len(users_to_remove) > 0:
        for u in users_to_remove: del ONLINE_USERS[u]
        emit_online_count() # <-- Avisa si alguien expira
        
    return jsonify({"count": len(active_list), "users": active_list}), 200

# --- Rutas de Admin (usadas por vip.py) ---

@app.route('/api/admin/users', methods=['GET'])
def admin_list():
    """ Esta ruta es usada por vip.py para la gestión de usuarios. """
    if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg": "Acceso denegado"}), 403
    try:
        today_str = datetime.datetime.utcnow().strftime('%Y-%m-%d')
        users = User.query.all()
        user_list = []
        
        # --- ¡NUEVO! LÓGICA DE VENCIMIENTO (como pediste) ---
        users_changed = False
        for u in users:
            # Si es 'pro' y tiene fecha de vencimiento
            if u.role == 'pro' and u.subscription_end:
                try:
                    # Compara la fecha de vencimiento con la de hoy
                    if u.subscription_end.split("T")[0] < today_str:
                        u.role = 'gratis' # Vuelve a gratis
                        u.subscription_end = None
                        users_changed = True
                except Exception as e:
                    print(f"Error al parsear fecha de suscripción para {u.username}: {e}")
            
            user_list.append({
                "username": u.username, 
                "email": u.email, 
                "role": u.role, # Envía el rol actualizado
                "identificador": u.identificador, 
                "subscriptionEndDate": u.subscription_end # Envía la fecha actualizada (o None)
            })
        
        # Si se cambió algún usuario, guardar en la DB
        if users_changed:
            db.session.commit()
            print("INFO: Se han actualizado los roles de usuarios vencidos.")
        # --- FIN DE LÓGICA ---
            
        return jsonify(user_list), 200
    except Exception as e: 
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/api/admin/users/<username>', methods=['PUT'])
def admin_update(username):
    """ Esta ruta es usada por vip.py para editar usuarios. """
    if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg": "No"}), 403
    u = User.query.filter_by(username=username).first(); d = request.get_json()
    if not u: return jsonify({"msg": "404"}), 404
    if 'role' in d: u.role = d['role']
    if 'subscriptionEndDate' in d: u.subscription_end = d['subscriptionEndDate']
    db.session.commit(); return jsonify({"message": "Actualizado"}), 200

@app.route('/api/admin/users/<username>', methods=['DELETE'])
def admin_delete(username):
    """ Esta ruta es usada por vip.py para borrar usuarios. """
    if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg": "No"}), 403
    u = User.query.filter_by(username=username).first()
    if u: db.session.delete(u); db.session.commit()
    if username in ONLINE_USERS: del ONLINE_USERS[username]
    return jsonify({"message": "Eliminado"}), 200

# --- Rutas de Archivos de Usuario (misarchivos.jsx) ---
@app.route('/api/my-files/<username>', methods=['GET'])
def get_files(username):
    """ Esta ruta es la que usa 'misarchivos.jsx'. Envía todos los datos necesarios. """
    try:
        files = UserFile.query.filter_by(owner_username=username).all()
        file_list = []
        for f in files:
            file_list.append({
                "id": f.id, "name": f.name, "type": f.type, "parentId": f.parent_id,
                "size_bytes": f.size_bytes,
                "size": format_file_size(f.size_bytes), # <- Dato clave
                "path": get_file_url(f.storage_path, 'uploads'),
                "isPublished": f.is_published,
                "date": f.created_at.strftime('%Y-%m-%d'), # <- Dato clave
                "verificationStatus": f.verification_status, # <- Dato clave
                "monetization": {"enabled": f.price > 0, "price": f.price},
                "description": f.description,
                "tags": f.tags.split(',') if f.tags else []
            })
        return jsonify(file_list), 200
    except Exception as e: 
        print(f"Error en get_files: {e}")
        return jsonify([]), 200

@app.route('/api/upload-file', methods=['POST'])
def upload_user_file():
    """ Esta ruta es la que usa 'subir.jsx'. Guarda el verificationStatus. """
    try:
        if 'file' not in request.files: return jsonify({"message": "Falta archivo"}), 400
        file = request.files['file']
        user_id = request.form.get('userId')
        parent_id = request.form.get('parentId')
        verification_status = request.form.get('verificationStatus', 'N/A') # <-- Recibe el status

        user = User.query.filter_by(username=user_id).first()
        if not user: return jsonify({"message": "Usuario inválido"}), 403
        
        filename = secure_filename(file.filename); unique_name = f"{uuid.uuid4().hex[:8]}_{filename}"
        save_path = os.path.join(UPLOAD_FOLDER, unique_name)
        file.save(save_path); file_size = os.path.getsize(save_path)
        
        if parent_id == 'null' or parent_id == 'undefined': 
            parent_id = None
        
        if parent_id == 'root': # Fallback
            root_folder = UserFile.query.filter_by(owner_username=user_id, parent_id=None, name="Archivos de Usuario").first()
            parent_id = root_folder.id if root_folder else None

        new_file = UserFile(
            owner_username=user_id, name=filename, type='file', 
            parent_id=parent_id, # <-- Usa el ID real
            size_bytes=file_size, storage_path=unique_name,
            verification_status=verification_status # <-- Guarda el status
        )
        
        db.session.add(new_file); db.session.commit()
        
        return jsonify({"message": "Subido", "newFile": {
            "id": new_file.id, "name": new_file.name, "type": "file", "parentId": parent_id, 
            "size_bytes": file_size, "size": format_file_size(file_size),
            "isPublished": False, "date": new_file.created_at.strftime('%Y-%m-%d'),
            "verificationStatus": new_file.verification_status,
            "path": get_file_url(new_file.storage_path, 'uploads'),
            "monetization": {"enabled": False, "price": 0.0}, "description": "", "tags": []
        }}), 201
    except Exception as e: 
        db.session.rollback()
        print(f"Error en upload-file: {e}")
        return jsonify({"message": str(e)}), 500

@app.route('/api/create-folder', methods=['POST'])
def create_folder():
    """ Esta ruta es la que usa 'misarchivos.jsx' y 'subir.jsx'. """
    try:
        d = request.get_json()
        parent_id = d.get('parentId')
        
        if parent_id == 'root' or not parent_id: 
            root_folder = UserFile.query.filter_by(owner_username=d.get('userId'), parent_id=None, name="Archivos de Usuario").first()
            parent_id = root_folder.id if root_folder else None

        nf = UserFile(owner_username=d.get('userId'), name=d.get('name'), type='folder', parent_id=parent_id, size_bytes=0)
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
                    if os.path.exists(file_path): os.remove(file_path)
                except Exception as e: print(f"Error al borrar archivo físico: {e}")
            db.session.delete(f)
            db.session.commit()
            return jsonify({"message": "Deleted"}), 200
        return jsonify({"message": "File not found"}), 404
    except Exception: 
        db.session.rollback()
        return jsonify({"message": "Error deleting file"}), 500

@app.route('/api/update-file', methods=['POST'])
def upd_file():
    """ Esta ruta es la que usa 'misarchivos.jsx' para publicar. """
    try: 
        d = request.get_json()
        f = UserFile.query.get(d.get('fileId'))
        if f: 
            u = d.get('updates', {})
            if 'name' in u: f.name = u['name']
            if 'isPublished' in u: f.is_published = u['isPublished'] # <-- Mueve a la biblioteca
            if 'description' in u: f.description = u['description']
            if 'tags' in u: f.tags = ",".join(u['tags'])
            if 'monetization' in u:
                f.price = float(u['monetization'].get('price', 0.0)) if u['monetization'].get('enabled', False) else 0.0

            db.session.commit()
            
            return jsonify({"updatedFile": {
                "id": f.id, "name": f.name, "type": f.type, "parentId": f.parent_id, 
                "size_bytes": f.size_bytes, "size": format_file_size(f.size_bytes),
                "path": get_file_url(f.storage_path, 'uploads'),
                "isPublished": f.is_published, "date": f.created_at.strftime('%Y-%m-%d'),
                "verificationStatus": f.verification_status,
                "monetization": {"enabled": f.price > 0, "price": f.price},
                "description": f.description, "tags": f.tags.split(',') if f.tags else []
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
# --- GESTIÓN DE DOCUMENTOS (documentos.jsx, vip.py, consola_admin.py) ---
# =========================================================
@app.route('/api/documentos/<section>', methods=['GET'])
def get_gestion_docs(section):
    if section not in SUB_DOC_FOLDERS: return jsonify({"msg": "Sección inválida"}), 400
    try:
        docs = DocGestion.query.filter_by(section=section).all()
        # Esta estructura la leen 'vip.py', 'consola_admin.py' y 'documentos.jsx'
        return jsonify([{
            "id": d.id, "name": d.name, "size": d.size, "date": d.created_at.isoformat(),
            "url": get_file_url(os.path.join(section, d.storage_path), 'documentos_gestion')
        } for d in docs]), 200
    except: return jsonify([]), 200

@app.route('/api/documentos/upload', methods=['POST'])
def upload_gestion_doc():
    # Esta ruta la usan 'vip.py' y 'consola_admin.py'
    if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg": "Acceso denegado"}), 403
    try:
        if 'file' not in request.files or 'section' not in request.form: return jsonify({"message": "Faltan datos"}), 400
        file = request.files['file']; section = request.form['section']
        if section not in SUB_DOC_FOLDERS: return jsonify({"message": "Sección inválida"}), 400
        
        filename = secure_filename(file.filename)
        storage_name = f"{uuid.uuid4().hex[:8]}_{filename}"
        save_path = os.path.join(DOCS_FOLDER, section, storage_name)
        
        file.save(save_path)
        file_size = os.path.getsize(save_path)
        
        new_doc = DocGestion(name=filename, section=section, size=file_size, storage_path=storage_name)
        db.session.add(new_doc); db.session.commit()
        return jsonify({"message": "Documento subido"}), 201
    except Exception as e: return jsonify({"message": f"Error: {str(e)}"}), 500

# --- ¡¡NUEVA RUTA DE BORRADO (Para vip.py y consola_admin.py)!! ---
@app.route('/api/documentos/delete/<int:doc_id>', methods=['DELETE'])
def delete_gestion_doc(doc_id):
    if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: 
        return jsonify({"msg": "Acceso denegado"}), 403
    try:
        doc = DocGestion.query.get(doc_id)
        if not doc:
            return jsonify({"message": "Documento no encontrado"}), 404
        
        # 1. Borrar archivo físico
        if doc.storage_path:
            try:
                file_path = os.path.join(DOCS_FOLDER, doc.section, doc.storage_path)
                if os.path.exists(file_path):
                    os.remove(file_path)
            except Exception as e:
                print(f"Error al borrar archivo físico del doc: {e}")
        
        # 2. Borrar registro de la DB
        db.session.delete(doc)
        db.session.commit()
        return jsonify({"message": "Documento eliminado"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": f"Error: {str(e)}"}), 500

# =========================================================
# --- CONSOLAS (documentos.jsx) ---
# =========================================================
@app.route('/api/logs/historical', methods=['POST', 'GET'])
def logs(): 
    if request.method == 'GET':
        if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg": "Acceso denegado"}), 403
        try:
            logs = HistoricalLog.query.order_by(HistoricalLog.date.desc()).limit(100).all()
            return jsonify([{
                "id": log.id, "user": log.user, "ip": log.ip, "quality": log.quality,
                "url": get_file_url(log.storage_path, 'logs_historical') if log.storage_path else None, 
                "date": log.date.isoformat()
            } for log in logs]), 200
        except Exception as e: return jsonify({"error": str(e)}), 500
    
    if request.method == 'POST':
        user = request.headers.get('X-Username'); ip = request.headers.get('X-IP'); quality = request.headers.get('X-Quality')
        if not user or not ip or not quality: return jsonify({"message": "Faltan datos"}), 400
        filename_ref = f"LOG_{user}_{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}.log"
        save_path = os.path.join(LOGS_FOLDER, filename_ref)
        try:
            with open(save_path, 'wb') as f: f.write(request.data)
            new_log = HistoricalLog(user=user, ip=ip, quality=quality, filename=filename_ref, storage_path=filename_ref, date=datetime.datetime.utcnow())
            db.session.add(new_log); db.session.commit()
            return jsonify({"status": "Log registrado", "filename": filename_ref}), 201
        except Exception as e: return jsonify({"status": f"Error DB: {str(e)}"}), 500
        
@app.route('/api/logs/incident', methods=['POST'])
def inc(): 
    try:
        user = request.form.get('X-Username', request.headers.get('X-Username')); ip = request.form.get('X-IP', request.headers.get('X-IP')); message = request.form.get('message', 'Sin mensaje')
        if not user or not ip: return jsonify({"message": "Faltan datos de cabecera"}), 400
        file = request.files.get('log_file'); storage_name = None; filename = "N/A"
        if file:
            filename = secure_filename(file.filename)
            storage_name = f"INCIDENT_{user}_{uuid.uuid4().hex[:8]}_{filename}"
            save_path = os.path.join(INCIDENTS_FOLDER, storage_name)
            file.save(save_path)
        new_incident = IncidentReport(user=user, ip=ip, message=message, filename=filename, storage_path=storage_name, date=datetime.datetime.utcnow())
        db.session.add(new_incident); db.session.commit()
        return jsonify({"status":"Reporte de incidente recibido"}), 201
    except Exception as e: return jsonify({"status": f"Error al procesar incidente: {str(e)}"}), 500

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

@app.route('/api/updates/upload', methods=['POST'])
def upload_update_file_route():
    try:
        filename = request.headers.get('X-Vercel-Filename')
        if not filename: return jsonify({"message": "Falta X-Vercel-Filename"}), 400
        filename = secure_filename(filename)
        version_str = "".join(filter(str.isdigit, filename)) or "0"
        save_path = os.path.join(UPDATES_FOLDER, filename)
        with open(save_path, 'wb') as f: f.write(request.data)
        file_size = os.path.getsize(save_path)
        existing = UpdateFile.query.filter_by(filename=filename).first()
        if existing: db.session.delete(existing); db.session.commit()
        new_update = UpdateFile(filename=filename, version=version_str, size=file_size, storage_path=filename)
        db.session.add(new_update); db.session.commit()
        return jsonify({"message": "Actualización subida"}), 201
    except Exception as e: return jsonify({"message": f"Error: {str(e)}"}), 500

@app.route('/api/updates/list', methods=['GET'])
def list_update_files():
    try:
        updates = UpdateFile.query.order_by(UpdateFile.date.desc()).all()
        return jsonify([{
            "id": u.id, "name": u.filename, "version": u.version,
            "size": u.size, "date": u.date.isoformat()
        } for u in updates]), 200
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route('/api/updates/check', methods=['GET'])
def chk():
    try:
        latest_update = UpdateFile.query.order_by(UpdateFile.date.desc()).first()
        if not latest_update: return jsonify({"message":"No updates"}), 404
        return jsonify({
            "version": latest_update.version,
            "file_name": latest_update.filename,
            "download_url": get_file_url(latest_update.storage_path, 'updates'),
            "date": latest_update.date.isoformat()
        }), 200
    except Exception as e: return jsonify({"error": str(e)}), 500

# =========================================================
# --- API DE BIBLIOTECA PÚBLICA (biblioteca.jsx) ---
# =========================================================
@app.route('/api/biblioteca/public-files', methods=['GET'])
def get_public_files():
    try:
        files = UserFile.query.filter_by(is_published=True).order_by(UserFile.created_at.desc()).all()
        file_list = []
        for f in files:
            file_list.append({
                "id": f.id, "name": f.name, "type": f.type, "parentId": f.parent_id,
                "size_bytes": f.size_bytes, "size": format_file_size(f.size_bytes),
                "path": get_file_url(f.storage_path, 'uploads'),
                "isPublished": f.is_published, "date": f.created_at.strftime('%Y-%m-%d'),
                "verificationStatus": f.verification_status,
                "monetization": {"enabled": f.price > 0, "price": f.price},
                "description": f.description, "tags": f.tags.split(',') if f.tags else [],
                "userId": f.owner_username 
            })
        return jsonify(file_list), 200
    except Exception as e: 
        print(f"Error en get_public_files: {e}")
        return jsonify([]), 200

@app.route('/api/biblioteca/profiles', methods=['GET'])
def get_public_profiles():
    try:
        users = User.query.all()
        profile_list = [{
            "username": u.username.lower(),
            "displayName": u.username.capitalize(), 
            "avatar": None 
        } for u in users]
        return jsonify(profile_list), 200
    except Exception as e:
        print(f"Error en get_public_profiles: {e}")
        return jsonify([]), 200

# =========================================================
# --- ARRANQUE DEL SERVIDOR ---
# =========================================================
if __name__ == '__main__': 
    # Usamos socketio.run() para activar los WebSockets
    socketio.run(app, host='0.0.0.0', port=7860)
