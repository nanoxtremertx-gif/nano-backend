# --- servidor.py --- (v10.0 - Hugging Face Final)
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
print(">>> INICIANDO SERVIDOR (v10.0 - Backend Maestro) <<<")

CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)
bcrypt = Bcrypt(app)
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

# --- RUTAS ---
@app.route('/')
def health_check(): return jsonify({"status": "v10.0 ONLINE", "db": db_status}), 200

# --- 1. RUTA ADMIN (LA QUE FALTABA) ---
@app.route('/api/admin/users', methods=['GET'])
def admin_list():
    if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg": "No"}), 403
    try:
        users = User.query.all()
        return jsonify([{
            "username": u.username, "email": u.email, "role": u.role, 
            "subscriptionEndDate": u.subscription_end
        } for u in users]), 200
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route('/api/admin/users/<username>', methods=['DELETE'])
def admin_delete(username):
    if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg": "No"}), 403
    try:
        u = User.query.filter_by(username=username).first()
        if u: db.session.delete(u); db.session.commit()
        return jsonify({"message": "Eliminado"}), 200
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route('/api/admin/users/<username>', methods=['PUT'])
def admin_update(username):
    if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg": "No"}), 403
    try:
        u = User.query.filter_by(username=username).first()
        d = request.get_json()
        if u:
            if 'role' in d: u.role = d['role']
            if 'subscriptionEndDate' in d: u.subscription_end = d['subscriptionEndDate']
            db.session.commit()
            return jsonify({"message": "Actualizado"}), 200
        return jsonify({"msg": "404"}), 404
    except Exception as e: return jsonify({"error": str(e)}), 500

# --- 2. SUBIDA DE ARCHIVOS ---
@app.route('/api/upload-file', methods=['POST'])
def upload_user_file():
    try:
        if 'file' not in request.files: return jsonify({"message": "Sin archivo"}), 400
        file = request.files['file']
        user_id = request.form.get('userId'); parent_id = request.form.get('parentId')
        
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

        return jsonify({
            "message": "Subido", 
            "newFile": {"id": new_file.id, "name": new_file.name, "type": "file", "parentId": new_file.parent_id, "size": f"{file_size/1048576:.2f} MB"}
        }), 201
    except Exception as e: return jsonify({"message": str(e)}), 500

@app.route('/get-crs-author', methods=['POST'])
def inspect_crs_author():
    try:
        if 'file' not in request.files: return jsonify({"error": "No file"}), 400
        file = request.files['file']
        temp_path = os.path.join(UPLOAD_FOLDER, f"temp_{uuid.uuid4().hex}.crs")
        file.save(temp_path)
        author_id = "N/A"
        try:
            with open(temp_path, 'rb') as f:
                data = pickle.load(f)
            author_id = data.get('public_author', 'N/A')
        except: pass
        finally:
            if os.path.exists(temp_path): os.remove(temp_path)
        return jsonify({"authorId": str(author_id)}), 200
    except Exception as e: return jsonify({"error": str(e)}), 500

# --- 3. LISTADO ---
@app.route('/api/my-files/<username>', methods=['GET'])
def get_files(username):
    try:
        files = UserFile.query.filter_by(owner_username=username).all()
        return jsonify([
            {"id": f.id, "name": f.name, "type": f.type, "parentId": f.parent_id, "size": f"{f.size_bytes/1048576:.2f} MB" if f.size_bytes else "0 KB", "path": f.storage_path, "isPublished": f.is_published} 
            for f in files
        ]), 200
    except Exception: return jsonify([]), 200

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
            return jsonify({"updatedFile": {"id": f.id, "isPublished": f.is_published}}), 200
        return jsonify({"msg": "404"}), 404
    except: return jsonify({"message": "Error"}), 500

# --- 4. AUTH ---
@app.route('/api/login', methods=['POST'])
def login():
    d = request.get_json(); u = User.query.filter_by(username=d.get('username')).first()
    if u and bcrypt.check_password_hash(u.hash, d.get('password')): 
        return jsonify({"message": "OK", "user": {"username": u.username, "email": u.email, "role": u.role, "identificador": u.identificador, "isAdmin": u.role == 'admin'}}), 200
    return jsonify({"message": "Bad credentials"}), 401

@app.route('/api/register', methods=['POST'])
def register():
    d = request.get_json()
    if User.query.filter_by(username=d.get('username')).first(): return jsonify({"message": "Taken"}), 409
    db.session.add(User(username=d.get('username'), hash=bcrypt.generate_password_hash(d.get('password')).decode('utf-8'), email=d.get('email'), identificador=d.get('identificador'), role="gratis", fingerprint=d.get('username').lower()))
    db.session.commit(); return jsonify({"message": "OK"}), 201

# --- 5. CONSOLAS ---
@app.route('/api/logs/historical', methods=['POST', 'GET'])
def logs(): 
    if request.method=='POST': return jsonify({"status":"OK"}), 201
    return jsonify([]), 200
@app.route('/api/logs/incident', methods=['POST'])
def inc(): return jsonify({"status":"OK"}), 201
@app.route('/api/logs/incidents', methods=['GET'])
def incs(): return jsonify([]), 200
@app.route('/api/updates/check', methods=['GET'])
def chk(): return jsonify({"message":"No updates"}), 404

if __name__ == '__main__': 
    app.run(host='0.0.0.0', port=7860)
