# --- servidor.py --- (v26.0 - MAESTRO FINAL: FIX BIBLIOTECA + CFO + S4 + RESET)
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

# ==========================================
# 🆕 MODELOS PARA AUDITORÍA CFO
# ==========================================
class DownloadRecord(db.Model):
    __tablename__ = 'download_record'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(100))
    filename = db.Column(db.String(255))
    category = db.Column(db.String(50))
    ip_address = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class SalesRecord(db.Model):
    __tablename__ = 'sales_record'
    id = db.Column(db.Integer, primary_key=True)
    buyer_username = db.Column(db.String(100))
    amount = db.Column(db.Float)
    concept = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# --- 2. INICIALIZAR EXTENSIONES ---
cors = CORS()
bcrypt = Bcrypt()
socketio = SocketIO()

# --- 3. MEMORIA RAM ---
ONLINE_USERS = {}
ADMIN_SECRET_KEY = "NANO_MASTER_KEY_2025" 
db_status = "Desconocido"

# --- 4. DEFINIR LA FÁBRICA ---
def create_app():
    global db_status
    
    app = Flask(__name__)
    print(">>> INICIANDO SERVIDOR MAESTRO (v26.0 - Sinergia Total) <<<")

    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        "pool_pre_ping": True, "pool_recycle": 300, "pool_timeout": 30, "pool_size": 10, "max_overflow": 20
    }

    try:
        raw_url = os.environ.get('NEON_URL')
        if not raw_url:
            print("⚠️ NEON_URL no encontrada. Usando SQLite local.")
            app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///local_fallback.db"
            db_status = "SQLite (Local)"
        else:
            parsed = urlparse(raw_url)
            scheme = 'postgresql' if parsed.scheme == 'postgres' else parsed.scheme
            clean_url = urlunparse((scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, parsed.fragment)).strip("'").strip()
            if 'postgresql' in clean_url and 'sslmode' not in clean_url: clean_url += "?sslmode=require"
            app.config['SQLALCHEMY_DATABASE_URI'] = clean_url
            db_status = "Neon PostgreSQL (REAL)"
    except Exception as e:
        print(f"!!! ERROR CRÍTICO AL CONFIGURAR DB: {e}")
        app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///fallback.db"
        db_status = "SQLite (FALLBACK)"

    # --- 6. INIT ---
    cors.init_app(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)
    socketio.init_app(app, cors_allowed_origins="*")
    bcrypt.init_app(app)
    db.init_app(app)

    # --- 7. DIRECTORIOS (ESTRUCTURA DE 3 CARPETAS SOLICITADA) ---
    BASE_DIR = os.getcwd()
    
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    AVATARS_FOLDER = os.path.join(UPLOAD_FOLDER, 'avatars')
    DOCS_FOLDER = os.path.join(BASE_DIR, 'documentos_gestion')
    BIBLIOTECA_PUBLIC_FOLDER = os.path.join(BASE_DIR, 'biblioteca_publica')

    # Carpetas de Diagnóstico
    LOGS_FOLDER = os.path.join(BASE_DIR, 'logs_historical')       # 1. Logs
    INCIDENTS_FOLDER = os.path.join(BASE_DIR, 'logs_incidents')   # 2. Incidentes
    UPDATES_FOLDER = os.path.join(BASE_DIR, 'updates_system')     # 3. Actualizaciones
    
    # Subcarpeta de Tracking
    UPDATES_TRACKING_FOLDER = os.path.join(UPDATES_FOLDER, 'download_tracking')

    ALL_FOLDERS = [
        UPLOAD_FOLDER, AVATARS_FOLDER, DOCS_FOLDER, BIBLIOTECA_PUBLIC_FOLDER,
        LOGS_FOLDER, INCIDENTS_FOLDER, UPDATES_FOLDER, UPDATES_TRACKING_FOLDER
    ]
    for folder in ALL_FOLDERS: os.makedirs(folder, exist_ok=True)

    SUB_DOC_FOLDERS = ['desarrollo', 'gestion', 'operaciones']
    for sub in SUB_DOC_FOLDERS: os.makedirs(os.path.join(DOCS_FOLDER, sub), exist_ok=True)

    # --- HELPER: TRACKER DB (CFO) ---
    def track_download_db(filename, category):
        try:
            user = request.args.get('user') or request.headers.get('X-Username') or "Anonimo"
            ip = request.remote_addr
            rec = DownloadRecord(user_id=user, filename=filename, category=category, ip_address=ip)
            db.session.add(rec)
            db.session.commit()
        except Exception as e:
            print(f"Error DB Tracking: {e}")

    # --- Helpers Normales ---
    def emit_online_count():
        try: socketio.emit('update_online_count', {'count': len(ONLINE_USERS)})
        except: pass

    def get_file_url(filename, folder_route='uploads'):
        if not filename: return None
        return f"{request.host_url}{folder_route}/{filename}"

    def format_file_size(size_bytes):
        if size_bytes is None: return "N/A"
        if size_bytes < 1024: return f"{size_bytes} Bytes"
        if size_bytes < 1048576: return f"{size_bytes/1024:.1f} KB"
        return f"{size_bytes/1048576:.2f} MB"

    # --- HEALTH ---
    @app.route('/')
    def index(): return jsonify({"status": "v26.0 ONLINE", "db": db_status}), 200
    
    @app.route('/health')
    def health(): return jsonify({"status": "ALIVE"}), 200

    # --- RUTAS DE DESCARGA (CON TRACKING) ---
    @app.route('/uploads/<path:filename>')
    def download_user_file(filename): 
        track_download_db(filename, 'user_file')
        return send_from_directory(UPLOAD_FOLDER, filename)

    @app.route('/uploads/avatars/<path:filename>')
    def download_avatar(filename): return send_from_directory(AVATARS_FOLDER, filename)

    @app.route('/logs_historical/<path:filename>')
    def download_log_file(filename): 
        track_download_db(filename, 'historical_log')
        return send_from_directory(LOGS_FOLDER, filename)
    
    @app.route('/logs_incidents/<path:filename>')
    def download_incident_file(filename): 
        track_download_db(filename, 'incident_report')
        return send_from_directory(INCIDENTS_FOLDER, filename)

    @app.route('/documentos_gestion/<path:section>/<path:filename>')
    def download_doc_gestion(section, filename):
        if section not in SUB_DOC_FOLDERS: return jsonify({"msg": "Sección inválida"}), 400
        track_download_db(filename, f'doc_{section}')
        return send_from_directory(os.path.join(DOCS_FOLDER, section), filename)

    @app.route('/biblioteca_publica/<path:filename>')
    def download_biblioteca_file(filename):
        track_download_db(filename, 'public_lib')
        return send_from_directory(BIBLIOTECA_PUBLIC_FOLDER, filename)
    
    # --- RUTA DE DESCARGA DE ACTUALIZACIONES (TRACKING DOBLE: DB + TXT) ---
    @app.route('/updates/<path:filename>')
    def download_update_file(filename):
        # 1. DB Tracking (CFO)
        track_download_db(filename, 'system_update')

        # 2. File Tracking (COO - Carpeta interna)
        try:
            requester_ip = request.remote_addr
            requester_user = request.args.get('user', 'Anonimo')
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_line = f"[{timestamp}] IP: {requester_ip} - User: {requester_user} - Downloaded: {filename}\n"
            
            tracking_file = os.path.join(UPDATES_TRACKING_FOLDER, f"track_{filename}.txt")
            with open(tracking_file, "a") as f:
                f.write(log_line)
        except: pass

        return send_from_directory(UPDATES_FOLDER, filename)

    # --- API CFO ANALYTICS ---
    @app.route('/api/cfo/analytics', methods=['GET'])
    def get_cfo_analytics():
        if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg": "Deny"}), 403
        try:
            total_dls = DownloadRecord.query.count()
            total_sales = db.session.query(db.func.sum(SalesRecord.amount)).scalar() or 0.0
            
            top = db.session.query(DownloadRecord.user_id, db.func.count(DownloadRecord.id))\
                    .group_by(DownloadRecord.user_id)\
                    .order_by(db.func.count(DownloadRecord.id).desc()).limit(5).all()
            top_users = [{"user": r[0], "count": r[1]} for r in top]
            
            recents = DownloadRecord.query.order_by(DownloadRecord.timestamp.desc()).limit(50).all()
            recent_list = [{"user": r.user_id, "file": r.filename, "type": r.category, "date": r.timestamp.isoformat()} for r in recents]

            return jsonify({
                "total_downloads": total_dls,
                "total_sales": total_sales,
                "top_users": top_users,
                "recent_downloads": recent_list
            }), 200
        except Exception as e: return jsonify({"error": str(e)}), 500

    @app.route('/admin/create_tables', methods=['GET'])
    def create_tables():
        if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg": "Acceso denegado"}), 403
        try:
            with app.app_context(): db.create_all()
            return jsonify({"message": "Tablas actualizadas."}), 200
        except Exception as e: return jsonify({"error": str(e)}), 500

    # --- SOCKETS ---
    @socketio.on('connect')
    def handle_connect(): emit('update_online_count', {'count': len(ONLINE_USERS)})
    @socketio.on('disconnect')
    def handle_disconnect(): pass

    # --- AUTH Y GESTIÓN ---
    @app.route('/api/register', methods=['POST'])
    def register():
        d = request.get_json()
        if User.query.filter_by(username=d.get('username')).first(): return jsonify({"message": "Usuario ocupado"}), 409
        if User.query.filter_by(email=d.get('email')).first(): return jsonify({"message": "Email ocupado"}), 409
        
        new_user = User(username=d.get('username'), hash=bcrypt.generate_password_hash(d.get('password')).decode('utf-8'), email=d.get('email'), identificador=d.get('identificador'), role="gratis", fingerprint=d.get('username').lower(), display_name=d.get('username').capitalize(), bio="Nuevo usuario", avatar="/user.ico")
        try:
            db.session.add(new_user); db.session.commit()
            new_folder = UserFile(owner_username=d.get('username'), name="Archivos de Usuario", type='folder', parent_id=None, size_bytes=0, verification_status='N/A')
            db.session.add(new_folder); db.session.commit()
            ONLINE_USERS[d.get('username')] = datetime.datetime.utcnow(); emit_online_count()
            return jsonify({"message": "Registrado"}), 201
        except Exception as e: db.session.rollback(); return jsonify({"message": str(e)}), 500

    @app.route('/api/login', methods=['POST'])
    def login():
        d = request.get_json(); u = User.query.filter_by(username=d.get('username')).first()
        if u and bcrypt.check_password_hash(u.hash, d.get('password')):
            try:
                if not UserFile.query.filter_by(owner_username=u.username, parent_id=None).first():
                    db.session.add(UserFile(owner_username=u.username, name="Archivos de Usuario", type='folder', parent_id=None, size_bytes=0)); db.session.commit()
            except: db.session.rollback()
            ONLINE_USERS[u.username] = datetime.datetime.utcnow(); emit_online_count()
            return jsonify({"message":"OK", "user": {"username":u.username, "email":u.email, "role":u.role, "identificador":u.identificador, "isAdmin":u.role=='admin', "displayName":getattr(u,'display_name',u.username), "bio":getattr(u,'bio',''), "avatar":getattr(u,'avatar','/user.ico')}}), 200
        return jsonify({"message": "Error credenciales"}), 401

    @app.route('/api/update-profile', methods=['POST'])
    def update_profile():
        try:
            u = User.query.filter_by(username=request.form.get('username')).first()
            if not u: return jsonify({"success":False}), 404
            u.display_name = request.form.get('displayName', u.display_name); u.bio = request.form.get('bio', u.bio)
            f = request.files.get('avatar')
            if f:
                fn = secure_filename(f.filename); uid = f"avatar_{uuid.uuid4().hex[:8]}_{fn}"
                f.save(os.path.join(AVATARS_FOLDER, uid)); u.avatar = f"/uploads/avatars/{uid}"
            db.session.commit()
            return jsonify({"success":True, "updatedUser": {"username":u.username, "displayName":u.display_name, "avatar":u.avatar}}), 200
        except: return jsonify({"success":False}), 500

    @app.route('/api/heartbeat', methods=['POST'])
    def heartbeat():
        d = request.get_json(); u = d.get('username')
        if u: ONLINE_USERS[u] = datetime.datetime.utcnow(); return jsonify({"status":"alive"}), 200
        return jsonify({"msg":"No user"}), 400

    @app.route('/api/logout-signal', methods=['POST'])
    def logout_signal():
        try: 
            d=request.get_json(silent=True); u=d.get('username') if d else request.form.get('username')
            if u in ONLINE_USERS: del ONLINE_USERS[u]; emit_online_count(); return jsonify({"status":"disconnected"}), 200
        except: pass
        return jsonify({"status":"ignored"}), 200

    @app.route('/api/online-users', methods=['GET'])
    def get_online_users():
        limit = datetime.datetime.utcnow() - timedelta(seconds=45); active = []
        to_del = [u for u, t in ONLINE_USERS.items() if t <= limit]
        for u in to_del: del ONLINE_USERS[u]
        for u, t in ONLINE_USERS.items(): active.append({"username": u, "last_seen": t.isoformat()})
        if to_del: emit_online_count()
        return jsonify({"count": len(active), "users": active}), 200

    @app.route('/api/admin/users', methods=['GET'])
    def admin_list():
        if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg": "Acceso denegado"}), 403
        try: users = User.query.all(); return jsonify([{"username":u.username, "email":u.email, "role":u.role, "identificador":u.identificador, "subscriptionEndDate":u.subscription_end} for u in users]), 200
        except Exception as e: return jsonify({"error": str(e)}), 500

    @app.route('/api/admin/users/<username>', methods=['PUT', 'DELETE'])
    def admin_modify(username):
        if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg": "No"}), 403
        u = User.query.filter_by(username=username).first()
        if not u: return jsonify({"msg": "404"}), 404
        
        if request.method == 'PUT':
            d = request.get_json()
            new_role = d.get('role')
            # --- VENTA AUTOMÁTICA (CFO) ---
            if u.role != 'pro' and new_role == 'pro':
                sale = SalesRecord(buyer_username=username, amount=10.0, concept="Upgrade to PRO") 
                db.session.add(sale)
            
            if new_role: u.role = new_role
            if 'subscriptionEndDate' in d: u.subscription_end = d['subscriptionEndDate']
            db.session.commit(); return jsonify({"message": "Actualizado"}), 200
        
        if request.method == 'DELETE':
            db.session.delete(u); db.session.commit()
            if username in ONLINE_USERS: del ONLINE_USERS[username]
            return jsonify({"message": "Eliminado"}), 200

    @app.route('/api/admin/delete-public-file/<file_id>', methods=['DELETE'])
    def admin_delete_public_file(file_id):
        if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg": "Deny"}), 403
        try:
            f = UserFile.query.get(file_id)
            if f:
                if f.storage_path: 
                    try: os.remove(os.path.join(UPLOAD_FOLDER, f.storage_path))
                    except: pass
                db.session.delete(f); db.session.commit(); return jsonify({"message": "Deleted"}), 200
            return jsonify({"message": "404"}), 404
        except: return jsonify({"error": "Error"}), 500

    @app.route('/api/my-files/<username>', methods=['GET'])
    def get_files(username):
        try:
            files = UserFile.query.filter_by(owner_username=username).all()
            file_list = []
            for f in files:
                file_list.append({
                    "id": f.id, "name": f.name, "type": f.type, "parentId": f.parent_id,
                    "size_bytes": f.size_bytes, "size": format_file_size(f.size_bytes),
                    "path": get_file_url(f.storage_path, 'uploads'),
                    "isPublished": f.is_published, "date": f.created_at.strftime('%Y-%m-%d'),
                    "verificationStatus": f.verification_status,
                    "monetization": {"enabled": f.price > 0, "price": f.price},
                    "description": f.description, "tags": f.tags.split(',') if f.tags else []
                })
            return jsonify(file_list), 200
        except: return jsonify([]), 200

    # --- ENDPOINT DE SUBIDA: FIX BIBLIOTECA (LECTURA DE isPublished) ---
    @app.route('/api/upload-file', methods=['POST'])
    def upload_user_file():
        try:
            if 'file' not in request.files: return jsonify({"message": "Falta archivo"}), 400
            file = request.files['file']; user_id = request.form.get('userId')
            parent_id = request.form.get('parentId')
            verification_status = request.form.get('verificationStatus', 'N/A')
            description = request.form.get('description', None)
            
            # --- FIX CRÍTICO: Detectar si se publica ---
            # El frontend envía "isPublished" como string "true" o "false"
            is_pub_str = request.form.get('isPublished', 'false').lower()
            is_published = (is_pub_str == 'true')
            
            filename = secure_filename(file.filename); unique_name = f"{uuid.uuid4().hex[:8]}_{filename}"
            save_path = os.path.join(UPLOAD_FOLDER, unique_name)
            file.save(save_path); file_size = os.path.getsize(save_path)
            
            if parent_id in ['null', 'undefined', '', None]:
                root_folder = UserFile.query.filter_by(owner_username=user_id, parent_id=None, type='folder').first()
                pid = root_folder.id if root_folder else None
            else:
                pid = parent_id
            
            new_file = UserFile(
                owner_username=user_id, name=filename, type='file', parent_id=pid, 
                size_bytes=file_size, storage_path=unique_name, verification_status=verification_status, 
                description=description, 
                is_published=is_published # <--- AHORA SÍ SE GUARDA EL ESTADO
            )
            db.session.add(new_file); db.session.commit()
            
            return jsonify({"message": "Subido", "newFile": {
                "id": new_file.id, "name": new_file.name, "type": "file", "parentId": pid, 
                "size_bytes": file_size, "size": format_file_size(file_size),
                "isPublished": new_file.is_published, 
                "date": new_file.created_at.strftime('%Y-%m-%d'),
                "verificationStatus": new_file.verification_status,
                "path": get_file_url(new_file.storage_path, 'uploads'),
                "monetization": {"enabled": False, "price": 0.0}, "description": description, "tags": []
            }}), 201
        except Exception as e: return jsonify({"message":str(e)}), 500

    @app.route('/api/create-folder', methods=['POST'])
    def create_folder():
        try:
            d = request.get_json(); pid = d.get('parentId')
            if not pid or pid == 'root':
                 r = UserFile.query.filter_by(owner_username=d.get('userId'), parent_id=None).first()
                 pid = r.id if r else None
            nf = UserFile(owner_username=d.get('userId'), name=d.get('name'), type='folder', parent_id=pid, size_bytes=0, verification_status='N/A')
            db.session.add(nf); db.session.commit()
            return jsonify({"newFolder":{"id":nf.id}}), 201
        except Exception as e: return jsonify({"message": str(e)}), 500

    @app.route('/api/delete-file', methods=['DELETE'])
    def delete_f():
        try: 
            d = request.get_json(); f = UserFile.query.get(d.get('fileId'))
            if f: 
                if f.type == 'file' and f.storage_path:
                    try:
                        file_path = os.path.join(UPLOAD_FOLDER, f.storage_path)
                        if os.path.exists(file_path): os.remove(file_path)
                    except: pass
                db.session.delete(f); db.session.commit()
                return jsonify({"message": "Deleted"}), 200
            return jsonify({"message": "File not found"}), 404
        except: db.session.rollback(); return jsonify({"message": "Error"}), 500

    @app.route('/api/update-file', methods=['POST'])
    def upd_file():
        try: 
            d = request.get_json(); f = UserFile.query.get(d.get('fileId'))
            if f: 
                u = d.get('updates', {})
                if 'name' in u: f.name = u['name']
                if 'isPublished' in u: f.is_published = u['isPublished']
                if 'description' in u: f.description = u['description']
                if 'tags' in u: f.tags = ",".join(u['tags'])
                if 'monetization' in u: f.price = float(u['monetization'].get('price', 0.0)) if u['monetization'].get('enabled', False) else 0.0
                db.session.commit()
                return jsonify({"updatedFile": { "id": f.id, "name": f.name }}), 200
            return jsonify({"msg": "404"}), 404
        except Exception as e: return jsonify({"message": str(e)}), 500

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

    @app.route('/api/documentos/<section>', methods=['GET'])
    def get_gestion_docs(section):
        docs = DocGestion.query.filter_by(section=section).all()
        return jsonify([{"id":d.id, "name":d.name, "type":d.type, "parent_id":d.parent_id, "url":get_file_url(os.path.join(section, d.storage_path), 'documentos_gestion') if d.storage_path else None} for d in docs if d.name != 'chat_data.json']), 200

    @app.route('/api/documentos/upload', methods=['POST'])
    def upload_gestion_doc():
        if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg":"Auth Fail"}), 403
        f = request.files['file']; sec = request.form['section']; pid = request.form.get('parentId')
        if pid in ['null','None']: pid = None
        fn = secure_filename(f.filename)
        sn = fn if fn == 'chat_data.json' else f"{uuid.uuid4().hex[:8]}_{fn}"
        sp = os.path.join(DOCS_FOLDER, sec, sn); os.makedirs(os.path.join(DOCS_FOLDER, sec), exist_ok=True)
        f.save(sp)
        if fn == 'chat_data.json': 
            old = DocGestion.query.filter_by(name=fn, section=sec).first()
            if old: db.session.delete(old)
        nd = DocGestion(name=fn, section=sec, size=os.path.getsize(sp), storage_path=sn, type='file', parent_id=pid)
        db.session.add(nd); db.session.commit()
        return jsonify({"message":"Subido"}), 201

    @app.route('/api/documentos/create-folder', methods=['POST'])
    def create_gestion_folder():
        if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg":"Auth Fail"}), 403
        d = request.get_json(); pid = d.get('parentId')
        if pid in ['null','None']: pid = None
        db.session.add(DocGestion(name=d.get('name'), section=d.get('section'), type='folder', parent_id=pid))
        db.session.commit(); return jsonify({"message":"Created"}), 201

    @app.route('/api/documentos/delete/<int:doc_id>', methods=['DELETE'])
    def delete_gestion_doc(doc_id):
        if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg":"Auth Fail"}), 403
        d = DocGestion.query.get(doc_id)
        if d:
            if d.storage_path:
                try: os.remove(os.path.join(DOCS_FOLDER, d.section, d.storage_path))
                except: pass
            db.session.delete(d); db.session.commit()
            return jsonify({"message":"Deleted"}), 200
        return jsonify({"message":"404"}), 404

    # --- SECCIÓN DIAGNÓSTICO: LOGS, INCIDENTES Y ACTUALIZACIONES ---
    
    @app.route('/api/logs/historical', methods=['POST', 'GET'])
    def logs(): 
        if request.method == 'GET':
            if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg": "Acceso denegado"}), 403
            logs = HistoricalLog.query.order_by(HistoricalLog.date.desc()).limit(100).all()
            return jsonify([{"id": l.id, "user": l.user, "ip": l.ip, "quality": l.quality, "date": l.date.isoformat(), "filename": l.filename} for l in logs]), 200
        
        user = request.headers.get('X-Username')
        f = request.files.get('log_file')
        fn = f"LOG_{user}_{uuid.uuid4().hex}.txt"
        if f: f.save(os.path.join(LOGS_FOLDER, fn))
        else: 
             with open(os.path.join(LOGS_FOLDER, fn), 'wb') as lf: lf.write(request.data)
        
        db.session.add(HistoricalLog(user=user, ip=request.headers.get('X-IP'), quality=request.headers.get('X-Quality'), filename=fn, storage_path=fn, date=datetime.datetime.utcnow()))
        db.session.commit()
        return jsonify({"status": "Log registrado"}), 201
            
    @app.route('/api/logs/incident', methods=['POST', 'GET'])
    def inc(): 
        if request.method == 'GET': 
             if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg": "Acceso denegado"}), 403
             rs = IncidentReport.query.order_by(IncidentReport.date.desc()).limit(100).all()
             return jsonify([{"id":r.id, "user":r.user, "message":r.message, "date":r.date.isoformat(), "filename":r.filename} for r in rs]), 200

        user = request.form.get('X-Username'); f = request.files.get('log_file'); fn = "N/A"
        if f: 
            fn = secure_filename(f.filename); sv = f"INCIDENT_{user}_{fn}"
            f.save(os.path.join(INCIDENTS_FOLDER, sv)); fn = sv
        
        db.session.add(IncidentReport(user=user, ip=request.form.get('X-IP'), message=request.form.get('message'), filename=fn, storage_path=fn, date=datetime.datetime.utcnow()))
        db.session.commit()
        return jsonify({"status":"Report Saved"}), 201
    
    @app.route('/api/logs/incidents', methods=['GET'])
    def incs_old(): return inc()

    # --- UPLOAD UPDATES (ORIGINAL ROUTE PRESERVED) ---
    @app.route('/api/updates/upload', methods=['POST'])
    def upload_update_file_route_new():
        fn = secure_filename(request.headers.get('X-Vercel-Filename'))
        sp = os.path.join(UPDATES_FOLDER, fn)
        with open(sp, 'wb') as f: f.write(request.data)
        
        exist = UpdateFile.query.filter_by(filename=fn).first()
        if exist: db.session.delete(exist); db.session.commit()
        
        new_update = UpdateFile(filename=fn, version="1.0", size=os.path.getsize(sp), storage_path=fn)
        db.session.add(new_update); db.session.commit()
        return jsonify({"message":"Uploaded"}), 201

    @app.route('/api/updates/list', methods=['GET'])
    def list_update_files_new():
        us = UpdateFile.query.order_by(UpdateFile.date.desc()).all()
        return jsonify([{"id":u.id, "name":u.filename, "version":u.version} for u in us]), 200

    @app.route('/api/updates/check', methods=['GET'])
    def chk_new():
        lat = UpdateFile.query.order_by(UpdateFile.date.desc()).first()
        if not lat: return jsonify({"message":"No updates"}), 404
        return jsonify({"version": lat.version, "download_url": get_file_url(lat.storage_path, 'updates')}), 200

    # --- RESET MAESTRO (LIMPIA LAS 3 CARPETAS + DB) ---
    @app.route('/api/admin/reset-diagnostics', methods=['DELETE'])
    def reset_diagnostics():
        if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg":"Auth Fail"}), 403
        try:
            db.session.query(HistoricalLog).delete()
            db.session.query(IncidentReport).delete()
            db.session.query(UpdateFile).delete()
            # Opcional: Borrar tablas de analytics si quieres resetear también eso
            # db.session.query(DownloadRecord).delete() 
            # db.session.query(SalesRecord).delete() 
            
            for folder in [LOGS_FOLDER, INCIDENTS_FOLDER, UPDATES_FOLDER, UPDATES_TRACKING_FOLDER]:
                for f in os.listdir(folder):
                    fp = os.path.join(folder, f)
                    if os.path.isfile(fp): os.remove(fp)
            
            db.session.commit()
            return jsonify({"status":"ok", "msg":"All diagnostics purged"}), 200
        except Exception as e: db.session.rollback(); return jsonify({"error":str(e)}), 500

    @app.route('/api/chat/history', methods=['GET'])
    def get_chat():
        try: 
            p = os.path.join(DOCS_FOLDER, 'operaciones', 'chat_data.json')
            if not os.path.exists(p): 
                with open(p, 'w') as f: json.dump([], f)
            with open(p, 'r') as f: return jsonify(json.load(f)), 200
        except: return jsonify([]), 200

    @app.route('/api/chat/send', methods=['POST'])
    def send_chat():
        try:
            p = os.path.join(DOCS_FOLDER, 'operaciones', 'chat_data.json')
            d = request.get_json(); h = []
            if os.path.exists(p): 
                with open(p, 'r') as f: h = json.load(f)
            h.append({"user":d.get("user","?"), "msg":d.get("msg",""), "date":datetime.datetime.now().strftime("%H:%M")})
            with open(p, 'w') as f: json.dump(h[-50:], f)
            return jsonify({"status":"OK"}), 200
        except: return jsonify({"error":"Fail"}), 500

    # Worker Integration (FIXED SYNTAX HERE)
    CONV_FILE = os.path.join(BASE_DIR, 'server_conversion_records.json')
    def load_recs(): 
        if not os.path.exists(CONV_FILE): return []
        try: 
            with open(CONV_FILE, 'r') as f: return json.load(f)
        except: return []
    
    def save_conversion_records(data):
        try: 
            with open(CONV_FILE, 'w') as f: 
                json.dump(data, f)
        except: pass

    @app.route('/api/worker/check-permission', methods=['POST'])
    def w_check():
        if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"allow":False}), 403
        return jsonify({"allow":True}), 200 

    @app.route('/api/worker/log-success', methods=['POST'])
    def w_log():
        if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"status":"Fail"}), 403
        r = load_recs(); r.append(request.get_json())
        with open(CONV_FILE, 'w') as f: json.dump(r[-1000:], f)
        return jsonify({"status":"Recorded"}), 201

    @app.route('/api/worker/records', methods=['GET'])
    def w_get(): return jsonify({"records": load_recs()}), 200

    @app.route('/admin/create_tables', methods=['GET'])
    def create_tbls():
        if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg": "No"}), 403
        with app.app_context(): db.create_all()
        return jsonify({"msg": "OK"}), 200

    return app

if __name__ == '__main__': 
    app = create_app()
    # FORZAR CREACIÓN DE TABLAS AL INICIAR (CFO/COO)
    with app.app_context():
        db.create_all()
        print(">>> DB SYNC OK <<<")
    socketio.run(app, host='0.0.0.0', port=7860)
