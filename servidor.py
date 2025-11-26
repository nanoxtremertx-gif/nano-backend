# --- servidor.py --- (v22.0 - MAESTRO FINAL UNIFICADO: CORE + CHAT + WORKER S4)
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
    print(">>> INICIANDO SERVIDOR MAESTRO (v22.0 - Full Integration) <<<")

    # --- 5. CONFIGURACIÓN DE APP ---
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # OPTIMIZACIÓN DB NEON (Anti-Disconnect)
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        "pool_pre_ping": True,
        "pool_recycle": 300,
        "pool_timeout": 30,
        "pool_size": 10,
        "max_overflow": 20
    }

    try:
        raw_url = os.environ.get('NEON_URL')
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
        print(f"!!! ERROR CRÍTICO AL CONFIGURAR DB: {e}")
        print("!!! USANDO SQLITE COMO FALLBACK.")
        app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///fallback.db"
        db_status = "SQLite (FALLBACK)"

    # --- 6. INICIALIZACIÓN DE EXTENSIONES ---
    cors.init_app(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)
    socketio.init_app(app, cors_allowed_origins="*")
    bcrypt.init_app(app)
    db.init_app(app) 

    # --- 7. DIRECTORIOS ---
    BASE_DIR = os.getcwd()
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    AVATARS_FOLDER = os.path.join(UPLOAD_FOLDER, 'avatars')
    LOGS_FOLDER = os.path.join(BASE_DIR, 'logs_historical')
    UPDATES_FOLDER = os.path.join(BASE_DIR, 'updates')
    INCIDENTS_FOLDER = os.path.join(BASE_DIR, 'logs_incidents')
    DOCS_FOLDER = os.path.join(BASE_DIR, 'documentos_gestion')
    BIBLIOTECA_PUBLIC_FOLDER = os.path.join(BASE_DIR, 'biblioteca_publica') 

    # Crear carpetas
    for folder in [UPLOAD_FOLDER, AVATARS_FOLDER, LOGS_FOLDER, UPDATES_FOLDER, INCIDENTS_FOLDER, DOCS_FOLDER, BIBLIOTECA_PUBLIC_FOLDER]:
        os.makedirs(folder, exist_ok=True)

    SUB_DOC_FOLDERS = ['desarrollo', 'gestion', 'operaciones']
    for sub in SUB_DOC_FOLDERS:
        os.makedirs(os.path.join(DOCS_FOLDER, sub), exist_ok=True)

    # --- Funciones Helper ---
    def emit_online_count():
        try:
            count = len(ONLINE_USERS)
            socketio.emit('update_online_count', {'count': count})
        except Exception as e:
            print(f"Error al emitir conteo: {e}")

    def get_file_url(filename, folder_route='uploads'):
        if not filename: return None
        return f"{request.host_url}{folder_route}/{filename}"

    def format_file_size(size_bytes):
        if size_bytes is None: return "N/A" 
        if size_bytes < 1024: return f"{size_bytes} Bytes"
        if size_bytes < 1048576: return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1073741824: return f"{size_bytes / 1048576:.2f} MB"
        else: return f"{size_bytes / 1073741824:.2f} GB"

    # --- RUTA PARA UPTIMEROBOT (LIGERA) ---
    @app.route('/health')
    def health_check_uptime():
        return "ALIVE", 200

    # --- RUTAS PÚBLICAS Y HEALTH CHECK ---
    @app.route('/')
    def health_check(): 
        return jsonify({"status": "v22.0 ONLINE (Maestro)", "db": db_status}), 200

    @app.route('/uploads/<path:filename>')
    def download_user_file(filename): return send_from_directory(UPLOAD_FOLDER, filename)
    @app.route('/uploads/avatars/<path:filename>')
    def download_avatar(filename): return send_from_directory(AVATARS_FOLDER, filename)
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
    
    @app.route('/admin/create_tables', methods=['GET'])
    def create_tables():
        if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY:
            return jsonify({"msg": "Acceso denegado"}), 403
        try:
            with app.app_context():
                db.create_all()
            return jsonify({"message": "Tablas creadas (o ya existían)."}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # --- SOCKETS ---
    @socketio.on('connect')
    def handle_connect():
        emit('update_online_count', {'count': len(ONLINE_USERS)})

    @socketio.on('disconnect')
    def handle_disconnect():
        pass

    # --- AUTH ---
    @app.route('/api/register', methods=['POST'])
    def register():
        d = request.get_json()
        if User.query.filter_by(username=d.get('username')).first(): return jsonify({"message": "Usuario ocupado"}), 409
        if User.query.filter_by(email=d.get('email')).first(): return jsonify({"message": "Email ocupado"}), 409
        
        new_user = User(
            username=d.get('username'), 
            hash=bcrypt.generate_password_hash(d.get('password')).decode('utf-8'), 
            email=d.get('email'), 
            identificador=d.get('identificador'), 
            role="gratis", 
            fingerprint=d.get('username').lower(),
            display_name=d.get('username').capitalize(),
            bio="Nuevo usuario en Nano Xtreme",
            avatar="/user.ico"
        )
        
        try:
            db.session.add(new_user)
            db.session.commit()
            
            new_folder = UserFile(owner_username=d.get('username'), name="Archivos de Usuario", type='folder', parent_id=None, size_bytes=0, verification_status='N/A')
            db.session.add(new_folder)
            db.session.commit()

            ONLINE_USERS[d.get('username')] = datetime.datetime.utcnow()
            emit_online_count()
            return jsonify({"message": "Registrado"}), 201
            
        except Exception as e: 
            db.session.rollback()
            return jsonify({"message": f"Error de BD: {str(e)}"}), 500

    @app.route('/api/login', methods=['POST'])
    def login():
        d = request.get_json()
        u = User.query.filter_by(username=d.get('username')).first()
        
        if u and bcrypt.check_password_hash(u.hash, d.get('password')):
            try:
                root_folder = UserFile.query.filter_by(owner_username=u.username, parent_id=None, name="Archivos de Usuario").first()
                if not root_folder:
                    new_root = UserFile(owner_username=u.username, name="Archivos de Usuario", type='folder', parent_id=None, size_bytes=0, verification_status='N/A')
                    db.session.add(new_root); db.session.commit()
            except Exception as e:
                db.session.rollback(); print(f"Error carpeta raíz: {e}")

            ONLINE_USERS[u.username] = datetime.datetime.utcnow()
            emit_online_count()
            
            return jsonify({
                "message": "OK", 
                "user": {
                    "username": u.username, "email": u.email, "role": u.role, "identificador": u.identificador, "isAdmin": u.role == 'admin',
                    "displayName": getattr(u, 'display_name', u.username),
                    "bio": getattr(u, 'bio', ''),
                    "avatar": getattr(u, 'avatar', '/user.ico')
                }
            }), 200
            
        return jsonify({"message": "Credenciales inválidas"}), 401

    @app.route('/api/update-profile', methods=['POST'])
    def update_profile():
        try:
            username = request.form.get('username')
            display_name = request.form.get('displayName')
            bio = request.form.get('bio')
            file = request.files.get('avatar')

            if not username: return jsonify({"success": False, "message": "Username requerido"}), 400
            user = User.query.filter_by(username=username).first()
            if not user: return jsonify({"success": False, "message": "Usuario no encontrado"}), 404

            if display_name: user.display_name = display_name
            if bio: user.bio = bio

            if file:
                filename = secure_filename(file.filename)
                unique_name = f"avatar_{uuid.uuid4().hex[:8]}_{filename}"
                save_path = os.path.join(AVATARS_FOLDER, unique_name)
                file.save(save_path)
                user.avatar = f"/uploads/avatars/{unique_name}"

            db.session.commit()

            return jsonify({
                "success": True,
                "updatedUser": {
                    "username": user.username, "email": user.email, "role": user.role, "identificador": user.identificador,
                    "displayName": user.display_name, "bio": user.bio, "avatar": user.avatar
                }
            }), 200

        except Exception as e:
            db.session.rollback()
            return jsonify({"success": False, "message": str(e)}), 500

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
            emit_online_count()
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
            emit_online_count()
            
        return jsonify({"count": len(active_list), "users": active_list}), 200

    # --- ADMIN / ARCHIVOS / GESTION ---
    @app.route('/api/admin/users', methods=['GET'])
    def admin_list():
        if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg": "Acceso denegado"}), 403
        try:
            users = User.query.all(); user_list = []
            for u in users: user_list.append({"username": u.username, "email": u.email, "role": u.role, "identificador": u.identificador, "subscriptionEndDate": u.subscription_end})
            return jsonify(user_list), 200
        except Exception as e: return jsonify({"error": str(e)}), 500

    @app.route('/api/admin/users/<username>', methods=['PUT', 'DELETE'])
    def admin_modify(username):
        if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg": "No"}), 403
        u = User.query.filter_by(username=username).first()
        if not u: return jsonify({"msg": "404"}), 404
        
        if request.method == 'PUT':
            d = request.get_json()
            if 'role' in d: u.role = d['role']
            if 'subscriptionEndDate' in d: u.subscription_end = d['subscriptionEndDate']
            db.session.commit(); return jsonify({"message": "Actualizado"}), 200
        
        if request.method == 'DELETE':
            db.session.delete(u); db.session.commit()
            if username in ONLINE_USERS: del ONLINE_USERS[username]
            return jsonify({"message": "Eliminado"}), 200

    @app.route('/api/admin/delete-public-file/<file_id>', methods=['DELETE'])
    def admin_delete_public_file(file_id):
        if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg": "Acceso denegado"}), 403
        try:
            f = UserFile.query.get(file_id)
            if not f: return jsonify({"message": "File not found"}), 404
            
            if f.storage_path:
                try: os.remove(os.path.join(UPLOAD_FOLDER, f.storage_path))
                except: pass

            db.session.delete(f); db.session.commit()
            return jsonify({"message": "Eliminado"}), 200
        except Exception as e: return jsonify({"message": f"Error: {str(e)}"}), 500

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

    @app.route('/api/upload-file', methods=['POST'])
    def upload_user_file():
        try:
            if 'file' not in request.files: return jsonify({"message": "Falta archivo"}), 400
            file = request.files['file']; user_id = request.form.get('userId')
            parent_id = request.form.get('parentId'); verification_status = request.form.get('verificationStatus', 'N/A')
            
            filename = secure_filename(file.filename); unique_name = f"{uuid.uuid4().hex[:8]}_{filename}"
            save_path = os.path.join(UPLOAD_FOLDER, unique_name)
            file.save(save_path); file_size = os.path.getsize(save_path)
            
            # Lógica Anti-Huérfanos (S4)
            if parent_id == 'null' or parent_id == 'undefined' or not parent_id:
                root_folder = UserFile.query.filter_by(owner_username=user_id, parent_id=None, type='folder').first()
                parent_id = root_folder.id if root_folder else None
            
            new_file = UserFile(owner_username=user_id, name=filename, type='file', parent_id=parent_id, size_bytes=file_size, storage_path=unique_name, verification_status=verification_status)
            db.session.add(new_file); db.session.commit()
            
            return jsonify({"message": "Subido", "newFile": {
                "id": new_file.id, "name": new_file.name, "type": "file", "parentId": parent_id, 
                "size_bytes": file_size, "size": format_file_size(file_size),
                "isPublished": False, "date": new_file.created_at.strftime('%Y-%m-%d'),
                "verificationStatus": new_file.verification_status,
                "path": get_file_url(new_file.storage_path, 'uploads'),
                "monetization": {"enabled": False, "price": 0.0}, "description": "", "tags": []
            }}), 201
        except Exception as e: return jsonify({"message": str(e)}), 500

    @app.route('/api/create-folder', methods=['POST'])
    def create_folder():
        try:
            d = request.get_json(); parent_id = d.get('parentId')
            if parent_id == 'root' or not parent_id:
                root_folder = UserFile.query.filter_by(owner_username=d.get('userId'), parent_id=None, name="Archivos de Usuario").first()
                parent_id = root_folder.id if root_folder else None
            nf = UserFile(owner_username=d.get('userId'), name=d.get('name'), type='folder', parent_id=parent_id, size_bytes=0, verification_status='N/A')
            db.session.add(nf); db.session.commit()
            return jsonify({"newFolder": {"id": nf.id, "name": nf.name, "type": "folder", "parentId": nf.parent_id}}), 201
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

    # --- INSPECCIÓN BÁSICA DE AUTOR ---
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

    # --- DOCUMENTOS Y LOGS (CON CHAT OCULTO) ---
    @app.route('/api/documentos/<section>', methods=['GET'])
    def get_gestion_docs(section):
        try:
            docs = DocGestion.query.filter_by(section=section).all()
            visible_docs = []
            for d in docs:
                if d.name == 'chat_data.json': continue 
                visible_docs.append({
                    "id": d.id, "name": d.name, "size": d.size, 
                    "url": get_file_url(os.path.join(section, d.storage_path), 'documentos_gestion') if d.storage_path else None, 
                    "type": d.type, "parent_id": d.parent_id,
                    "date": d.created_at.isoformat() if hasattr(d, 'created_at') else datetime.datetime.utcnow().isoformat()
                })
            return jsonify(visible_docs), 200
        except: return jsonify([]), 200

    @app.route('/api/documentos/upload', methods=['POST'])
    def upload_gestion_doc():
        if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg": "Acceso denegado"}), 403
        try:
            file = request.files['file']; section = request.form['section']; parent_id = request.form.get('parentId')
            if parent_id in ['null', 'None']: parent_id = None
            filename = secure_filename(file.filename)
            
            if filename == 'chat_data.json': storage_name = filename
            else: storage_name = f"{uuid.uuid4().hex[:8]}_{filename}"
            
            save_path = os.path.join(DOCS_FOLDER, section, storage_name)
            os.makedirs(os.path.join(DOCS_FOLDER, section), exist_ok=True)
            file.save(save_path); file_size = os.path.getsize(save_path)
            
            if filename == 'chat_data.json':
                 old_chat = DocGestion.query.filter_by(name='chat_data.json', section=section).first()
                 if old_chat: db.session.delete(old_chat)
            
            new_doc = DocGestion(name=filename, section=section, size=file_size, storage_path=storage_name, type='file', parent_id=parent_id)
            db.session.add(new_doc); db.session.commit()
            return jsonify({"message": "Subido"}), 201
        except Exception as e: return jsonify({"message": str(e)}), 500

    @app.route('/api/documentos/create-folder', methods=['POST'])
    def create_gestion_folder():
        if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg": "Acceso denegado"}), 403
        try:
            d = request.get_json(); parent_id = d.get('parentId')
            if parent_id in ['null', 'None']: parent_id = None
            new_folder = DocGestion(name=d.get('name'), section=d.get('section', 'gestion'), type='folder', parent_id=parent_id)
            db.session.add(new_folder); db.session.commit()
            return jsonify({"message": "Carpeta creada"}), 201
        except Exception as e: return jsonify({"message": str(e)}), 500

    @app.route('/api/documentos/delete/<int:doc_id>', methods=['DELETE'])
    def delete_gestion_doc(doc_id):
        if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg": "Acceso denegado"}), 403
        try:
            doc = DocGestion.query.get(doc_id)
            if doc:
                if doc.type == 'file' and doc.storage_path:
                     try: os.remove(os.path.join(DOCS_FOLDER, doc.section, doc.storage_path))
                     except: pass
                db.session.delete(doc); db.session.commit()
                return jsonify({"message": "Eliminado"}), 200
            return jsonify({"message": "No encontrado"}), 404
        except Exception as e: return jsonify({"message": str(e)}), 500

    @app.route('/api/logs/historical', methods=['POST', 'GET'])
    def logs(): 
        if request.method == 'GET':
            if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg": "Acceso denegado"}), 403
            logs = HistoricalLog.query.order_by(HistoricalLog.date.desc()).limit(100).all()
            return jsonify([{"id": l.id, "user": l.user, "ip": l.ip, "quality": l.quality, "date": l.date.isoformat()} for l in logs]), 200
        user = request.headers.get('X-Username'); filename_ref = f"LOG_{user}_{uuid.uuid4().hex}.log"
        new_log = HistoricalLog(user=user, ip=request.headers.get('X-IP'), quality=request.headers.get('X-Quality'), filename=filename_ref, storage_path=filename_ref, date=datetime.datetime.utcnow())
        db.session.add(new_log); db.session.commit()
        return jsonify({"status": "Log registrado"}), 201
            
    @app.route('/api/logs/incident', methods=['POST'])
    def inc(): 
        user = request.form.get('X-Username'); file = request.files.get('log_file'); filename = secure_filename(file.filename) if file else "N/A"
        new_incident = IncidentReport(user=user, ip=request.form.get('X-IP'), message=request.form.get('message'), filename=filename, storage_path=f"INCIDENT_{user}_{filename}", date=datetime.datetime.utcnow())
        db.session.add(new_incident); db.session.commit()
        return jsonify({"status":"Reporte recibido"}), 201

    @app.route('/api/logs/incidents', methods=['GET'])
    def incs(): 
        if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg": "Acceso denegado"}), 403
        reports = IncidentReport.query.order_by(IncidentReport.date.desc()).limit(100).all()
        return jsonify([{"id": r.id, "user": r.user, "message": r.message, "date": r.date.isoformat()} for r in reports]), 200

    @app.route('/api/updates/upload', methods=['POST'])
    def upload_update_file_route():
        filename = secure_filename(request.headers.get('X-Vercel-Filename'))
        save_path = os.path.join(UPDATES_FOLDER, filename); 
        with open(save_path, 'wb') as f: f.write(request.data)
        existing = UpdateFile.query.filter_by(filename=filename).first()
        if existing: db.session.delete(existing); db.session.commit()
        new_update = UpdateFile(filename=filename, version="1.0", size=os.path.getsize(save_path), storage_path=filename)
        db.session.add(new_update); db.session.commit()
        return jsonify({"message": "Actualización subida"}), 201

    @app.route('/api/updates/list', methods=['GET'])
    def list_update_files():
        updates = UpdateFile.query.order_by(UpdateFile.date.desc()).all()
        return jsonify([{"id": u.id, "name": u.filename, "version": u.version} for u in updates]), 200

    @app.route('/api/updates/check', methods=['GET'])
    def chk():
        latest = UpdateFile.query.order_by(UpdateFile.date.desc()).first()
        if not latest: return jsonify({"message":"No updates"}), 404
        return jsonify({"version": latest.version, "download_url": get_file_url(latest.storage_path, 'updates')}), 200

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
        except: return jsonify([]), 200

    @app.route('/api/biblioteca/profiles', methods=['GET'])
    def get_public_profiles():
        try:
            users = User.query.all(); profile_list = []
            for u in users: profile_list.append({"username": u.username.lower(), "displayName": getattr(u, 'display_name', u.username.capitalize()), "avatar": getattr(u, 'avatar', '/user.ico')})
            return jsonify(profile_list), 200
        except: return jsonify([]), 200

    # --- ENDPOINTS ESPECÍFICOS PARA EL CHAT ---
    @app.route('/api/chat/history', methods=['GET'])
    def get_chat_history_api():
        try:
            path = os.path.join(DOCS_FOLDER, 'operaciones', 'chat_data.json')
            if not os.path.exists(path):
                 default = [{"user":"System","msg":"Chat Iniciado","date":datetime.datetime.now().strftime("%H:%M")}]
                 with open(path, 'w') as f: json.dump(default, f)
                 return jsonify(default), 200
            with open(path, 'r') as f: return jsonify(json.load(f)), 200
        except: return jsonify([]), 200

    @app.route('/api/chat/send', methods=['POST'])
    def send_chat_msg_api():
        try:
            path = os.path.join(DOCS_FOLDER, 'operaciones', 'chat_data.json')
            data = request.get_json()
            history = []
            if os.path.exists(path):
                with open(path, 'r') as f: history = json.load(f)
            new_msg = {"user": data.get("user", "Anon"), "msg": data.get("msg", ""), "date": datetime.datetime.now().strftime("%H:%M")}
            history.append(new_msg)
            if len(history) > 50: history = history[-50:]
            with open(path, 'w') as f: json.dump(history, f, indent=2)
            return jsonify({"status": "OK", "history": history}), 200
        except Exception as e: return jsonify({"error": str(e)}), 500

    @app.route('/admin/fix_doc_table', methods=['GET'])
    def fix_doc_table_structure():
        if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: 
            return jsonify({"msg": "Acceso denegado"}), 403
        try:
            with app.app_context():
                print(">>> BORRANDO TABLA ANTIGUA doc_gestion...")
                db.session.execute(text('DROP TABLE IF EXISTS doc_gestion CASCADE;'))
                db.session.commit()
                print(">>> RECREANDO TABLAS...")
                db.create_all()
            return jsonify({"message": "ÉXITO: Tabla doc_gestion reconstruida."}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({"error": f"Fallo crítico: {str(e)}"}), 500
    
    # ===============================================================
    # 🔗 ZONA DE INTEGRACIÓN WORKER (S4)
    # ===============================================================
    CONVERSION_RECORDS_FILE = os.path.join(BASE_DIR, 'server_conversion_records.json')

    def load_conversion_records():
        if not os.path.exists(CONVERSION_RECORDS_FILE): return []
        try:
            with open(CONVERSION_RECORDS_FILE, 'r') as f: return json.load(f)
        except: return []

    def save_conversion_records(data):
        try:
            with open(CONVERSION_RECORDS_FILE, 'w') as f: json.dump(data, f)
        except: pass

    @app.route('/api/worker/check-permission', methods=['POST'])
    def worker_check_permission():
        if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"allow": False, "reason": "Auth Fail"}), 403
        data = request.get_json()
        client_id = data.get('singleUseClientId')
        cooldown_hours = 48
        records = load_conversion_records()
        user_records = sorted([r for r in records if r.get("singleUseClientId") == client_id], key=lambda x: x["timestamp"], reverse=True)
        if not user_records: return jsonify({"allow": True}), 200
        try:
            last_time = datetime.datetime.fromisoformat(user_records[0]["timestamp"].replace("Z", ""))
            unlock_time = last_time + timedelta(hours=cooldown_hours)
            if datetime.datetime.utcnow() < unlock_time:
                remaining = str(unlock_time - datetime.datetime.utcnow()).split('.')[0]
                return jsonify({"allow": False, "reason": f"Cooldown activo. Espera: {remaining}"}), 200
        except: return jsonify({"allow": True}), 200
        return jsonify({"allow": True}), 200

    @app.route('/api/worker/log-success', methods=['POST'])
    def worker_log_success():
        if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"status": "Fail"}), 403
        new_record = request.get_json()
        records = load_conversion_records()
        records.append(new_record)
        if len(records) > 1000: records = records[-1000:]
        save_conversion_records(records)
        return jsonify({"status": "Recorded"}), 201

    @app.route('/api/worker/records', methods=['GET'])
    def get_worker_records():
        return jsonify({"records": load_conversion_records()}), 200
            
    return app

if __name__ == '__main__': 
    app = create_app()
    socketio.run(app, host='0.0.0.0', port=7860)
