# --- servidor.py --- (v24.0 - MAESTRO FINAL: BASE v22.0 + CFO + RESET + 3 CARPETAS + S4)
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
# 🆕 MODELOS PARA AUDITORÍA CFO (AGREGADOS)
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
# ==========================================

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
    print(">>> INICIANDO SERVIDOR MAESTRO (v24.0 - Sinergia Completa: Worker + CFO + Reset) <<<")

    # --- 5. CONFIGURACIÓN DE APP ---
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # --- FIX VITAL: MOTOR DB ANTI-DESCONEXIÓN ---
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
            print("⚠️ NEON_URL no encontrada. Usando SQLite local.")
            app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///local_fallback.db"
            db_status = "SQLite (Local)"
        else:
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
        app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///fallback.db"
        db_status = "SQLite (FALLBACK)"

    # --- 6. INICIALIZACIÓN DE EXTENSIONES ---
    cors.init_app(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)
    socketio.init_app(app, cors_allowed_origins="*")
    bcrypt.init_app(app)
    db.init_app(app)

    # --- 7. DIRECTORIOS (MODIFICADO PARA 3 CARPETAS DE LLEGADA) ---
    BASE_DIR = os.getcwd()
    
    # Carpetas Base
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    AVATARS_FOLDER = os.path.join(UPLOAD_FOLDER, 'avatars')
    DOCS_FOLDER = os.path.join(BASE_DIR, 'documentos_gestion')
    BIBLIOTECA_PUBLIC_FOLDER = os.path.join(BASE_DIR, 'biblioteca_publica')

    # >> LAS 3 CARPETAS DE DIAGNÓSTICO (ESTRUCTURA SOLICITADA) <<
    LOGS_FOLDER = os.path.join(BASE_DIR, 'logs_historical')       # 1. Logs Históricos
    INCIDENTS_FOLDER = os.path.join(BASE_DIR, 'logs_incidents')   # 2. Logs Incidentes
    UPDATES_FOLDER = os.path.join(BASE_DIR, 'updates_system')     # 3. Actualizaciones (Sistema)
    
    # >> SUBCARPETA DE TRACKING (Dentro de Updates) <<
    UPDATES_TRACKING_FOLDER = os.path.join(UPDATES_FOLDER, 'download_tracking')

    # Crear todas las carpetas
    ALL_FOLDERS = [
        UPLOAD_FOLDER, AVATARS_FOLDER, DOCS_FOLDER, BIBLIOTECA_PUBLIC_FOLDER,
        LOGS_FOLDER, INCIDENTS_FOLDER, UPDATES_FOLDER, UPDATES_TRACKING_FOLDER
    ]
    for folder in ALL_FOLDERS:
        os.makedirs(folder, exist_ok=True)

    SUB_DOC_FOLDERS = ['desarrollo', 'gestion', 'operaciones']
    for sub in SUB_DOC_FOLDERS:
        os.makedirs(os.path.join(DOCS_FOLDER, sub), exist_ok=True)

    # --- HELPER: TRACKER DB (NUEVO PARA EL CFO) ---
    def track_download_db(filename, category):
        """Registra la descarga en la base de datos para el CFO."""
        try:
            # Detectar usuario: Query param > Header > Anon
            user = request.args.get('user') or request.headers.get('X-Username') or "Anonimo"
            ip = request.remote_addr
            rec = DownloadRecord(user_id=user, filename=filename, category=category, ip_address=ip)
            db.session.add(rec)
            db.session.commit()
        except Exception as e:
            print(f"Error DB Tracking: {e}")

    # --- Funciones Helper Originales ---
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
        return jsonify({"status": "v24.0 ONLINE (Maestro)", "db": db_status}), 200

    # --- RUTAS DE DESCARGA (CON TRACKING INTEGRADO) ---
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
    
    # --- RUTA DE DESCARGA DE ACTUALIZACIONES (CARPETA 3 + TRACKING DOBLE) ---
    @app.route('/updates/<path:filename>')
    def download_update_file(filename):
        # 1. Registrar en DB para CFO (NUEVO)
        track_download_db(filename, 'system_update')

        # 2. Registrar en TXT (Carpeta interna para rastreo físico)
        try:
            requester_ip = request.remote_addr
            requester_user = request.args.get('user', 'Anonimo')
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_line = f"[{timestamp}] IP: {requester_ip} - User: {requester_user} - Downloaded: {filename}\n"
            
            tracking_file = os.path.join(UPDATES_TRACKING_FOLDER, f"track_{filename}.txt")
            with open(tracking_file, "a") as f:
                f.write(log_line)
        except: pass

        # 3. Entregar archivo desde updates_system
        return send_from_directory(UPDATES_FOLDER, filename)

    # --- API CFO ANALYTICS (NUEVO ENDPOINT) ---
    @app.route('/api/cfo/analytics', methods=['GET'])
    def get_cfo_analytics():
        if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg": "Deny"}), 403
        try:
            # Totales
            total_dls = DownloadRecord.query.count()
            total_sales = db.session.query(db.func.sum(SalesRecord.amount)).scalar() or 0.0
            
            # Top Usuarios (Más descargas)
            top = db.session.query(DownloadRecord.user_id, db.func.count(DownloadRecord.id))\
                    .group_by(DownloadRecord.user_id)\
                    .order_by(db.func.count(DownloadRecord.id).desc()).limit(5).all()
            top_users = [{"user": r[0], "count": r[1]} for r in top]
            
            # Últimas descargas (Log vivo)
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
        if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY:
            return jsonify({"msg": "Acceso denegado"}), 403
        try:
            with app.app_context():
                db.create_all() # Crea todas las tablas (viejas y nuevas)
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

    # --- ADMIN / ARCHIVOS / GESTION (Rutas estándar) ---
    @app.route('/api/admin/users', methods=['GET'])
    def admin_list():
        if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg": "Acceso denegado"}), 403
        try:
            users = User.query.all(); user_list = []
            for u in users: user_list.append({"username": u.username, "email": u.email, "role": u.role, "identificador": u.identificador, "subscriptionEndDate": u.subscription_end})
            return jsonify(user_list), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route('/api/admin/users/<username>', methods=['PUT', 'DELETE'])
    def admin_modify(username):
        if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg": "No"}), 403
        u = User.query.filter_by(username=username).first()
        if not u: return jsonify({"msg": "404"}), 404
        
        if request.method == 'PUT':
            d = request.get_json()
            new_role = d.get('role')
            # --- DETECCIÓN DE VENTA AUTOMÁTICA (NUEVO) ---
            if u.role != 'pro' and new_role == 'pro':
                sale = SalesRecord(buyer_username=username, amount=10.0, concept="Upgrade to PRO") 
                db.session.add(sale)
            # -------------------------------------
            if new_role: u.role = new_role
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

    # --- ENDPOINT DE SUBIDA: FIX ORPHAN FILES ---
    @app.route('/api/upload-file', methods=['POST'])
    def upload_user_file():
        try:
            if 'file' not in request.files: return jsonify({"message": "Falta archivo"}), 400
            file = request.files['file']; user_id = request.form.get('userId')
            parent_id = request.form.get('parentId')
            verification_status = request.form.get('verificationStatus', 'N/A')
            description = request.form.get('description', None)
            
            filename = secure_filename(file.filename); unique_name = f"{uuid.uuid4().hex[:8]}_{filename}"
            save_path = os.path.join(UPLOAD_FOLDER, unique_name)
            file.save(save_path); file_size = os.path.getsize(save_path)
            
            # --- FIX: Si parentId es nulo, buscar la carpeta raíz ---
            if parent_id in ['null', 'undefined', '', None]:
                root_folder = UserFile.query.filter_by(owner_username=user_id, parent_id=None, type='folder').first()
                if root_folder:
                    parent_id = root_folder.id
                else:
                    parent_id = None
            # --------------------------------------------------------
            
            new_file = UserFile(owner_username=user_id, name=filename, type='file', parent_id=parent_id, size_bytes=file_size, storage_path=unique_name, verification_status=verification_status, description=description)
            db.session.add(new_file); db.session.commit()
            
            return jsonify({"message": "Subido", "newFile": {
                "id": new_file.id, "name": new_file.name, "type": "file", "parentId": parent_id, 
                "size_bytes": file_size, "size": format_file_size(file_size),
                "isPublished": False, "date": new_file.created_at.strftime('%Y-%m-%d'),
                "verificationStatus": new_file.verification_status,
                "path": get_file_url(new_file.storage_path, 'uploads'),
                "monetization": {"enabled": False, "price": 0.0}, "description": description, "tags": []
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
            # MODIFICACIÓN: FILTRAMOS 'chat_data.json' PARA QUE NO SE VEA EN LAS LISTAS
            docs = DocGestion.query.filter_by(section=section).all()
            
            visible_docs = []
            for d in docs:
                if d.name == 'chat_data.json': continue # OCULTAR ARCHIVO DE CHAT
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
            
            # Si es el chat, no usar UUID para sobreescribir siempre el mismo
            if filename == 'chat_data.json': storage_name = filename
            else: storage_name = f"{uuid.uuid4().hex[:8]}_{filename}"
            
            save_path = os.path.join(DOCS_FOLDER, section, storage_name)
            os.makedirs(os.path.join(DOCS_FOLDER, section), exist_ok=True)
            file.save(save_path); file_size = os.path.getsize(save_path)
            
            # Si es chat, borramos entrada vieja en DB para evitar duplicados visuales (aunque esté oculto)
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
        # GET: Listar logs para el COO
        if request.method == 'GET':
            if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg": "Acceso denegado"}), 403
            logs = HistoricalLog.query.order_by(HistoricalLog.date.desc()).limit(100).all()
            return jsonify([{"id": l.id, "user": l.user, "ip": l.ip, "quality": l.quality, "date": l.date.isoformat(), "filename": l.filename} for l in logs]), 200
        
        # POST: Guardar log en carpeta 1 (logs_historical)
        user = request.headers.get('X-Username')
        file = request.files.get('log_file')
        
        if file:
            filename_ref = f"LOG_{user}_{uuid.uuid4().hex}.txt"
            save_path = os.path.join(LOGS_FOLDER, filename_ref)
            file.save(save_path)
        else:
            filename_ref = f"LOG_{user}_{uuid.uuid4().hex}.txt"
            if request.data:
                with open(os.path.join(LOGS_FOLDER, filename_ref), 'wb') as f: f.write(request.data)
            else: filename_ref = "N/A"

        new_log = HistoricalLog(user=user, ip=request.headers.get('X-IP'), quality=request.headers.get('X-Quality'), filename=filename_ref, storage_path=filename_ref, date=datetime.datetime.utcnow())
        db.session.add(new_log); db.session.commit()
        return jsonify({"status": "Log registrado"}), 201
            
    @app.route('/api/logs/incident', methods=['POST', 'GET'])
    def inc():
        # GET: Incidentes (Nuevo para COO)
        if request.method == 'GET': 
             if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg": "Acceso denegado"}), 403
             rs = IncidentReport.query.order_by(IncidentReport.date.desc()).limit(100).all()
             return jsonify([{"id":r.id, "user":r.user, "message":r.message, "date":r.date.isoformat(), "filename":r.filename} for r in rs]), 200

        # POST: Guardar incidente en carpeta 2 (logs_incidents)
        user = request.form.get('X-Username'); file = request.files.get('log_file'); filename = secure_filename(file.filename) if file else "N/A"
        save_name = f"INCIDENT_{user}_{filename}"
        
        if file: file.save(os.path.join(INCIDENTS_FOLDER, save_name))
        
        new_incident = IncidentReport(user=user, ip=request.form.get('X-IP'), message=request.form.get('message'), filename=save_name if file else "N/A", storage_path=save_name if file else "N/A", date=datetime.datetime.utcnow())
        db.session.add(new_incident); db.session.commit()
        return jsonify({"status":"Reporte recibido"}), 201

    @app.route('/api/logs/incidents', methods=['GET'])
    def incs_old(): 
        # Ruta legado (mantiene compatibilidad)
        if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg": "Acceso denegado"}), 403
        reports = IncidentReport.query.order_by(IncidentReport.date.desc()).limit(100).all()
        return jsonify([{"id": r.id, "user": r.user, "message": r.message, "date": r.date.isoformat(), "filename": r.filename} for r in reports]), 200

    # --- ACTUALIZACIONES: CARPETA 3 (updates_system) + TRACKING ---
    @app.route('/api/updates/upload', methods=['POST'])
    def upload_update_file_route():
        filename = secure_filename(request.headers.get('X-Vercel-Filename'))
        # Guardar en la nueva carpeta updates_system
        save_path = os.path.join(UPDATES_FOLDER, filename)
        
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
        # URL apunta a /updates/...
        return jsonify({"version": latest.version, "download_url": get_file_url(latest.storage_path, 'updates')}), 200

    # --- RESET MAESTRO (LIMPIA LAS 3 CARPETAS + DB) ---
    @app.route('/api/admin/reset-diagnostics', methods=['DELETE'])
    def reset_diagnostics():
        if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg":"Auth Fail"}), 403
        try:
            db.session.query(HistoricalLog).delete()
            db.session.query(IncidentReport).delete()
            db.session.query(UpdateFile).delete()
            # Opcional: Borrar analytics
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

    # ===============================================================
    # 🔗 ZONA DE INTEGRACIÓN CON SERVIDOR 4 (WORKER)
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
        """Srv4 pregunta si el usuario puede convertir."""
        if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"allow": False, "reason": "Auth Fail"}), 403
        
        data = request.get_json()
        client_id = data.get('singleUseClientId')
        cooldown_hours = 48
        
        records = load_conversion_records()
        user_records = sorted(
            [r for r in records if r.get("singleUseClientId") == client_id],
            key=lambda x: x["timestamp"], reverse=True
        )

        if not user_records: return jsonify({"allow": True}), 200

        try:
            last_time_str = user_records[0]["timestamp"].replace("Z", "")
            last_time = datetime.datetime.fromisoformat(last_time_str)
            unlock_time = last_time + timedelta(hours=cooldown_hours)
            
            if datetime.datetime.utcnow() < unlock_time:
                remaining = str(unlock_time - datetime.datetime.utcnow()).split('.')[0]
                return jsonify({"allow": False, "reason": f"Cooldown activo. Espera: {remaining}"}), 200
        except:
            return jsonify({"allow": True}), 200
            
        return jsonify({"allow": True}), 200

    @app.route('/api/worker/log-success', methods=['POST'])
    def worker_log_success():
        """Srv4 reporta que terminó y entregó un archivo."""
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
