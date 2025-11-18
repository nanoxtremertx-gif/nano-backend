# --- servidor.py --- (v18.4 - SOPORTE REAL DE CARPETAS DE GESTIÓN)
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
from urllib.parse import urlparse, urlunparse
from sqlalchemy import text 

# --- 1. IMPORTAR MODELOS Y DB ---
# Importamos la 'db' (vacía) y los modelos desde nuestro nuevo models.py
from models import db, User, UserFile, HistoricalLog, IncidentReport, UpdateFile, DocGestion

# --- 2. INICIALIZAR EXTENSIONES (VACÍAS) ---
cors = CORS()
bcrypt = Bcrypt()
socketio = SocketIO()

# --- 3. Memoria RAM (Global) ---
ONLINE_USERS = {}
ADMIN_SECRET_KEY = "NANO_MASTER_KEY_2025" 
db_status = "Desconocido" # Variable global para el status

# --- 4. DEFINIR LA FÁBRICA DE LA APLICACIÓN ---
def create_app():
    global db_status 
    
    app = Flask(__name__)
    print(">>> INICIANDO SERVIDOR MAESTRO (v18.4 - Con Carpetas de Gestión) <<<")

    # --- 5. CONFIGURACIÓN DE APP ---
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
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

    # --- 6. INICIALIZACIÓN DE EXTENSIONES CON LA APP ---
    cors.init_app(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)
    socketio.init_app(app, cors_allowed_origins="*")
    bcrypt.init_app(app)
    db.init_app(app) 

    # --- 7. DEFINIR FUNCIONES Y RUTAS DENTRO DE LA FÁBRICA ---
    
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

    SUB_DOC_FOLDERS = ['desarrollo', 'gestion', 'operaciones']
    for sub in SUB_DOC_FOLDERS:
        os.makedirs(os.path.join(DOCS_FOLDER, sub), exist_ok=True)

    # --- Funciones Helper ---
    def emit_online_count():
        try:
            count = len(ONLINE_USERS)
            socketio.emit('update_online_count', {'count': count})
            print(f"EMITIENDO CONTEO: {count} usuarios")
        except Exception as e:
            print(f"Error al emitir conteo: {e}")

    def get_file_url(filename, folder_route='uploads'):
        if not filename: return None
        return f"{request.host_url}{folder_route}/{filename}"

    def format_file_size(size_bytes):
        # --- (Modificación v18.4) ---
        if size_bytes is None: return "N/A" # Las carpetas no tienen tamaño
        if size_bytes < 1024:
            return f"{size_bytes} Bytes"
        if size_bytes < 1048576: return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1073741824: return f"{size_bytes / 1048576:.2f} MB"
        else: return f"{size_bytes / 1073741824:.2f} GB"

    # --- Rutas de Descarga y Health Check ---
    @app.route('/')
    def health_check(): 
        global db_status 
        return jsonify({"status": "v18.4 ONLINE (Factory)", "db": db_status}), 200

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
        
        new_user = User(
            username=d.get('username'), 
            hash=bcrypt.generate_password_hash(d.get('password')).decode('utf-8'), 
            email=d.get('email'), 
            identificador=d.get('identificador'), 
            role="gratis", 
            fingerprint=d.get('username').lower()
        )
        
        try:
            db.session.add(new_user)
            db.session.commit()
            
            new_folder = UserFile(
                owner_username=d.get('username'), 
                name="Archivos de Usuario", 
                type='folder', 
                parent_id=None, 
                size_bytes=0,
                verification_status='N/A'
            )
            db.session.add(new_folder)
            db.session.commit()

            ONLINE_USERS[d.get('username')] = datetime.datetime.utcnow()
            emit_online_count()
            return jsonify({"message": "Registrado"}), 201
            
        except Exception as e: 
            db.session.rollback()
            print(f"!!! ERROR FATAL EN REGISTRO: {e}")
            return jsonify({"message": f"Error de BD: {str(e)}"}), 500

    @app.route('/api/login', methods=['POST'])
    def login():
        d = request.get_json()
        u = User.query.filter_by(username=d.get('username')).first()
        
        if u and bcrypt.check_password_hash(u.hash, d.get('password')):
            
            try:
                root_folder = UserFile.query.filter_by(
                    owner_username=u.username, 
                    parent_id=None, 
                    name="Archivos de Usuario"
                ).first()
                
                if not root_folder:
                    print(f"INFO: [Login] Creando carpeta raíz faltante para usuario antiguo: {u.username}")
                    new_root = UserFile(
                        owner_username=u.username, 
                        name="Archivos de Usuario", 
                        type='folder', 
                        parent_id=None, 
                        size_bytes=0,
                        verification_status='N/A'
                    )
                    db.session.add(new_root)
                    db.session.commit()
                else:
                    print(f"INFO: [Login] Carpeta raíz verificada para {u.username}")
                
            except Exception as e:
                db.session.rollback()
                print(f"ERROR CRÍTICO: No se pudo crear/verificar la carpeta raíz para {u.username}: {e}")

            ONLINE_USERS[u.username] = datetime.datetime.utcnow()
            emit_online_count()
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

    # --- Rutas de Admin (usadas por vip.py) ---
    @app.route('/api/admin/users', methods=['GET'])
    def admin_list():
        if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg": "Acceso denegado"}), 403
        try:
            today_str = datetime.datetime.utcnow().strftime('%Y-%m-%d')
            users = User.query.all()
            user_list = []
            
            users_changed = False
            for u in users:
                if u.role == 'pro' and u.subscription_end:
                    try:
                        if u.subscription_end.split("T")[0] < today_str:
                            u.role = 'gratis'
                            u.subscription_end = None
                            users_changed = True
                    except Exception as e:
                        print(f"Error al parsear fecha de suscripción para {u.username}: {e}")
                
                user_list.append({
                    "username": u.username, "email": u.email, "role": u.role,
                    "identificador": u.identificador, "subscriptionEndDate": u.subscription_end
                })
            
            if users_changed:
                db.session.commit()
                print("INFO: Se han actualizado los roles de usuarios vencidos.")
                
            return jsonify(user_list), 200
        except Exception as e: 
            db.session.rollback()
            return jsonify({"error": str(e)}), 500

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

    @app.route('/api/admin/delete-public-file/<int:file_id>', methods=['DELETE'])
    def admin_delete_public_file(file_id):
        if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: 
            return jsonify({"msg": "Acceso denegado"}), 403
        
        try:
            f = UserFile.query.get(file_id)
            if not f:
                return jsonify({"message": "File not found"}), 404
            
            if f.storage_path:
                try:
                    file_path = os.path.join(UPLOAD_FOLDER, f.storage_path)
                    if os.path.exists(file_path):
                        os.remove(file_path)
                except Exception as e:
                    print(f"Error al borrar archivo físico: {e}")
            
            db.session.delete(f)
            db.session.commit()
            
            return jsonify({"message": "Archivo eliminado permanentemente"}), 200
            
        except Exception as e:
            db.session.rollback()
            return jsonify({"message": f"Error de servidor: {str(e)}"}), 500

    # --- Rutas de Archivos de Usuario (misarchivos.jsx) ---
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
            verification_status = request.form.get('verificationStatus', 'N/A')

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
                parent_id=parent_id, size_bytes=file_size, storage_path=unique_name,
                verification_status=verification_status
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
        try:
            d = request.get_json()
            parent_id = d.get('parentId')
            
            if parent_id == 'root' or not parent_id: 
                root_folder = UserFile.query.filter_by(owner_username=d.get('userId'), parent_id=None, name="Archivos de Usuario").first()
                parent_id = root_folder.id if root_folder else None

            nf = UserFile(
                owner_username=d.get('userId'), 
                name=d.get('name'), 
                type='folder', 
                parent_id=parent_id, 
                size_bytes=0,
                verification_status='N/A'
            )
            db.session.add(nf); db.session.commit()
            return jsonify({"newFolder": {
                "id": nf.id, "name": nf.name, "type": "folder", "parentId": nf.parent_id, 
                "date": nf.created_at.strftime('%Y-%m-%d'), 
                "size": "0 KB", "size_bytes": 0, "isPublished": False, "verificationStatus": 'N/A'
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

    # --- GESTIÓN DE DOCUMENTOS (documentos.jsx, vip.py, consola_admin.py) ---
    
    # --- ✅ MODIFICACIÓN 1: Listar Archivos ---
    # Ahora devolvemos type y parent_id, que vienen de models.py
    @app.route('/api/documentos/<section>', methods=['GET'])
    def get_gestion_docs(section):
        # (v18.4) La sección 'gestion' ahora es la única que soporta carpetas
        if section != 'gestion': 
             # Comportamiento antiguo para 'desarrollo' y 'operaciones'
             if section not in SUB_DOC_FOLDERS: return jsonify({"msg": "Sección inválida"}), 400
             try:
                 docs = DocGestion.query.filter_by(section=section, type='file').all() # Solo archivos
                 return jsonify([{
                     "id": d.id, "name": d.name, "size": d.size, "date": d.created_at.isoformat(),
                     "url": get_file_url(os.path.join(section, d.storage_path), 'documentos_gestion'),
                     "type": 'file', "parent_id": None # Simula la data antigua
                 } for d in docs]), 200
             except: return jsonify([]), 200
        
        # Comportamiento nuevo solo para 'gestion'
        try:
            docs = DocGestion.query.filter_by(section=section).all()
            return jsonify([{
                "id": d.id, "name": d.name, "size": d.size, "date": d.created_at.isoformat(),
                "url": get_file_url(os.path.join(section, d.storage_path), 'documentos_gestion') if d.storage_path else None,
                "type": d.type, 
                "parent_id": d.parent_id 
            } for d in docs]), 200
        except Exception as e: 
            print(f"Error en get_gestion_docs: {e}")
            return jsonify([]), 200

    # --- ✅ MODIFICACIÓN 2: Subir Archivo ---
    # Ahora leemos el 'parentId' que nos envía vip.py
    @app.route('/api/documentos/upload', methods=['POST'])
    def upload_gestion_doc():
        if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: return jsonify({"msg": "Acceso denegado"}), 403
        try:
            if 'file' not in request.files or 'section' not in request.form: return jsonify({"message": "Faltan datos"}), 400
            file = request.files['file']
            section = request.form['section']
            
            # --- Leemos el PARENT ID ---
            # (El 'None' de vip.py se volverá 'null' o 0, lo parseamos a Int o None)
            parent_id_str = request.form.get('parentId')
            parent_id = int(parent_id_str) if parent_id_str and parent_id_str != 'null' and parent_id_str != 'None' else None
            
            if section not in SUB_DOC_FOLDERS: return jsonify({"message": "Sección inválida"}), 400
            
            filename = secure_filename(file.filename)
            storage_name = f"{uuid.uuid4().hex[:8]}_{filename}"
            save_path = os.path.join(DOCS_FOLDER, section, storage_name)
            
            file.save(save_path)
            file_size = os.path.getsize(save_path)
            
            # --- GUARDAMOS EL ARCHIVO CON SU PARENT ID Y TYPE ---
            new_doc = DocGestion(
                name=filename, 
                section=section, 
                size=file_size, 
                storage_path=storage_name,
                type='file', # Es un archivo
                parent_id=parent_id # Lo asignamos a su carpeta
            )
            db.session.add(new_doc); db.session.commit()
            return jsonify({"message": "Documento subido", "new_doc": {
                "id": new_doc.id, "name": new_doc.name, "type": 'file', "parent_id": new_doc.parent_id
            }}), 201
        except Exception as e: 
            db.session.rollback()
            return jsonify({"message": f"Error: {str(e)}"}), 500

    # --- ✅ MODIFICACIÓN 3: Crear Carpeta ---
    # Esta ruta es completamente nueva
    @app.route('/api/documentos/create-folder', methods=['POST'])
    def create_gestion_folder():
        if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: 
            return jsonify({"msg": "Acceso denegado"}), 403
        try:
            d = request.get_json()
            # Parseamos el parentId
            parent_id_str = d.get('parentId')
            parent_id = int(parent_id_str) if parent_id_str and parent_id_str != 'null' and parent_id_str != 'None' else None
            
            name = d.get('name')
            section = d.get('section', 'gestion') # 'gestion' por defecto

            if not name:
                return jsonify({"message": "Falta el nombre"}), 400

            new_folder = DocGestion(
                name=name,
                section=section,
                type='folder', # Es una carpeta
                parent_id=parent_id, # Asignada a su carpeta padre
                size=None,
                storage_path=None
            )
            db.session.add(new_folder)
            db.session.commit()
            
            # Devolvemos la nueva carpeta creada (con su ID real de la BD)
            return jsonify({"message": "Carpeta creada", "newFolder": {
                "id": new_folder.id, 
                "name": new_folder.name,
                "type": 'folder',
                "parent_id": new_folder.parent_id,
                "section": new_folder.section,
                "date": new_folder.created_at.isoformat(),
                "size": None,
                "url": None
            }}), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({"message": f"Error: {str(e)}"}), 500

    @app.route('/api/documentos/delete/<int:doc_id>', methods=['DELETE'])
    def delete_gestion_doc(doc_id):
        if request.headers.get('X-Admin-Key') != ADMIN_SECRET_KEY: 
            return jsonify({"msg": "Acceso denegado"}), 403
        try:
            doc = DocGestion.query.get(doc_id)
            if not doc:
                return jsonify({"message": "Documento no encontrado"}), 404
            
            # --- (Mejora v18.4) Borrado recursivo si es carpeta ---
            if doc.type == 'folder':
                children = DocGestion.query.filter_by(parent_id=doc_id).all()
                if len(children) > 0:
                    return jsonify({"message": "La carpeta no está vacía. Borre el contenido primero."}), 400
            
            if doc.storage_path:
                try:
                    file_path = os.path.join(DOCS_FOLDER, doc.section, doc.storage_path)
                    if os.path.exists(file_path):
                        os.remove(file_path)
                except Exception as e:
                    print(f"Error al borrar archivo físico del doc: {e}")
            
            db.session.delete(doc)
            db.session.commit()
            return jsonify({"message": "Documento eliminado"}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({"message": f"Error: {str(e)}"}), 500

    # --- CONSOLAS (documentos.jsx) ---
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

    # --- API DE BIBLIOTECA PÚBLICA (biblioteca.jsx) ---
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
            
    # --- 8. DEVOLVER LA APP CREADA ---
    return app

# --- 9. ARRANQUE (SOLO PARA PRUEBAS LOCALES) ---
if __name__ == '__main__': 
    # Esta sección solo se usa si corres 'python servidor.py'
    app = create_app()
    socketio.run(app, host='0.0.0.0', port=7860)
