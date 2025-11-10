# --- servidor.py ---
# (v2.4 - Arreglo de CORS para Vercel)

from flask import Flask, jsonify, request, make_response, send_from_directory, abort
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import uuid
import re
import time
import os

# --- Configuración de Flask ---
app = Flask(__name__)
# --- ¡CAMBIO IMPORTANTE AQUÍ! ---
# Habilitamos CORS para todas las rutas ("/*") y todos los orígenes ("*")
# Esto arregla el "Error de conexión" de Vercel.
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

# --- SIMULACIÓN DE BASE DE DATOS (En Memoria) ---
db_users = {}
db_files = {
    # 'username': [ {metadata}, {metadata} ]
}
db_logs_historicos = [] # Consola 1
db_archivos_actualizacion = [] # Consola 3

# --- RUTA DE HEALTH CHECK (Para UptimeRobot) ---
@app.route('/')
def health_check():
    """
    Ruta principal que devuelve un 200 OK para los monitores de uptime.
    """
    print("[HEALTH CHECK] UptimeRobot/Render ha revisado el servidor.")
    return jsonify({"status": "online", "message": "Servidor de Nano-Backend está activo."}), 200

# --- 1. ENDPOINTS DEL BACKEND WEB (Login, Registro, Subida) ---

@app.route('/api/register', methods=['POST'])
def register_user():
    """
    Maneja el registro de nuevos usuarios.
    """
    data = request.json
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    identificador = data.get('identificador') 

    if not username or not password or not email or not identificador:
        return jsonify({"message": "Faltan datos obligatorios"}), 400

    if username in db_users:
        return jsonify({"message": "El nombre de usuario ya existe"}), 409

    db_users[username] = {
        "password_hash": generate_password_hash(password),
        "email": email,
        "identificador": identificador,
        "fingerprint": username.lower() 
    }
    
    print(f"[REGISTRO] Usuario '{username}' creado exitosamente.")
    return jsonify({"message": "Usuario registrado exitosamente"}), 201

@app.route('/api/login', methods=['POST'])
def login_user():
    """
    Maneja el inicio de sesión de usuarios.
    """
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = db_users.get(username)

    if not user or not check_password_hash(user['password_hash'], password):
        print("[LOGIN] Fallido: Credenciales incorrectas para", username)
        return jsonify({"message": "Credenciales incorrectas"}), 401

    user_data_for_frontend = {
        "username": username,
        "email": user['email'],
        "role": "admin" if username == "admin" else "user", 
        "subscriptionEndDate": "2099-12-31"
    }
    
    print(f"[LOGIN] Usuario '{username}' inició sesión.")
    return jsonify({"message": "Login exitoso", "user": user_data_for_frontend}), 200

@app.route('/get-crs-author', methods=['POST'])
def get_crs_author():
    """
    Endpoint de análisis forense que 'subir.jsx' espera.
    """
    if 'file' not in request.files:
        print("[FORENSE] Petición sin archivo.")
        return jsonify({"authorId": "ERROR: No se envió archivo"}), 400

    file = request.files['file']
    
    if file.filename == '':
        return jsonify({"authorId": "ERROR: Nombre de archivo vacío"}), 400

    try:
        file_content = file.read()
        fingerprint_en_archivo = simular_analisis_crs(file_content)
        
        print(f"[FORENSE] Análisis de {file.filename} completado. ID: {fingerprint_en_archivo}")
        return jsonify({"authorId": fingerprint_en_archivo}), 200
        
    except Exception as e:
        print(f"[FORENSE] Error crítico al leer archivo: {e}")
        return jsonify({"authorId": f"ERROR CRÍTICO: {e}"}), 500

def simular_analisis_crs(file_bytes):
    """
    Simula la lectura de un 'id_fingerprint' (public_author).
    """
    content_lower = file_bytes.lower()

    if b"id_fingerprint=nano" in content_lower:
        return "nano"
    if b"id_fingerprint=user_test" in content_lower:
        return "user_test"
    if b"public_author:xtreme" in content_lower:
        return "xtreme"
    
    if b"id_fingerprint=" in content_lower or b"public_author:" in content_lower:
        return "desconocido" 

    return "NO_ID" # No tiene el campo

@app.route('/upload-crs', methods=['POST'])
def upload_crs_file():
    """
    Maneja la subida de archivos CRS y realiza la verificación de autoría.
    """
    if 'file' not in request.files or 'username' not in request.form or 'parentId' not in request.form:
        return jsonify({"allowed": False, "message": "Faltan datos (archivo, usuario o parentId)"}), 400

    file = request.files['file']
    username = request.form['username']
    parent_id = request.form['parentId'] # 'root' o un ID de carpeta
    
    if file.filename == '' or not file.filename.lower().endswith('.crs'):
        return jsonify({"allowed": False, "message": "Archivo inválido o no es .crs"}), 400

    user = db_users.get(username)
    if not user:
        return jsonify({"allowed": False, "message": "Usuario no encontrado"}), 404

    file_content = file.read()
    file_size = len(file_content)
    
    fingerprint_en_archivo = simular_analisis_crs(file_content)
    fingerprint_del_usuario = user.get('fingerprint', '').lower()

    status = "pending" # Estado por defecto

    if fingerprint_en_archivo == "NO_ID":
        print(f"[UPLOAD] Rechazado (NO_ID): {file.filename} de {username}")
        return jsonify({
            "allowed": False, 
            "status": "no_id", 
            "message": "El archivo no contiene un id_fingerprint (public_author)."
        }), 200 

    elif fingerprint_en_archivo == fingerprint_del_usuario:
        status = "clean" # Verde
        print(f"[UPLOAD] Aceptado (Clean): {file.filename} de {username}")
    
    else:
        status = "warning" # Amarillo
        print(f"[UPLOAD] Aceptado (Warning): {file.filename} de {username}. Autoría no coincide ({fingerprint_en_archivo})")

    file_metadata = {
        "id": str(uuid.uuid4()),
        "name": file.filename,
        "status": status,
        "date": datetime.datetime.now().isoformat(),
        "size": file_size,
        "type": "file", # Importante para 'misarchivos.jsx'
        "parentId": parent_id
    }
    
    if username not in db_files:
        db_files[username] = []
    db_files[username].append(file_metadata)

    return jsonify({
        "allowed": True, 
        "status": status, 
        "filename": file.filename,
        "message": f"Archivo '{file.filename}' registrado con estado: {status}"
    }), 200

@app.route('/api/my-files/<username>', methods=['GET'])
def get_my_files(username):
    """
    Devuelve la lista de archivos Y carpetas (metadata) de un usuario.
    """
    user_files = db_files.get(username, [])
    root_items = [f for f in user_files if f.get('parentId') == 'root']
    
    print(f"[MY_FILES] {username} solicitó sus archivos (root). Se encontraron {len(root_items)}.")
    return jsonify(root_items), 200

@app.route('/api/create-folder', methods=['POST'])
def create_folder():
    """
    Crea una nueva carpeta (metadata) para un usuario.
    """
    data = request.json
    folder_name = data.get('name')
    username = data.get('username')
    parent_id = data.get('parentId') # 'root' o un ID

    if not folder_name or not username or not parent_id:
        return jsonify({"message": "Faltan datos"}), 400

    new_folder = {
        "id": str(uuid.uuid4()),
        "name": folder_name,
        "type": "folder", # Importante para 'misarchivos.jsx'
        "date": datetime.datetime.now().isoformat(),
        "parentId": parent_id,
        "size": 0
    }

    if username not in db_files:
        db_files[username] = []
    db_files[username].append(new_folder)
    
    print(f"[FOLDER] Carpeta '{folder_name}' creada para {username}.")
    return jsonify({"message": "Carpeta creada", "newFolder": new_folder}), 201


# --- 2. ENDPOINTS DEL ACTUALIZADOR (Consolas) ---

# --- CONSOLA 1: LOGS HISTÓRICOS ---

@app.route('/api/logs/historical', methods=['POST'])
def receive_historical_log():
    """
    Recibe el 'log_proceso.txt' desde 'actualizacion.py' (Consola 1).
    """
    username = request.headers.get('X-Username', 'desconocido')
    ip = request.headers.get('X-IP', '0.0.0.0')
    quality = request.headers.get('X-Quality', 'N/A')
    log_content = request.data
    
    if not log_content:
        return jsonify({"message": "No se recibió contenido de log"}), 400

    log_filename = f"log_{username}_{int(time.time())}.txt"
    log_url = f"/simulated_logs/{log_filename}" 
    
    log_entry = {
        "id": str(uuid.uuid4()),
        "user": username,
        "ip": ip,
        "quality": quality,
        "logFile": log_filename,
        "url": log_url,
        "date": datetime.datetime.now().isoformat()
    }
    
    db_logs_historicos.insert(0, log_entry)
    
    print(f"[CONSOLA 1] Log recibido de {username} ({ip}).")
    return jsonify({"message": "Log histórico recibido"}), 201

@app.route('/api/logs/historical', methods=['GET'])
def list_historical_logs():
    """
    Entrega la lista de logs a 'documentos.jsx' (Consola 1).
    """
    print(f"[CONSOLA 1] Admin listando logs. Total: {len(db_logs_historicos)}")
    return jsonify(db_logs_historicos), 200


# --- CONSOLA 3: ACTUALIZACIONES ---

def extraer_version_de_nombre(filename):
    """
    Extrae el número de versión (ej: '003') de 'actualizacion003.py'.
    """
    match = re.search(r'actualizacion(\d{3,})\.py', filename)
    if match:
        return match.group(1)
    return "000"

@app.route('/api/updates/upload', methods=['POST'])
def upload_update_file():
    """
    Recibe un archivo de actualización (ej: 'actualizacion003.py') 
    desde 'documentos.jsx' (Consola 3).
    """
    filename = request.headers.get('X-Vercel-Filename')
    file_content = request.data
    
    if not filename or not file_content:
        return jsonify({"message": "Falta nombre o contenido del archivo"}), 400

    if not filename.startswith('actualizacion') or not filename.endswith('.py'):
        return jsonify({"message": "Nombre de archivo inválido."}), 400

    version = extraer_version_de_nombre(filename)
    update_url = f"/simulated_updates/{filename}"
    
    update_entry = {
        "id": str(uuid.uuid4()),
        "name": filename,
        "size": len(file_content),
        "date": datetime.datetime.now().isoformat(),
        "version": version,
        "url": update_url
    }
    
    global db_archivos_actualizacion
    db_archivos_actualizacion = [f for f in db_archivos_actualizacion if f['name'] != filename]
    db_archivos_actualizacion.append(update_entry)
    
    print(f"[CONSOLA 3] Nueva actualización subida: {filename} (Versión: {version})")
    return jsonify({"message": "Archivo de actualización subido"}), 201

@app.route('/api/updates/list', methods=['GET'])
def list_update_files():
    """
    Entrega la lista de archivos de actualización a 'documentos.jsx' (Consola 3).
    """
    sorted_list = sorted(db_archivos_actualizacion, key=lambda x: x['version'], reverse=True)
    print(f"[CONSOLA 3] Admin listando actualizaciones. Total: {len(sorted_list)}")
    return jsonify(sorted_list), 200

@app.route('/api/updates/check', methods=['GET'])
def check_for_updates():
    """
    Es llamado por 'actualizacion.py' para buscar la última versión.
    """
    auth = request.authorization
    if not auth or auth.username != 'socios' or auth.password != '121351':
        print("[UPDATE CHECK] Intento fallido de autenticación.")
        return jsonify({"message": "No autorizado"}), 401
        
    if not db_archivos_actualizacion:
        print("[UPDATE CHECK] No hay actualizaciones disponibles (404).")
        return jsonify({"message": "No hay actualizaciones disponibles"}), 404

    try:
        latest_update = max(db_archivos_actualizacion, key=lambda x: int(x['version']))
    except Exception as e:
        print(f"[UPDATE CHECK] Error al buscar última versión: {e}")
        return jsonify({"message": "Error interno al buscar versión"}), 500

    print(f"[UPDATE CHECK] Cliente buscando update. Última versión: {latest_update['name']}")
    
    return jsonify({
        "version": latest_update['version'],
        "file_name": latest_update['name'],
        "download_url": latest_update['url']
    }), 200


# --- RUTAS DE DESCARGA SIMULADA ---
@app.route('/simulated_updates/<filename>')
def download_simulated_update(filename):
    """
    Simula la descarga del archivo .py de actualización.
    """
    auth = request.authorization
    if not auth or auth.username != 'socios' or auth.password != '121351':
        abort(401)
        
    print(f"[DESCARGA] Cliente descargando actualización: {filename}")
    
    fake_content = f"""
# --- Archivo de actualización simulado: {filename} ---
import time
print("Iniciando actualización simulada...")
time.sleep(3)
print("...Proceso de actualización simulado terminado.")
# --- Fin de la simulación ---
"""
    response = make_response(fake_content)
    response.headers["Content-Type"] = "text/x-python-script"
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return response

@app.route('/simulated_logs/<filename>')
def download_simulated_log(filename):
    """
    Simula la descarga de un log para el admin (Consola 1).
    """
    print(f"[DESCARGA] Admin descargando log: {filename}")
    fake_content = f"Contenido simulado del log: {filename}\nUsuario: {filename.split('_')[1]}\n"
    response = make_response(fake_content)
    response.headers["Content-Type"] = "text/plain"
    return response


# --- Iniciar el servidor ---
if __name__ == '__main__':
    # El puerto lo define Render, pero 5000 es un buen default
    port = int(os.environ.get('PORT', 5000))
    print("Iniciando servidor Flask...")
    # Usamos 0.0.0.0 para que sea accesible desde Render
    app.run(host='0.0.0.0', port=port)