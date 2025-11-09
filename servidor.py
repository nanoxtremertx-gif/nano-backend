# --- servidor.py ---
# Este script unifica el backend de la aplicación web (login, registro, subida)
# y el backend del actualizador (logs, check de updates).
# Utiliza Flask y no requiere base de datos (datos en memoria).

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
# Habilitamos CORS para permitir que tu frontend (React/Next.js) se conecte
CORS(app) 

# --- SIMULACIÓN DE BASE DE DATOS (En Memoria) ---

# 1. Backend Web
db_users = {}
# Ejemplo de db_users:
# "nano": {
#     "password_hash": "...",
#     "email": "nano@nano.com",
#     "identificador": "123456-7",
#     "fingerprint": "nano" # La "Marca de Autoría"
# }

db_files = {}
# Ejemplo de db_files:
# "nano": [
#     {"id": "...", "name": "archivo1.crs", "status": "clean", "date": "...", "size": 1024},
#     {"id": "...", "name": "archivo2.crs", "status": "warning", "date": "...", "size": 2048}
# ]

# 2. Backend de Actualizador (Consolas)
db_logs_historicos = [] # Consola 1
# Ejemplo:
# { "id": "...", "user": "user_app", "ip": "192.168.1.1", "quality": "Pro", 
#   "logFile": "log_user_app_12345.txt", "url": "/simulated_logs/log_user_app_12345.txt", "date": "..." }

db_archivos_actualizacion = [] # Consola 3
# Ejemplo:
# { "id": "...", "name": "actualizacion002.py", "size": 5120, "date": "...", 
#   "version": "002", "url": "/simulated_updates/actualizacion002.py" }


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
    identificador = data.get('identificador') # (RUT, etc.)

    if not username or not password or not email or not identificador:
        return jsonify({"message": "Faltan datos obligatorios"}), 400

    if username in db_users:
        return jsonify({"message": "El nombre de usuario ya existe"}), 409

    # Guardamos al usuario
    db_users[username] = {
        "password_hash": generate_password_hash(password),
        "email": email,
        "identificador": identificador,
        "fingerprint": username.lower() # Usamos el username como "Marca de Autoría"
    }
    
    print(f"[REGISTRO] Usuario '{username}' creado exitosamente.")
    print("DB Users:", db_users)
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
        return jsonify({"message": "Credenciales incorrectas"}), 401

    # Datos del usuario que enviamos al frontend (simulando login.jsx)
    user_data_for_frontend = {
        "username": username,
        "email": user['email'],
        "role": "admin" if username == "admin" else "user", # Simulación de admin
        "subscriptionEndDate": "2099-12-31" # Simulación
    }
    
    print(f"[LOGIN] Usuario '{username}' inició sesión.")
    return jsonify({"message": "Login exitoso", "user": user_data_for_frontend}), 200

@app.route('/get-crs-author', methods=['POST'])
def get_crs_author():
    """
    Endpoint de análisis forense que 'subir.jsx' espera.
    Solo lee el archivo y devuelve el 'authorId' (fingerprint).
    """
    if 'file' not in request.files:
        print("[FORENSE] Petición sin archivo.")
        return jsonify({"authorId": "ERROR: No se envió archivo"}), 400

    file = request.files['file']
    
    if file.filename == '':
        return jsonify({"authorId": "ERROR: Nombre de archivo vacío"}), 400

    try:
        file_content = file.read()
        
        # 1. Simular análisis forense
        fingerprint_en_archivo = simular_analisis_crs(file_content)
        
        print(f"[FORENSE] Análisis de {file.filename} completado. ID: {fingerprint_en_archivo}")
        
        # 2. Devolver solo el ID, como 'subir.jsx' espera
        return jsonify({"authorId": fingerprint_en_archivo}), 200
        
    except Exception as e:
        print(f"[FORENSE] Error crítico al leer archivo: {e}")
        return jsonify({"authorId": f"ERROR CRÍTICO: {e}"}), 500

def simular_analisis_crs(file_bytes):
    """
    Simula la lectura de un 'id_fingerprint' (public_author)
    leyendo bytes específicos del archivo.
    """
    # Convertimos a minúsculas para comparar
    content_lower = file_bytes.lower()

    # Buscamos patrones simulados
    if b"id_fingerprint=nano" in content_lower:
        return "nano"
    if b"id_fingerprint=user_test" in content_lower:
        return "user_test"
    if b"public_author:xtreme" in content_lower:
        return "xtreme"
    
    # Si no encuentra un ID conocido, pero parece tener el campo
    if b"id_fingerprint=" in content_lower or b"public_author:" in content_lower:
        return "desconocido" # Un ID que no coincide

    # Si no tiene el campo
    return "NO_ID"

@app.route('/upload-crs', methods=['POST'])
def upload_crs_file():
    """
    Maneja la subida de archivos CRS y realiza la verificación de autoría.
    Esto es llamado por 'subir.jsx'.
    """
    if 'file' not in request.files or 'username' not in request.form:
        return jsonify({"allowed": False, "message": "Faltan datos (archivo o usuario)"}), 400

    file = request.files['file']
    username = request.form['username']
    
    if file.filename == '' or not file.filename.lower().endswith('.crs'):
        return jsonify({"allowed": False, "message": "Archivo inválido o no es .crs"}), 400

    user = db_users.get(username)
    if not user:
        return jsonify({"allowed": False, "message": "Usuario no encontrado"}), 404

    # Leemos el contenido del archivo para analizarlo
    # ¡Importante! El frontend ya analizó el archivo con /get-crs-author.
    # Esta ruta ('/upload-crs') es solo para confirmar y registrar la metadata.
    # No necesitamos leer el contenido de nuevo si confiamos en el frontend.
    
    # PERO, para ser seguros, volveremos a analizarlo aquí.
    
    file_content = file.read()
    file_size = len(file_content)
    
    # 1. Simular análisis forense
    fingerprint_en_archivo = simular_analisis_crs(file_content)
    
    # 2. Obtener la "Marca de Autoría" registrada del usuario
    fingerprint_del_usuario = user.get('fingerprint', '').lower()

    # 3. Lógica de verificación
    
    # "Si NO tiene id_fingerprint -> NO se sube"
    # El frontend (subir.jsx) ya debería haber filtrado esto, pero lo validamos
    if fingerprint_en_archivo == "NO_ID":
        print(f"[UPLOAD] Rechazado (NO_ID): {file.filename} de {username}")
        return jsonify({
            "allowed": False, 
            "status": "no_id", 
            "message": "El archivo no contiene un id_fingerprint (public_author) y no se puede subir."
        }), 200 # 200 OK, pero 'allowed: false'

    # "Si la autoría coincide -> aparece verde"
    elif fingerprint_en_archivo == fingerprint_del_usuario:
        status = "clean" # Verde
        print(f"[UPLOAD] Aceptado (Clean): {file.filename} de {username}")
    
    # "Si no coincide -> aparece amarillo"
    else:
        status = "warning" # Amarillo
        print(f"[UPLOAD] Aceptado (Warning): {file.filename} de {username}. Autoría no coincide ({fingerprint_en_archivo})")

    # Guardamos solo la metadata (No guardamos el archivo real)
    file_metadata = {
        "id": str(uuid.uuid4()),
        "name": file.filename,
        "status": status,
        "date": datetime.datetime.now().isoformat(),
        "size": file_size
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
    Devuelve la lista de archivos (metadata) de un usuario.
    """
    user_files = db_files.get(username, [])
    print(f"[MY_FILES] {username} solicitó sus archivos. Se encontraron {len(user_files)}.")
    return jsonify(user_files), 200


# --- 2. ENDPOINTS DEL ACTUALIZADOR (Consolas) ---

# --- CONSOLA 1: LOGS HISTÓRICOS ---

@app.route('/api/logs/historical', methods=['POST'])
def receive_historical_log():
    """
    Recibe el 'log_proceso.txt' desde 'actualizacion.py' (Consola 1).
    """
    # Obtenemos metadatos de los headers (como en actualizacion.py)
    username = request.headers.get('X-Username', 'desconocido')
    ip = request.headers.get('X-IP', '0.0.0.0')
    quality = request.headers.get('X-Quality', 'N/A')
    
    # El log viene como 'data' (binario)
    log_content = request.data
    
    if not log_content:
        return jsonify({"message": "No se recibió contenido de log"}), 400

    # Simulamos el guardado del log
    log_filename = f"log_{username}_{int(time.time())}.txt"
    log_url = f"/simulated_logs/{log_filename}" # URL simulada
    
    log_entry = {
        "id": str(uuid.uuid4()),
        "user": username,
        "ip": ip,
        "quality": quality,
        "logFile": log_filename,
        "url": log_url,
        "date": datetime.datetime.now().isoformat()
    }
    
    db_logs_historicos.insert(0, log_entry) # Añadimos al principio
    
    print(f"[CONSOLA 1] Log recibido de {username} ({ip}). Tamaño: {len(log_content)} bytes.")
    
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
    # 'documentos.jsx' envía el nombre en el header
    filename = request.headers.get('X-Vercel-Filename')
    file_content = request.data
    
    if not filename or not file_content:
        return jsonify({"message": "Falta nombre o contenido del archivo"}), 400

    if not filename.startswith('actualizacion') or not filename.endswith('.py'):
        return jsonify({"message": "Nombre de archivo inválido."}), 400

    version = extraer_version_de_nombre(filename)
    
    # Simulamos guardado
    update_url = f"/simulated_updates/{filename}"
    
    update_entry = {
        "id": str(uuid.uuid4()),
        "name": filename,
        "size": len(file_content),
        "date": datetime.datetime.now().isoformat(),
        "version": version,
        "url": update_url
    }
    
    # Borramos versiones anteriores con el mismo nombre si existieran
    global db_archivos_actualizacion
    db_archivos_actualizacion = [f for f in db_archivos_actualizacion if f['name'] != filename]
    # Añadimos la nueva
    db_archivos_actualizacion.append(update_entry)
    
    print(f"[CONSOLA 3] Nueva actualización subida: {filename} (Versión: {version})")
    
    return jsonify({"message": "Archivo de actualización subido"}), 201

@app.route('/api/updates/list', methods=['GET'])
def list_update_files():
    """
    Entrega la lista de archivos de actualización a 'documentos.jsx' (Consola 3).
    """
    # Ordenamos por versión (como string) descendente
    sorted_list = sorted(db_archivos_actualizacion, key=lambda x: x['version'], reverse=True)
    print(f"[CONSOLA 3] Admin listando actualizaciones. Total: {len(sorted_list)}")
    return jsonify(sorted_list), 200

@app.route('/api/updates/check', methods=['GET'])
def check_for_updates():
    """
    Es llamado por 'actualizacion.py' para buscar la última versión.
    """
    # Autenticación simple (como la que usa actualizacion.py)
    auth = request.authorization
    if not auth or auth.username != 'socios' or auth.password != '121351':
        print("[UPDATE CHECK] Intento fallido de autenticación.")
        return jsonify({"message": "No autorizado"}), 401
        
    if not db_archivos_actualizacion:
        print("[UPDATE CHECK] No hay actualizaciones disponibles (404).")
        return jsonify({"message": "No hay actualizaciones disponibles"}), 404

    # Buscamos la versión más alta
    try:
        latest_update = max(db_archivos_actualizacion, key=lambda x: int(x['version']))
    except Exception as e:
        print(f"[UPDATE CHECK] Error al buscar última versión: {e}")
        return jsonify({"message": "Error interno al buscar versión"}), 500

    print(f"[UPDATE CHECK] Cliente buscando update. Última versión: {latest_update['name']}")
    
    # Devolvemos la data que 'actualizacion.py' espera
    return jsonify({
        "version": latest_update['version'],
        "file_name": latest_update['name'],
        "download_url": latest_update['url'] # El cliente usará esta URL
    }), 200


# --- RUTAS DE DESCARGA SIMULADA ---
# (Estas rutas devuelven contenido falso para completar el ciclo)

@app.route('/simulated_updates/<filename>')
def download_simulated_update(filename):
    """
    Simula la descarga del archivo .py de actualización.
    """
    # Verificamos que 'actualizacion.py' se autentique
    auth = request.authorization
    if not auth or auth.username != 'socios' or auth.password != '121351':
        abort(401)
        
    print(f"[DESCARGA] Cliente descargando actualización: {filename}")
    
    # Creamos un archivo python falso para la descarga
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