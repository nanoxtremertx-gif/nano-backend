# --- servidor.py -- - (v2.5 - Soporte Completo para Reportes de Incidente)

from flask import Flask, jsonify, request, make_response, send_from_directory, abort
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import uuid
import re
import time
import os
import io

# --- Configuración de Flask ---
app = Flask(__name__)

# --- ¡ESTA ES LA LÍNEA QUE ARREGLA TODO! ---
# Habilitamos CORS para todas las rutas ("/*") y todos los orígenes ("*")
# Esto arregla el "Error de conexión" de Vercel/Next.js con el backend de Render.
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)
# --- FIN DEL ARREGLO ---

# --- SIMULACIÓN DE BASE DE DATOS (En Memoria) ---
# NOTA: En un entorno de producción, esto sería una base de datos persistente (PostgreSQL, MongoDB, etc.)
db_users = {} # Almacena usuarios {username: {hash, email, identificador}}
db_files = {
    # 'username': [ {metadata}, {metadata} ] # Almacena metadatos de archivos subidos por usuario
}
db_logs_historicos = [] # Consola 1: Logs de actividad
db_archivos_actualizacion = [] # Consola 3: Archivos .py subidos por el admin
db_incidentes_reportados = [] # Consola 2: Reportes de incidentes RECIBIDOS
# ----------------------------------------------------------------------


# --- RUTA DE HEALTH CHECK (Para UptimeRobot/Render) ---
@app.route('/')
def health_check():
    """
    Ruta principal que devuelve un 200 OK para los monitores de uptime.
    """
    print("[HEALTH CHECK] UptimeRobot/Render ha revisado el servidor.")
    return jsonify({"status": "Servidor de control en marcha (v2.5)"}), 200


# ----------------------------------------------------
# 🔐 REGISTRO Y LOGIN (rutas /api/register y /api/login)
# ----------------------------------------------------
@app.route('/api/register', methods=['POST'])
def register_user():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    identificador = data.get('identificador')

    # Validación de campos
    if not username or not email or not password or not identificador:
        return jsonify({"message": "Faltan campos requeridos."}), 400

    # 1. Verificar si el usuario ya existe
    if username in db_users:
        return jsonify({"message": "El nombre de usuario ya existe."}), 409

    # 2. Hashing de la contraseña por seguridad
    hashed_password = generate_password_hash(password)

    # 3. Almacenar el usuario
    db_users[username] = {
        "hash": hashed_password,
        "email": email,
        "identificador": identificador,
        "fingerprint": username.lower() # Este es el ID de autoría usado para el CRS
    }
    
    # 4. Inicializar la lista de archivos para el nuevo usuario
    db_files[username] = []

    print(f"[REGISTRO] Usuario {username} registrado. ID Fingerprint: {db_users[username]['fingerprint']}")
    return jsonify({"message": "Usuario registrado exitosamente."}), 201

@app.route('/api/login', methods=['POST'])
def login_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # 1. Validar campos
    if not username or not password:
        return jsonify({"message": "Faltan campos requeridos."}), 400

    # 2. Buscar usuario
    user_data = db_users.get(username)

    if user_data and check_password_hash(user_data['hash'], password):
        # 3. Éxito: Devolver datos no sensibles para el localStorage del frontend
        print(f"[LOGIN] Usuario {username} ha iniciado sesión.")
        
        # Simulamos un log de actividad (Consola 1)
        db_logs_historicos.insert(0, {
            "id": str(uuid.uuid4()),
            "date": datetime.datetime.now().isoformat(),
            "type": "LOGIN",
            "user": username,
            "description": "Inicio de sesión exitoso en la plataforma.",
            "ip": request.remote_addr,
            "url_log": f"/simulated_logs/log_{username}_{int(time.time())}.txt"
        })
        
        return jsonify({
            "message": "Login exitoso",
            "user": {
                "username": username,
                "email": user_data['email'],
                "identificador": user_data['identificador'],
                "isAdmin": username.lower() == 'admin' # Rol simulado de admin
            }
        }), 200
    else:
        # 4. Fallo
        print(f"[LOGIN] Fallo de login para {username}.")
        return jsonify({"message": "Credenciales incorrectas."}), 401


# ----------------------------------------------------
# ⬆️ GESTIÓN DE ARCHIVOS CRS (rutas /get-crs-author y /upload-crs)
# ----------------------------------------------------
def simular_analisis_crs(file_storage, logged_fingerprint):
    """
    Simula el análisis forense del archivo CRS (.crs) para extraer la autoría.
    
    Lógica de simulación:
    - Si el nombre del archivo empieza por 'CLEAN', devuelve el fingerprint del usuario.
    - Si el nombre del archivo empieza por 'WARNING', devuelve un fingerprint diferente.
    - Si el nombre del archivo empieza por 'MALWARE', devuelve "NO_ID".
    - Cualquier otro archivo devuelve un ID aleatorio.
    """
    filename = file_storage.filename.upper()
    
    if filename.startswith('CLEAN_'):
        extracted_id = logged_fingerprint
        block_text = f"Autoría verificada. ID: {extracted_id}"
    elif filename.startswith('WARNING_'):
        # Simula un ID diferente al del usuario logueado
        extracted_id = f"ANON_{int(time.time())}"
        block_text = f"⚠️ Advertencia de Autoría. El ID extraído ({extracted_id}) NO COINCIDE con su perfil ({logged_fingerprint}). Requiere supervisión."
    elif filename.startswith('MALWARE_'):
        extracted_id = "NO_ID"
        block_text = "🚫 Bloque de Autoría Ilegible. El archivo NO CONTIENE el ID de autenticación. Se clasifica como CRÍTICO."
    else:
        # Por defecto, devuelve el ID del usuario
        extracted_id = logged_fingerprint
        block_text = f"Análisis estándar completado. ID: {extracted_id}"

    return {
        "autor_encriptada": "0x"+str(uuid.uuid4()).replace('-', '')[0:16], # Hash simulado
        "raw_extracted_id": extracted_id, # ID sin ofuscar (el importante)
        "autor_propietaria": logged_fingerprint, # El ID del usuario que sube
        "forensic_block_text": block_text
    }

@app.route('/get-crs-author', methods=['POST'])
def get_crs_author():
    """
    Paso 1: Recibe el archivo, simula el análisis y devuelve el ID de autoría.
    """
    logged_user = request.form.get('logged_user')
    file = request.files.get('file')

    if not logged_user or not file:
        return jsonify({"message": "Faltan el usuario logueado o el archivo."}), 400
    
    # 1. Obtener el 'fingerprint' del usuario logueado
    user_data = db_users.get(logged_user)
    if not user_data:
        return jsonify({"message": "Usuario no encontrado."}), 404
        
    logged_fingerprint = user_data['fingerprint']

    # 2. Simular el análisis forense
    forensic_result = simular_analisis_crs(file, logged_fingerprint)
    
    print(f"[ANALISIS] Archivo {file.filename}. Resultado ID: {forensic_result['raw_extracted_id']}")
    
    return jsonify(forensic_result), 200

@app.route('/upload-crs', methods=['POST'])
def upload_crs():
    """
    Paso 2: Recibe el archivo y los metadatos, registra la subida final.
    """
    logged_user = request.form.get('logged_user')
    extracted_id = request.form.get('extracted_id') # El ID extraído en el paso 1
    file = request.files.get('file')

    if not logged_user or not extracted_id or not file:
        return jsonify({"message": "Faltan datos esenciales para la subida."}), 400

    user_data = db_users.get(logged_user)
    if not user_data:
        return jsonify({"message": "Usuario no encontrado."}), 404
        
    logged_fingerprint = user_data['fingerprint']
    
    final_status = ""
    warning_message = None
    allowed = True

    # 1. Control de Archivos Ilegibles (MALWARE_*)
    if extracted_id == "NO_ID":
        final_status = "malware"
        warning_message = "CRÍTICO: Bloque de Autoría Ilegible. Subida RECHAZADA."
        allowed = False
        print(f"[SUBIDA] Archivo {file.filename} RECHAZADO (Malware/NO_ID).")

    # 2. Control de Archivos Limpios (CLEAN_*)
    elif extracted_id == logged_fingerprint:
        final_status = "clean"
        warning_message = "Verificado: Autoría validada. Subida ACEPTADA."
        print(f"[SUBIDA] Archivo {file.filename} ACEPTADO (Clean).")

    # 3. Control de Archivos con Advertencia (WARNING_*)
    else: # Si extracted_id NO COINCIDE con logged_fingerprint
        final_status = "warning"
        warning_message = f"ADVERTENCIA: Autoría ({extracted_id}) NO COINCIDE con perfil ({logged_fingerprint}). Subida ACEPTADA bajo supervisión."
        allowed = True
        print(f"[SUBIDA] Archivo {file.filename} ACEPTADO (Warning).")

    
    # 4. Si el archivo está permitido, registrar metadatos
    if allowed:
        new_file_metadata = {
            "id": str(uuid.uuid4()),
            "filename": file.filename,
            "size": len(file.read()), # Leemos el tamaño del archivo
            "date": datetime.datetime.now().isoformat(),
            "status": final_status,
            "extracted_id": extracted_id
        }
        file.seek(0) # Resetear el puntero del archivo
        
        db_files[logged_user].insert(0, new_file_metadata) # Almacenar en la "DB"

        # Simulamos un log de actividad (Consola 1)
        db_logs_historicos.insert(0, {
            "id": str(uuid.uuid4()),
            "date": datetime.datetime.now().isoformat(),
            "type": "FILE_UPLOAD",
            "user": logged_user,
            "description": f"Subido archivo {file.filename} con estado: {final_status}.",
            "ip": request.remote_addr,
            "url_log": f"/simulated_logs/log_{logged_user}_{int(time.time())}.txt"
        })
    
    return jsonify({
        "message": warning_message,
        "status": final_status,
        "allowed": allowed
    }), 200

# ----------------------------------------------------
# 🖥️ CONSOLAS DE ADMINISTRACIÓN
# ----------------------------------------------------

# --- RUTA DE CONSOLA 1: LOG HISTÓRICO ---
@app.route('/api/logs/historical', methods=['GET'])
def list_historical_logs():
    """
    Entrega la lista de logs de actividad a 'documentos.jsx' (Consola 1).
    """
    global db_logs_historicos
    # Devolvemos una copia de la lista (simulando una consulta a la DB)
    print(f"[CONSOLA 1] Admin listando logs históricos. Total: {len(db_logs_historicos)}")
    return jsonify(db_logs_historicos), 200

# --- RUTA DE CONSOLA 3: GESTIÓN DE ACTUALIZACIONES ---
@app.route('/api/updates/upload', methods=['POST'])
def upload_update_file():
    """
    Recibe el archivo de actualización .py del admin (documentos.jsx).
    """
    # El frontend de Vercel (documentos.jsx) envía el nombre en un header
    filename = request.headers.get('X-Vercel-Filename')
    
    # Asumimos que el admin está logueado (aquí no hay verificación de Auth real)
    if not filename:
        return jsonify({"message": "Falta el nombre del archivo (X-Vercel-Filename)."}), 400

    # Registrar la metadata de la actualización
    new_update_metadata = {
        "id": str(uuid.uuid4()),
        "filename": filename,
        "date": datetime.datetime.now().isoformat(),
        "version": filename.replace('.py', '').split('_')[-1] # Versión simulada
    }

    global db_archivos_actualizacion
    # Insertar al inicio para que el último subido sea el "más reciente"
    db_archivos_actualizacion.insert(0, new_update_metadata) 
    
    print(f"[CONSOLA 3] Archivo de actualización subido: {filename}")

    return jsonify({"message": "Actualización registrada con éxito."}), 201

@app.route('/api/updates/list', methods=['GET'])
def list_updates():
    """
    Entrega la lista de archivos de actualización subidos a 'documentos.jsx' (Consola 3).
    """
    global db_archivos_actualizacion
    print(f"[CONSOLA 3] Admin listando archivos de actualización. Total: {len(db_archivos_actualizacion)}")
    return jsonify(db_archivos_actualizacion), 200

@app.route('/api/updates/check', methods=['GET'])
def check_for_update():
    """
    Endpoint para que el script 'actualizacion.py' compruebe si hay una versión nueva.
    Utiliza Autenticación Básica (Basic Auth).
    """
    # 1. Autenticación Básica para el script de actualización
    auth = request.authorization
    # El script 'actualizacion.py' utiliza el par ('socios', '121351')
    if not auth or auth.username != 'socios' or auth.password != '121351':
        print("[AUTH FALLIDA] Intento de acceso a /api/updates/check.")
        return jsonify({'message': 'Acceso denegado. Autenticación fallida.'}), 401
    
    global db_archivos_actualizacion
    
    # 2. Devolver la actualización más reciente
    if db_archivos_actualizacion:
        latest_update = db_archivos_actualizacion[0] # El primero es el más reciente
        print(f"[UPDATE CHECK] Script conectado. Última versión disponible: {latest_update['filename']}")
        return jsonify({
            "status": "available",
            "filename": latest_update['filename'],
            "url": f"/simulated_downloads/{latest_update['filename']}", # Ruta de descarga simulada
            "version": latest_update['version']
        }), 200
    else:
        print("[UPDATE CHECK] Script conectado. No hay actualizaciones disponibles.")
        return jsonify({"status": "latest", "message": "No hay actualizaciones disponibles."}), 200

# ----------------------------------------------------
# 🚨 RUTA DE CONSOLA 2: REPORTES DE INCIDENTE (¡NUEVO!)
# ----------------------------------------------------

@app.route('/api/logs/incident', methods=['POST'])
def receive_incident_report():
    """
    Recibe el reporte de incidente desde 'actualizacion.py' (Modo incidente).
    """
    # Headers de contexto enviados por el script
    username = request.headers.get('X-Username', 'desconocido')
    ip = request.headers.get('X-IP', '0.0.0.0')
    quality = request.headers.get('X-Quality', 'N/A')
    
    # Datos enviados por el script actualizacion.py (run_incident_report)
    message = request.form.get('message')
    log_file_storage = request.files.get('log_file')
    
    # Validación básica
    if not message or not log_file_storage:
        print("[INCIDENTE] Error 400: Faltan datos en el reporte.")
        return jsonify({"message": "Faltan datos de mensaje o archivo de log (log_file)"}), 400

    # Crear entrada de incidente
    incident_entry = {
        "id": str(uuid.uuid4()),
        "user": username,
        "ip": ip,
        "quality": quality,
        "logFileName": log_file_storage.filename,
        # Nota: Usamos una URL simulada para la descarga en el panel de admin
        "logFileUrl": f"/simulated_logs/{log_file_storage.filename.replace('.txt', '_INCIDENTE.txt')}",
        "message": message,
        "date": datetime.datetime.now().isoformat(),
        "is_incident": True
    }
    
    global db_incidentes_reportados
    db_incidentes_reportados.insert(0, incident_entry) 
    
    print(f"[CONSOLA 2] Incidente recibido de {username} ({ip}). Archivo: {log_file_storage.filename}")
    return jsonify({"message": "Reporte de incidente recibido"}), 201

@app.route('/api/logs/incidents', methods=['GET'])
def list_incident_reports():
    """
    Entrega la lista de incidentes a 'documentos.jsx' (Consola 2).
    """
    global db_incidentes_reportados
    
    print(f"[CONSOLA 2] Admin listando incidentes. Total: {len(db_incidentes_reportados)}")
    # Devuelve la lista de incidentes (ordenados por el más reciente)
    return jsonify(db_incidentes_reportados), 200


# ----------------------------------------------------
# ⬇️ RUTAS DE DESCARGA SIMULADA
# ----------------------------------------------------
@app.route('/simulated_downloads/<filename>')
def download_simulated_update(filename):
    """
    Simula la descarga del archivo .py de actualización. Requiere Basic Auth.
    """
    auth = request.authorization
    # Verifica la misma Basic Auth que usa el script 'actualizacion.py'
    if not auth or auth.username != 'socios' or auth.password != '121351':
        abort(401)
        
    print(f"[DESCARGA] Cliente descargando actualización: {filename}")
    
    # Contenido simulado para el archivo .py
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
    Simula la descarga de un log o reporte para el admin (Consola 1 y 2).
    """
    print(f"[DESCARGA] Admin descargando log/reporte: {filename}")
    
    # Contenido simulado
    if 'INCIDENTE' in filename:
         fake_content = f"--- REPORTE DE INCIDENTE SIMULADO ---\nFecha: {datetime.datetime.now().isoformat()}\nUsuario Reporte: {filename.split('_')[1]}\n\n[Contenido Anti-Robo] Detección de código malicioso en la línea 42 de main.c. Archivo bloqueado y puesto en cuarentena."
    else:
        fake_content = f"Contenido simulado del log de actividad: {filename}\nUsuario: {filename.split('_')[1] or 'N/A'}\nDetalle: Simulación de 500 líneas de actividad normal del sistema."
        
    response = make_response(fake_content)
    response.headers["Content-Type"] = "text/plain"
    return response


# --- Iniciar el servidor ---
if __name__ == '__main__':
    # Usar puerto 5000 por defecto para desarrollo local
    # Render automáticamente usará la variable de entorno PORT.
    print("\n--- Servidor de Control de Servicios (Nano Blue) ---")
    print("🌐 Iniciando servidor Flask. Acceso: http://127.0.0.1:5000")
    # Para Render, usamos host='0.0.0.0' para que sea accesible externamente
    app.run(host='0.0.0.0', port=os.environ.get('PORT', 5000), debug=True)