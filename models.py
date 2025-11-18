# --- models.py ---
# Este archivo define la ESTRUCTURA de la base de datos.
from flask_sqlalchemy import SQLAlchemy
import datetime
import uuid

# 1. Creamos la extensión SIN conectarla a la app
db = SQLAlchemy()

# 2. Definimos todos los modelos
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
    # --- ✅ INICIO DE LA MODIFICACIÓN ---
    # storage_path y size ahora pueden ser nulos (para las carpetas)
    storage_path = db.Column(db.String(500), nullable=True)
    size = db.Column(db.Integer, nullable=True) 
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    # Estas dos columnas son la clave de todo
    # (Asegúrate de reiniciar el servidor y correr /admin/create_tables)
    type = db.Column(db.String(20), default='file') # Para saber si es 'file' o 'folder'
    parent_id = db.Column(db.Integer, nullable=True) # Para saber en qué carpeta está
    # --- ✅ FIN DE LA MODIFICACIÓN ---
