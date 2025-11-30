# wsgi.py
import os
import sys
# Asegurarse de que el directorio de la aplicación esté en el path de Python
sys.path.insert(0, os.path.dirname(__file__)) 
from servidor3 import app as application

if __name__ == "__main__":
    application.run()
