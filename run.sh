#!/bin/bash
# Forzar la ruta de Python para que encuentre el módulo
export PYTHONPATH=/app:$PYTHONPATH
# Ejecutar Gunicorn directamente con el comando 'exec', el más seguro
exec gunicorn -b 0.0.0.0:7860 servidor3:app