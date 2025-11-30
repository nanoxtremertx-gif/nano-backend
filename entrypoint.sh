#!/bin/bash
# entrypoint.sh: Asegura el PATH y arranca Gunicorn

# 1. FUERZA EL PATH DE PYTHON
export PYTHONPATH=/app:$PYTHONPATH

# 2. INICIA GUNICORN EN MODO PRODUCCIÓN
# Usamos el comando más directo y seguro
exec gunicorn -w 4 servidor3:app --bind 0.0.0.0:5002 --timeout 60
