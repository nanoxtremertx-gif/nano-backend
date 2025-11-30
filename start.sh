#!/bin/bash
# 1. FIX: Asegurar que Python pueda encontrar el módulo 'servidor3' en la ruta de trabajo.
export PYTHONPATH=/app:$PYTHONPATH
# 2. Ejecutar Gunicorn. Llama a la función 'create_app' del módulo 'servidor3'.
exec gunicorn -b 0.0.0.0:7860 servidor3:create_app
