# Dockerfile Unificado (Backend + Visor IA)
FROM python:3.10-slim

# 1. Instalar dependencias de sistema (Git y Gráficos para IA)
RUN apt-get update && apt-get install -y \
    git \
    git-lfs \
    libgl1-mesa-glx \
    libglib2.0-0 \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# 2. Activar Git LFS (Para modelos pesados)
RUN git lfs install

# 3. Carpeta de trabajo
WORKDIR /app

# 4. Instalar librerías Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 5. Crear usuario seguro (Requisito de Hugging Face)
RUN useradd -m -u 1000 user
USER user
ENV HOME=/home/user \
    PATH=/home/user/.local/bin:$PATH

# 6. Copiar todo el código
COPY --chown=user . .

# 7. Crear carpeta de uploads
RUN mkdir -p /app/uploads && chmod 777 /app/uploads

# 8. Exponer puerto
EXPOSE 7860

# 9. COMANDO MAESTRO: Arrancar Servidor 1 (Backend)
# Nota: En este Space correremos el Backend Principal (servidor.py)
CMD ["gunicorn", "-b", "0.0.0.0:7860", "servidor:app", "--timeout", "120"]