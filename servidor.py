# coo.py (v25.0 - NANO COO SUITE - FULL ACCESS)
# ROL: Chief Operating Officer
# ACTUALIZACIÓN: 
# - Integración total de "X-Admin-Key" en todas las consultas para ver datos ocultos.
# - Sistema Heartbeat activo para aparecer Online.
# - Chat Global enlazado.

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, scrolledtext, filedialog
import requests
import json
import threading
import time
import os
from datetime import datetime
import calendar
from pathlib import Path

# --- CONFIGURACIÓN ---
API_URL = "https://nano-xtremertx-nano-backend.hf.space"
ADMIN_BACKEND_KEY = "NANO_MASTER_KEY_2025" # <--- ESTA LLAVE ABRE TODAS LAS PUERTAS
ADMIN_LOCAL_KEY = "121351" 
HEADERS = {"X-Admin-Key": ADMIN_BACKEND_KEY}

# --- COLORES DARK TECH ---
C_BG = "#0a0a0a"       
C_PANEL = "#161b22"    
C_HEADER = "#0d1117"   
C_ACCENT = "#00BFFF"   # Cyan
C_GREEN = "#238636"    # Verde
C_RED = "#da3633"      # Rojo
C_YELLOW = "#facc15"   # Amarillo
C_TEXT = "#e6edf3"     
C_MUTED = "#8b949e"    

# --- UTILIDADES ---
def format_date(iso):
    try: return datetime.fromisoformat(iso.replace("Z", "+00:00")).strftime('%d/%m %H:%M') if iso else "N/A"
    except: return "N/A"

def check_auth(title, cb):
    if simpledialog.askstring("Seguridad", f"🔑 Clave para: {title}", show='*') == ADMIN_LOCAL_KEY: cb()
    else: messagebox.showerror("Error", "Clave Incorrecta")

# ==========================================================
# 💬 SISTEMA DE CHAT
# ==========================================================
class ChatManager:
    def __init__(self, app, user_id="COO"):
        self.app = app; self.user = user_id; self.messages = []; self.running = True
        
    def start_sync(self):
        def loop():
            while self.running:
                try:
                    # La Key permite leer el historial aunque esté en carpeta privada
                    r = requests.get(f"{API_URL}/api/chat/history", headers=HEADERS, timeout=5)
                    if r.ok:
                        new_data = r.json()
                        if len(new_data) != len(self.messages):
                            self.messages = new_data
                            if hasattr(self.app, 'chat_window') and self.app.chat_window.winfo_exists():
                                self.app.after(0, self.app.render_chat_window)
                except: pass
                time.sleep(3) 
        threading.Thread(target=loop, daemon=True).start()

    def send(self, msg):
        threading.Thread(target=lambda: requests.post(f"{API_URL}/api/chat/send", json={"user": self.user, "msg": msg}, headers=HEADERS), daemon=True).start()

# ==========================================================
# 📱 CLASE PRINCIPAL: COO APP
# ==========================================================
class COOMasterApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("NANO COO v25.0 [Admin Mode]")
        self.geometry("380x720")
        self.resizable(False, False)
        self.configure(bg=C_BG)

        self.chat_sys = ChatManager(self, "COO")
        self.current_view = "inicio"
        self.current_frame = None
        self.dock_btns = {}
        
        # Datos
        self.metrics = {
            'logs': 0, 'reports': 0, 'updates': 0, 'active_users': 0, 'operationFiles': 0,
            'mockLogData': [], 'mockIncidentData': [], 'mockUpdateData': [], 'mockOperationFiles': []
        }
        self.solved_incidents = set()
        self.current_dir = None 

        self.setup_ui()
        
        # INICIO SECUENCIAL PARA GARANTIZAR CONEXIÓN
        self.start_heartbeat()     # 1. Avisar presencia
        self.chat_sys.start_sync() # 2. Conectar Chat
        self.after(1000, self.refresh_all_data) # 3. Descargar datos seguros

    def setup_ui(self):
        s = ttk.Style(); s.theme_use("clam")
        s.configure("Treeview", background=C_PANEL, foreground=C_TEXT, fieldbackground=C_PANEL, borderwidth=0, rowheight=35, font=("Segoe UI", 9))
        s.configure("Treeview.Heading", background=C_HEADER, foreground=C_ACCENT, font=("Segoe UI", 9, "bold"), borderwidth=0)
        s.map("Treeview", background=[("selected", "#2a2a2a")], foreground=[("selected", "white")])
        
        # Estilo Barra de Progreso
        s.configure("Horizontal.TProgressbar", background=C_GREEN, troughcolor=C_PANEL, bordercolor=C_BG, lightcolor=C_GREEN, darkcolor=C_GREEN)

        self.header = tk.Frame(self, bg=C_HEADER, height=50); self.header.pack(fill=tk.X, side=tk.TOP)
        self.lbl_title = tk.Label(self.header, text="COO SUITE", bg=C_HEADER, fg=C_ACCENT, font=("Segoe UI", 12, "bold")); self.lbl_title.pack(pady=12)

        self.dock = tk.Frame(self, bg=C_HEADER, height=60); self.dock.pack(fill=tk.X, side=tk.BOTTOM); self.dock.pack_propagate(0)
        self.container = tk.Frame(self, bg=C_BG); self.container.pack(fill=tk.BOTH, expand=True)

        btns = [("inicio", "🏠", "Inicio"), ("diag", "🩺", "Diagnóstico"), ("ops", "⚙️", "Ops")]
        for k, i, t in btns:
            b = tk.Label(self.dock, text=f"{i}\n{t}", bg=C_HEADER, fg=C_MUTED, cursor="hand2", font=("Segoe UI", 8))
            b.bind("<Button-1>", lambda e, v=k: self.switch_view(v))
            b.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            self.dock_btns[k] = b
            
        self.switch_view("inicio")

    def switch_view(self, view):
        self.current_view = view
        if self.current_frame: self.current_frame.destroy()
        for k, b in self.dock_btns.items(): b.config(fg=C_ACCENT if k==view else C_MUTED)
        
        if view == "inicio": self.build_inicio()
        elif view == "diag": self.build_diag()
        elif view == "ops": self.build_ops()
        self.current_frame.pack(fill=tk.BOTH, expand=True)

    def refresh_all_data(self):
        threading.Thread(target=self.fetch_metrics_thread, daemon=True).start()

    def fetch_metrics_thread(self):
        def get(url): 
            try: 
                # IMPORTANTE: Enviamos HEADERS con la Key Maestra
                r = requests.get(f"{API_URL}{url}", headers=HEADERS, timeout=10)
                return r.json() if r.status_code==200 else []
            except: return []

        logs = get("/api/logs/historical")
        incs = get("/api/logs/incidents")
        ups = get("/api/updates/list")
        users = get("/api/online-users")
        ops = get("/api/documentos/operaciones")

        self.metrics['logs'] = len(logs); self.metrics['mockLogData'] = logs
        
        # Detectar resueltos
        for l in logs:
            if l and isinstance(l, dict) and "RESPUESTA_INCIDENTE_" in l.get('quality', ''):
                try: self.solved_incidents.add(int(l['quality'].split('_')[-1]))
                except: pass

        pendientes = [i for i in incs if i.get('id') not in self.solved_incidents]

        self.metrics['reports'] = len(pendientes)
        self.metrics['mockIncidentData'] = incs
        self.metrics['updates'] = len(ups); self.metrics['mockUpdateData'] = ups
        self.metrics['active_users'] = users.get('count', 0) if isinstance(users, dict) else 0
        
        # Filtro solo PDFs/Carpetas para contador
        self.metrics['mockOperationFiles'] = ops if isinstance(ops, list) else []
        valid_files = [f for f in self.metrics['mockOperationFiles'] if f.get('type')=='folder' or f.get('name','').lower().endswith('.pdf')]
        self.metrics['operationFiles'] = len(valid_files)

        if self.current_view == "inicio": self.after(0, self.safe_refresh_dashboard)
        if self.current_view == "ops": self.after(0, self.render_ops_list)

    def start_heartbeat(self):
        def loop():
            while True:
                try: requests.post(f"{API_URL}/api/heartbeat", json={"username": "COO_Console"}, timeout=5)
                except: pass
                time.sleep(30)
        threading.Thread(target=loop, daemon=True).start()

    def api_req(self, end, cb, method='GET', data=None, files=None):
        def run():
            try:
                h = HEADERS.copy()
                if files and 'Content-Type' in h: del h['Content-Type']
                r = requests.request(method, f"{API_URL}{end}", headers=h, data=(json.dumps(data) if data and not files else None) if not files else data, files=files)
                if r.ok: self.after(0, lambda: cb(r.json() if r.text else {}))
                else: self.after(0, lambda: cb(None))
            except: self.after(0, lambda: cb(None))
        threading.Thread(target=run, daemon=True).start()

    # ==========================================================
    # 🏠 VISTA 1: INICIO (DISEÑO CFO + CHAT)
    # ==========================================================
    def build_inicio(self):
        self.lbl_title.config(text="PANEL OPERATIVO", fg=C_ACCENT)
        f = tk.Frame(self.container, bg=C_BG); self.current_frame = f
        
        canvas = tk.Canvas(f, bg=C_BG, bd=0, highlightthickness=0); 
        scrollbar = ttk.Scrollbar(f, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=C_BG)
        
        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw", width=360) 
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # BIG NUMBER
        self.lbl_big_num = tk.Label(scrollable_frame, text="...", bg=C_BG, fg=C_RED, font=("Segoe UI", 28, "bold"))
        tk.Label(scrollable_frame, text="INCIDENTES ACTIVOS", bg=C_BG, fg=C_MUTED, font=("Segoe UI", 8)).pack(pady=(20,0))
        self.lbl_big_num.pack(pady=(0, 20))

        # CARDS
        grid = tk.Frame(scrollable_frame, bg=C_BG); grid.pack(fill=tk.X, padx=10)
        grid.columnconfigure(0, weight=1); grid.columnconfigure(1, weight=1)
        
        def card(r, c, t, v, col):
            fr = tk.Frame(grid, bg=C_PANEL, padx=10, pady=10)
            fr.grid(row=r, column=c, sticky="nsew", padx=5, pady=5)
            tk.Label(fr, text=t, bg=C_PANEL, fg=C_MUTED, font=("Segoe UI", 7, "bold")).pack(anchor="w")
            lbl = tk.Label(fr, text=str(v), bg=C_PANEL, fg=col, font=("Segoe UI", 14, "bold"))
            lbl.pack(anchor="e")
            return lbl

        self.lbl_users = card(0, 0, "USUARIOS ONLINE", "...", C_GREEN)
        self.lbl_files = card(0, 1, "ARCHIVOS OPS", "...", C_YELLOW)
        self.lbl_logs = card(1, 0, "LOGS TOTALES", "...", C_TEXT)
        self.lbl_patches = card(1, 1, "PARCHES", "...", C_ACCENT)

        # BOTONES
        btn_f = tk.Frame(scrollable_frame, bg=C_BG); btn_f.pack(fill=tk.X, pady=20, padx=15)
        tk.Button(btn_f, text="💬 CHAT EJECUTIVO", command=self.open_chat_window, bg=C_PANEL, fg=C_YELLOW, bd=0, font=("Segoe UI", 10, "bold"), pady=10).pack(fill=tk.X, pady=5)
        tk.Button(btn_f, text="⟳ Sincronizar Datos", command=self.refresh_all_data, bg=C_PANEL, fg=C_TEXT, bd=0, font=("Segoe UI", 9)).pack(fill=tk.X)

        self.safe_refresh_dashboard()

    def safe_refresh_dashboard(self):
        if self.current_view == "inicio" and hasattr(self, 'lbl_big_num'):
            n = self.metrics['reports']
            color = C_RED if n > 0 else C_GREEN
            self.lbl_big_num.config(text=str(n), fg=color)
            self.lbl_users.config(text=str(self.metrics['active_users']))
            self.lbl_files.config(text=str(self.metrics['operationFiles']))
            self.lbl_logs.config(text=str(self.metrics['logs']))
            self.lbl_patches.config(text=str(self.metrics['updates']))

    # --- CHAT POPUP ---
    def open_chat_window(self):
        top = tk.Toplevel(self); top.title("Chat Ejecutivo"); top.geometry("380x600"); top.configure(bg=C_BG)
        tk.Label(top, text="MURO DE COMUNICACIÓN", bg=C_HEADER, fg=C_ACCENT, font=("Segoe UI", 12, "bold"), pady=10).pack(fill=tk.X)
        self.chat_window = scrolledtext.ScrolledText(top, bg=C_PANEL, fg="white", font=("Segoe UI", 9), bd=0, padx=10, pady=10)
        self.chat_window.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.render_chat_window()
        
        ifrm = tk.Frame(top, bg=C_PANEL, padx=10, pady=10); ifrm.pack(fill=tk.X)
        ent = tk.Entry(ifrm, bg=C_BG, fg="white", insertbackground="white", relief="flat")
        ent.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=5)
        
        def send():
            m = ent.get().strip()
            if m: self.chat_sys.send(m); ent.delete(0, tk.END); self.chat_window.config(state='normal'); self.chat_window.insert(tk.END, "> Enviando...\n", "temp"); self.chat_window.config(state='disabled')
        
        ent.bind("<Return>", lambda e: send())
        tk.Button(ifrm, text="➤", command=send, bg=C_GREEN, fg="white", bd=0, width=4).pack(side=tk.RIGHT, padx=(5,0))

    def render_chat_window(self):
        if not hasattr(self, 'chat_window') or not self.chat_window.winfo_exists(): return
        self.chat_window.config(state='normal'); self.chat_window.delete(1.0, tk.END)
        for m in self.chat_sys.messages[-30:]:
            user = m.get('user','Anon')
            col = C_ACCENT if user=="COO" else (C_YELLOW if user=="CTO" else C_GREEN)
            self.chat_window.insert(tk.END, f"[{m.get('date')}] {user}: ", "meta")
            self.chat_window.insert(tk.END, f"{m.get('msg')}\n\n", "text")
            self.chat_window.tag_config("meta", foreground=col, font=("Segoe UI", 8, "bold"))
            self.chat_window.tag_config("text", foreground="white")
        self.chat_window.see(tk.END); self.chat_window.config(state='disabled')

    # ==========================================================
    # 🩺 VISTA 2: DIAGNÓSTICO (AVANZADO)
    # ==========================================================
    def build_diag(self):
        self.lbl_title.config(text="DIAGNÓSTICO", fg=C_RED)
        f = tk.Frame(self.container, bg=C_BG); self.current_frame = f
        scroll = tk.Frame(f, bg=C_BG); scroll.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        def admin_btn(title, icon, count, color, cmd):
            btn = tk.Frame(scroll, bg=C_PANEL, pady=15, padx=15); btn.pack(fill=tk.X, pady=8)
            tk.Label(btn, text=icon, bg=C_PANEL, fg=color, font=("Segoe UI", 20)).pack(side=tk.LEFT)
            info = tk.Frame(btn, bg=C_PANEL); info.pack(side=tk.LEFT, padx=15)
            tk.Label(info, text=title, bg=C_PANEL, fg="white", font=("Segoe UI", 12, "bold")).pack(anchor="w")
            tk.Label(info, text=f"{count} registros", bg=C_PANEL, fg=C_MUTED, font=("Segoe UI", 9)).pack(anchor="w")
            tk.Button(btn, text="ABRIR", command=cmd, bg=C_BG, fg=color, bd=0, font=("Segoe UI", 9, "bold")).pack(side=tk.RIGHT)

        admin_btn("LOGS HISTÓRICOS", "📜", self.metrics['logs'], C_ACCENT, self.show_logs_window)
        admin_btn("INCIDENTES", "⚠️", self.metrics['reports'], C_RED, self.show_incidents_window)
        admin_btn("ACTUALIZACIONES", "🚀", self.metrics['updates'], C_YELLOW, self.show_updates_window)

    # --- LOGS: DESCARGAR ---
    def show_logs_window(self):
        top = tk.Toplevel(self); top.title("Logs Históricos"); top.geometry("400x600"); top.configure(bg=C_BG)
        tree = ttk.Treeview(top, columns=("User","IP","Date"), show="headings"); tree.pack(fill=tk.BOTH, expand=True)
        for c in ["User","IP","Date"]: tree.heading(c, text=c)
        for d in self.metrics['mockLogData']: 
            if d and isinstance(d, dict):
                tree.insert("", "end", iid=d.get('id',0), values=(d.get('user'), d.get('ip','N/A'), format_date(d.get('date'))))
        
        def download_log():
            sel = tree.selection(); 
            if not sel: return
            item = next((x for x in self.metrics['mockLogData'] if str(x.get('id'))==sel[0]), None)
            if item and item.get('filename'): 
                self.download_file_real(f"/logs_historical/{item['filename']}", item['filename'])
            
        tk.Button(top, text="📥 DESCARGAR LOG", command=download_log, bg=C_ACCENT, fg="black").pack(fill=tk.X, pady=10)

    # --- INCIDENTES: DESCARGAR Y RESPONDER ---
    def show_incidents_window(self):
        top = tk.Toplevel(self); top.title("Incidentes"); top.geometry("450x650"); top.configure(bg=C_BG)
        tree = ttk.Treeview(top, columns=("User","Date","State"), show="headings"); tree.pack(fill=tk.BOTH, expand=True)
        tree.heading("User", text="USUARIO"); tree.heading("Date", text="FECHA"); tree.heading("State", text="ESTADO")
        
        for i in self.metrics['mockIncidentData']:
            if not i or not isinstance(i, dict): continue
            state = "✅ RESUELTO" if i.get('id') in self.solved_incidents else "❌ PENDIENTE"
            tree.insert("", "end", iid=i.get('id'), values=(i.get('user'), format_date(i.get('date')), state))

        def open_detail(event):
            sel = tree.selection(); 
            if not sel: return
            inc = next((x for x in self.metrics['mockIncidentData'] if str(x.get('id'))==sel[0]), None)
            if not inc: return
            
            det = tk.Toplevel(self); det.title("Detalle Incidente"); det.geometry("400x500"); det.configure(bg=C_PANEL)
            tk.Label(det, text=f"Reporte de {inc.get('user')}", bg=C_PANEL, fg=C_ACCENT, font=("Segoe UI", 12, "bold")).pack(pady=10)
            msg_box = tk.Text(det, height=5, bg=C_BG, fg="white", bd=0); msg_box.pack(fill=tk.X, padx=10)
            msg_box.insert(tk.END, inc.get('message','')); msg_box.config(state='disabled')
            
            if inc.get('filename') and inc.get('filename') != 'N/A':
                tk.Button(det, text="📥 DESCARGAR LOG ADJUNTO", bg=C_YELLOW, fg="black", 
                          command=lambda: self.download_file_real(f"/logs_incidents/{inc['filename']}", inc['filename'])).pack(fill=tk.X, padx=10, pady=5)

            tk.Label(det, text="RESPONDER CON PARCHE (.py)", bg=C_PANEL, fg=C_GREEN, font=("Segoe UI", 10, "bold")).pack(pady=(15,5))
            resp_txt = tk.Text(det, height=3, bg=C_BG, fg="white"); resp_txt.pack(fill=tk.X, padx=10)
            
            def send_reply():
                msg = resp_txt.get("1.0", tk.END).strip()
                if not msg: return messagebox.showerror("Error", "Escribe un mensaje.")
                file_path = filedialog.askopenfilename(filetypes=[("Python", "*.py")])
                
                # Si selecciona archivo, se sube. Si no, solo responde texto.
                if file_path:
                    with open(file_path, 'rb') as f:
                        requests.post(f"{API_URL}/api/documentos/upload", headers=HEADERS, 
                                      data={'section':'operaciones', 'parentId':None}, 
                                      files={'file':(os.path.basename(file_path), f.read())})
                
                requests.post(f"{API_URL}/api/logs/historical", headers={"X-Username":"COO"}, 
                              json={"quality": f"RESPUESTA_INCIDENTE_{inc['id']}"})
                
                self.solved_incidents.add(inc['id'])
                messagebox.showinfo("Éxito", "Respuesta enviada."); det.destroy(); top.destroy(); self.refresh_all_data()

            tk.Button(det, text="ENVIAR RESPUESTA", command=send_reply, bg=C_GREEN, fg="white", pady=10).pack(fill=tk.X, padx=10, pady=10)

        tree.bind("<Double-1>", open_detail)

    def show_updates_window(self):
        top = tk.Toplevel(self); top.title("Actualizaciones"); top.geometry("400x400"); top.configure(bg=C_BG)
        tree = ttk.Treeview(top, columns=("File","Ver"), show="headings"); tree.pack(fill=tk.BOTH, expand=True)
        tree.heading("File", text="ARCHIVO"); tree.heading("Ver", text="VERSIÓN")
        for u in self.metrics['mockUpdateData']: 
             if u and isinstance(u, dict):
                 tree.insert("", "end", values=(u.get('filename'), u.get('version')))
        
        def upload_patch():
            p = filedialog.askopenfilename(filetypes=[("Python Script", "*.py"), ("All Files", "*.*")])
            if p:
                try:
                    with open(p, 'rb') as f:
                        r = requests.post(f"{API_URL}/api/updates/upload", headers={"X-Admin-Key": ADMIN_BACKEND_KEY, "X-Vercel-Filename": os.path.basename(p)}, data=f.read())
                    if r.status_code==201: messagebox.showinfo("OK", "Parche subido."); top.destroy(); self.refresh_all_data()
                except Exception as e: messagebox.showerror("Error", str(e))
        
        tk.Button(top, text="⬆️ SUBIR PARCHE (.PY)", command=upload_patch, bg=C_YELLOW, fg="black", pady=10).pack(fill=tk.X)

    # --- FUNCIÓN REAL DE DESCARGA AL DISCO ---
    def download_file_real(self, endpoint, filename):
        url = f"{API_URL}{endpoint}"
        save_path = filedialog.asksaveasfilename(initialfile=filename, title="Guardar archivo como...")
        if not save_path: return
        
        try:
            r = requests.get(url, stream=True)
            if r.status_code == 200:
                with open(save_path, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192): f.write(chunk)
                messagebox.showinfo("Descarga", f"Archivo guardado en:\n{save_path}")
            else:
                messagebox.showerror("Error", f"Error del servidor: {r.status_code}")
        except Exception as e:
            messagebox.showerror("Error", f"Fallo en descarga: {e}")

    # ==========================================================
    # ⚙️ VISTA 3: OPERACIONES (DOCUMENTOS)
    # ==========================================================
    def build_ops(self):
        self.lbl_title.config(text="OPERACIONES", fg=C_YELLOW)
        f = tk.Frame(self.container, bg=C_BG); self.current_frame = f
        bar = tk.Frame(f, bg=C_BG, pady=5, padx=10); bar.pack(fill=tk.X)
        if self.current_dir: tk.Button(bar, text="⬅", command=self.ops_back, bg=C_PANEL, fg="white", bd=0, width=4).pack(side=tk.LEFT)
        tk.Button(bar, text="+📂", command=self.ops_new, bg=C_YELLOW, fg="black", bd=0, width=4).pack(side=tk.RIGHT, padx=2)
        tk.Button(bar, text="+📄", command=self.ops_up, bg=C_GREEN, fg="white", bd=0, width=4).pack(side=tk.RIGHT, padx=2)
        self.ops_scroll = tk.Frame(f, bg=C_BG); self.ops_scroll.pack(fill=tk.BOTH, expand=True, padx=10); self.render_ops_list()

    def render_ops_list(self):
        for w in self.ops_scroll.winfo_children(): w.destroy()
        def nm(v): return int(v) if v not in [None, 'null'] and str(v).isdigit() else None
        items = [x for x in self.metrics['mockOperationFiles'] if nm(x.get('parent_id')) == nm(self.current_dir)]
        
        # FILTRO: Solo carpetas y PDFs
        valid_items = [i for i in items if i.get('type')=='folder' or i.get('name','').lower().endswith('.pdf')]

        if not valid_items: tk.Label(self.ops_scroll, text="(Vacío)", bg=C_BG, fg=C_MUTED).pack(pady=20)
        for i in valid_items:
            r = tk.Frame(self.ops_scroll, bg=C_PANEL, pady=8, padx=10); r.pack(fill=tk.X, pady=2)
            fol = i.get('type')=='folder'
            tk.Label(r, text=f"{'📁' if fol else '📄'} {i['name']}", bg=C_PANEL, fg=(C_YELLOW if fol else C_ACCENT)).pack(side=tk.LEFT)
            r.bind("<Button-1>", lambda e, x=i: (setattr(self, 'current_dir', x['id']) or self.render_ops_list()) if x.get('type')=='folder' else None)
            tk.Button(r, text="X", command=lambda x=i: self.ops_del(x), bg=C_RED, fg="white", bd=0, width=3).pack(side=tk.RIGHT)

    def ops_back(self):
        c = next((x for x in self.metrics['mockOperationFiles'] if x['id'] == self.current_dir), None)
        self.current_dir = c.get('parent_id') if c else None; self.render_ops_list()
    
    def ops_new(self): 
        n = simpledialog.askstring("Nueva", "Nombre:")
        if n: self.api_req("/api/documentos/create-folder", lambda r: self.refresh_all_data(), method='POST', data={'name':n, 'section':'operaciones', 'parentId':self.current_dir})
    def ops_up(self): 
        p = filedialog.askopenfilename(filetypes=[("PDF","*.pdf")])
        if p: 
            def run(): requests.post(f"{API_URL}/api/documentos/upload", headers=HEADERS, data={'section':'operaciones', 'parentId':self.current_dir}, files={'file':(os.path.basename(p), open(p,'rb').read())}); self.after(0, self.refresh_all_data)
            threading.Thread(target=run).start()
    def ops_del(self, i): check_auth("Borrar", lambda: self.api_req(f"/api/documentos/delete/{i['id']}", lambda r: self.refresh_all_data(), method='DELETE'))

if __name__ == "__main__":
    app = COOMasterApp()
    app.mainloop()
