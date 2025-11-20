# lector.py (v10.15 - Limpio: Sin Firma Visual, Sin Bloqueo de Capturas)
# NOTA: Se ha eliminado la inyección de firma (imagen limpia).
# NOTA: Se ha eliminado el sistema Anti-Robo y Blacklist de procesos.
# NOTA: La ventana ya no bloquea el foco (se puede minimizar/cambiar ventana).
# NOTA: MANTIENE sistema de "Strikes" (Integridad de Tracker) y Logs.

import sys
import os
import pickle
import numpy as np
from PIL import Image, ImageTk
from pathlib import Path
import tkinter as tk
from tkinter import font, messagebox, simpledialog, scrolledtext
import threading
import io
import zlib
import argparse
import base64
import hashlib
import subprocess
import time
import traceback
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import json
import random

# --- SOPORTE PARA BORDES REDONDEADOS (SOLO VISUAL) ---
WINDOWS_ROUNDED_SUPPORT = False
try:
    import ctypes
    from ctypes import wintypes
    DWM_NCA_STATUS = 1; DWM_NCA_STATUS_BORDER = 0x00000001
    DWMWA_WINDOW_CORNER_PREFERENCE = 33; DWMWCP_ROUND = 2
    SWP_FRAMECHANGED = 0x0020; SWP_NOMOVE = 0x0002; SWP_NOSIZE = 0x0001
    HWND_TOP = 0
    _windll = ctypes.windll; _user32 = _windll.user32
    _gdi32 = _windll.gdi32; _dwmapi = _windll.dwmapi
    _SetWindowRgn = _user32.SetWindowRgn
    _CreateRoundRectRgn = _gdi32.CreateRoundRectRgn
    _DeleteObject = _gdi32.DeleteObject
    _SetWindowPos = _user32.SetWindowPos
    WINDOWS_ROUNDED_SUPPORT = True
except (ImportError, AttributeError, Exception):
    pass

# --- NOMBRES DE MODELOS ---
GENESIS_NAME = 'kiphu_genesis_engine.keras'
ODIN_NAME = 'odin_corrector.keras'
GENERALISTA_NAME = 'generalista_hd_best.keras'
LEXICON_NAME = 'khipu_lexicon.npy'

# --- CONSTANTES DE TRACKER ---
def get_app_path():
    if getattr(sys, 'frozen', False):
        if hasattr(sys, '_MEIPASS'):
            return Path(sys._MEIPASS)
        return Path(sys.executable).parent
    return Path(__file__).parent

BASE_DIR = get_app_path()
STRIKE_LIMIT = 5
LECTOR_SECRET_KEY = "k!p#u@tr&n(e)s-2c$r%t-LECTOR_SECURE" 
LECTOR_TRACKER_FILE = BASE_DIR / "lector_tracker.dat"
LECTOR_WITNESS_FILE = BASE_DIR / ".lector_witness"
LECTOR_LOCK_FILE = BASE_DIR / ".lector_lock"
ANTIROBO_LOG_PATH = BASE_DIR / "antirobo_local_events.log"

# --- FUNCIONES DE STRIKES (SISTEMA CONSERVADO) ---
def _generate_lector_signature(data_dict):
    temp_dict = data_dict.copy()
    if 'signature' in temp_dict:
        del temp_dict['signature']
    data_string = f"{temp_dict.get('strikes', 0)}-{LECTOR_SECRET_KEY}"
    return hashlib.sha256(data_string.encode()).hexdigest()

def _initiate_lockdown_lector(reason):
    # Bloqueo por manipulación de archivos de seguridad
    messagebox.showerror("Error de Seguridad", f"El lector ha sido bloqueado.\nMotivo: {reason}")
    try:
        with open(LECTOR_LOCK_FILE, 'w') as f:
            f.write(time.asctime())
    except:
        pass

def check_for_lockdown_lector():
    if LECTOR_LOCK_FILE.exists():
        return True
    return False

def load_or_initialize_lector_tracker():
    tracker_exists = LECTOR_TRACKER_FILE.exists()
    witness_exists = LECTOR_WITNESS_FILE.exists()

    if not tracker_exists and witness_exists:
        _initiate_lockdown_lector("Archivo de tracker principal ausente (Manipulación detectada).")
        return None
    
    if tracker_exists:
        try:
            with open(LECTOR_TRACKER_FILE, 'r') as f:
                data = json.load(f)
            
            signature = data.pop('signature', None)
            if signature != _generate_lector_signature(data):
                _initiate_lockdown_lector("Firma de tracker inválida.")
                return None

            data['signature'] = signature
            
            if not witness_exists:
                with open(LECTOR_WITNESS_FILE, 'w') as f: f.write(time.asctime())

            return data
            
        except Exception as e:
            _initiate_lockdown_lector(f"Error al leer el tracker ({e})")
            return None
    
    elif not tracker_exists and not witness_exists:
        try:
            data = {'strikes': 0}
            data['signature'] = _generate_lector_signature(data)
            
            with open(LECTOR_TRACKER_FILE, 'w') as f:
                json.dump(data, f, indent=4)
            with open(LECTOR_WITNESS_FILE, 'w') as f:
                f.write(time.asctime())
            
            return data
        except Exception as e:
            _initiate_lockdown_lector(f"No se pudo crear el sistema de tracker. ({e})")
            return None
    
    _initiate_lockdown_lector("Inconsistencia en archivos de tracker.")
    return None

def increment_lector_strike_count():
    try:
        data = load_or_initialize_lector_tracker()
        if data is None: return STRIKE_LIMIT + 1
        
        count = data.get("strikes", 0) + 1
        data["strikes"] = count
        data["signature"] = _generate_lector_signature(data)
        
        with open(LECTOR_TRACKER_FILE, 'w') as f:
            json.dump(data, f, indent=4)
            
        return count
    except Exception:
        return STRIKE_LIMIT + 1

# --- FUNCIONES DE DESENCRIPTACIÓN ---
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def decrypt_data(encrypted_crs_data: dict, password: str) -> dict | None:
    try:
        salt, encrypted_data = encrypted_crs_data['salt'], encrypted_crs_data['encrypted_data']
        fernet = Fernet(derive_key(password, salt))
        decrypted_pickle = fernet.decrypt(encrypted_data)
        return pickle.loads(decrypted_pickle)
    except InvalidToken:
        raise ValueError("Contraseña inválida o archivo corrupto.")
    except Exception as e:
        raise RuntimeError(f"Ocurrió un error grave durante la desencriptación: {e}")

def paeth_predictor(a, b, c):
    p = a + b - c; pa = abs(p - a); pb = abs(p - b); pc = abs(p - c)
    if pa <= pb and pa <= pc: return a
    elif pb <= pc: return b
    else: return c

# ---------------------------
# (ELIMINADO) ANTI-ROBO Y BLACKLIST
# ---------------------------

TF_AVAILABLE = False
try:
    import tensorflow as tf
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
    TF_AVAILABLE = True
except ImportError:
    print("ADVERTENCIA: TensorFlow no encontrado. La reconstrucción de IA fallará.")
    pass

# --- VENTANA DE SOPORTE TÉCNICO (STRIKE SYSTEM) ---
class SoporteTecnicoWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Soporte Técnico - Lector Bloqueado")
        self.geometry("450x380")
        
        COLOR_FONDO_OSCURO = "#0D1117"
        COLOR_PANEL_BG = "#161B22"
        COLOR_TEXTO_NORMAL = "#E6EDF3"
        COLOR_TEXTO_ERROR = "#F85149"
        COLOR_PRINCIPAL_CYAN = "#00BFFF"
        
        self.configure(bg=COLOR_FONDO_OSCURO)
        self.resizable(False, False)
        
        try:
            screen_w = self.winfo_screenwidth()
            screen_h = self.winfo_screenheight()
            x = (screen_w // 2) - (450 // 2)
            y = (screen_h // 2) - (380 // 2)
            self.geometry(f"450x380+{x}+{y}")
        except Exception:
            pass

        self.protocol("WM_DELETE_WINDOW", self.destroy)
        
        main_frame = tk.Frame(self, bg=COLOR_PANEL_BG, padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        tk.Label(main_frame, text="ACCESO BLOQUEADO",
                 font=('Segoe UI', 14, 'bold'), bg=COLOR_PANEL_BG, fg=COLOR_TEXTO_ERROR).pack(pady=(0, 10))
        
        tk.Label(main_frame, text="Se ha superado el límite de intentos de seguridad.\nEl lector ha sido bloqueado permanentemente.",
                 font=('Segoe UI', 10), bg=COLOR_PANEL_BG, fg=COLOR_TEXTO_NORMAL, justify=tk.LEFT).pack(pady=(0, 15), anchor='w')

        tk.Label(main_frame, text="Escriba un reporte de incidente para el soporte:",
                 font=('Segoe UI', 10, 'bold'), bg=COLOR_PANEL_BG, fg=COLOR_TEXTO_NORMAL).pack(pady=(5, 5), anchor='w')

        self.text_widget = scrolledtext.ScrolledText(main_frame, height=6, width=50,
                                                     bg=COLOR_FONDO_OSCURO, fg=COLOR_TEXTO_NORMAL,
                                                     bd=1, relief=tk.SOLID, insertbackground="white",
                                                     font=('Segoe UI', 9))
        self.text_widget.pack(fill=tk.X, expand=True, pady=(0, 15))
        
        self.lbl_status = tk.Label(main_frame, text="",
                                   font=('Segoe UI', 9, 'italic'), bg=COLOR_PANEL_BG, fg=COLOR_PRINCIPAL_CYAN)
        self.lbl_status.pack(pady=(0, 10))

        self.btn_enviar = tk.Button(main_frame, text="Enviar Reporte de Incidente",
                                    font=('Segoe UI', 10, 'bold'), bg=COLOR_PRINCIPAL_CYAN, fg=COLOR_FONDO_OSCURO,
                                    relief=tk.FLAT, command=self.enviar_reporte_incidente)
        self.btn_enviar.pack(pady=(0, 10))

    def enviar_reporte_incidente(self):
        report_text = self.text_widget.get("1.0", tk.END).strip()
        
        if not report_text:
            self.lbl_status.config(text="Error: Por favor, escriba un breve reporte.")
            return

        self.btn_enviar.config(state=tk.DISABLED, text="Enviando...")
        self.lbl_status.config(text="Iniciando reporte...")
        self.update_idletasks()

        if not self.run_update_script(report_text):
            return

        self.lbl_status.config(text="Reporte enviado. Cierre esta ventana.")
        self.text_widget.config(state=tk.DISABLED)

    def run_update_script(self, report_text):
        update_script_path = BASE_DIR / "actualizacion.py"
        
        if not update_script_path.exists():
            self.lbl_status.config(text="Error: 'actualizacion.py' no encontrado.")
            self.btn_enviar.config(state=tk.NORMAL, text="Enviar Reporte")
            return False
            
        try:
            log_path_to_send = str(ANTIROBO_LOG_PATH)
            command = [
                sys.executable, 
                str(update_script_path), 
                "--mode", "incidente",
                "--mensaje", report_text, 
                "--log_path", log_path_to_send
            ]
            subprocess.Popen(
                command,
                cwd=BASE_DIR,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
            )
            return True
        except Exception as e:
            self.lbl_status.config(text=f"Error al ejecutar script: {e}")
            self.btn_enviar.config(state=tk.NORMAL, text="Enviar Reporte")
            return False

# --- CLASE PRINCIPAL DEL LECTOR ---
class ElegantViewer(tk.Tk):
    CONTROL_BAR_COLOR = "#252525"; TEXT_COLOR = "#d0d0d0"; BUTTON_HOVER_COLOR = "#3c3c3c"
    CORNER_RADIUS = 20

    def __init__(self, crs_path=None, models_dir=None, password=None):
        super().__init__()
        
        self.crs_path = Path(crs_path) if crs_path else None
        self.models_dir = Path(models_dir) if models_dir else BASE_DIR / "xtremertx_ai" / "models"
        self.password, self.models = password, {}

        self.original_image = None; self.zoom_level, self.rotation_angle = 1.0, 0
        self.image_offset_x, self.image_offset_y = 0, 0; self.pan_start_x, self.pan_start_y = 0, 0
        self.hq_render_job = None; self.is_fullscreen = False; self.original_geometry = None
        self.is_panning = False
        
        self.q_dna_value = ""

        self.withdraw()
        self._setup_window()
        self.attributes('-topmost', False) # Ya no fuerza topmost agresivo

        self._create_widgets(); self._bind_events()
        
        if self.crs_path and self.crs_path.is_file():
            self.start_reconstruction()
        else:
            self.after(0, self.deiconify)
            self.update_status("Esperando archivo .crs (Arrastre y suelte o abra con argumentos).")

    def _setup_window(self):
        self.geometry("900x700")
        # self.overrideredirect(True) # Opcional: Si quieres bordes nativos, comenta esto.
        self.overrideredirect(True) # Mantenemos estilo custom
        self.configure(bg="black")
        self.after(10, self.apply_window_visual_styles)
        self.after(20, self.set_appwindow)

    def apply_window_visual_styles(self):
        if not WINDOWS_ROUNDED_SUPPORT:
            return
        try:
            if not self.is_fullscreen:
                self.set_window_rounded_corners()
                self.set_window_shadow()
        except Exception:
            pass

    def clear_window_region(self):
        if WINDOWS_ROUNDED_SUPPORT:
            try:
                hwnd = self.winfo_id()
                _SetWindowRgn(hwnd, 0, True)
                _dwmapi.DwmSetWindowAttribute(hwnd, DWM_NCA_STATUS, ctypes.byref(ctypes.c_int(DWM_NCA_STATUS_BORDER)), ctypes.sizeof(ctypes.c_int))
                _SetWindowPos(hwnd, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_FRAMECHANGED)
            except Exception:
                pass

    def set_window_rounded_corners(self):
        if not WINDOWS_ROUNDED_SUPPORT: return
        try:
            hwnd = self.winfo_id()
            h_region = _CreateRoundRectRgn(0, 0, self.winfo_width(), self.winfo_height(), self.CORNER_RADIUS, self.CORNER_RADIUS)
            _SetWindowRgn(hwnd, h_region, True)
            _DeleteObject(h_region)
            if sys.platform == 'win32' and sys.getwindowsversion().build >= 22000:
                _dwmapi.DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, ctypes.byref(ctypes.c_int(DWMWCP_ROUND)), ctypes.sizeof(ctypes.c_int))
            _SetWindowPos(hwnd, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_FRAMECHANGED)
        except Exception:
            pass

    def set_window_shadow(self):
        if not WINDOWS_ROUNDED_SUPPORT: return
        try:
            hwnd = self.winfo_id()
            _dwmapi.DwmSetWindowAttribute(hwnd, DWM_NCA_STATUS, ctypes.byref(ctypes.c_int(DWM_NCA_STATUS_BORDER)), ctypes.sizeof(ctypes.c_int))
        except Exception:
             pass

    def _create_widgets(self):
        self.default_font = font.nametofont("TkDefaultFont"); self.default_font.configure(family="Segoe UI", size=9)
        self.icon_font = font.Font(family="Segoe UI Symbol", size=12)

        self.grid_rowconfigure(1, weight=1); self.grid_columnconfigure(0, weight=1)

        self.title_bar = tk.Frame(self, bg="black", height=25)
        self.title_bar.grid(row=0, column=0, sticky="new")
        self._create_title_bar_widgets()

        self.canvas = tk.Canvas(self, bg="black", bd=0, highlightthickness=0)
        self.canvas.grid(row=1, column=0, sticky="nsew")

        self.control_panel = tk.Frame(self, bg=self.CONTROL_BAR_COLOR)
        self.control_panel.grid(row=2, column=0, sticky="ew")

        self._create_control_buttons()

        id_frame = tk.Frame(self.control_panel, bg=self.CONTROL_BAR_COLOR)
        id_frame.pack(side="left", padx=20, fill='y', pady=2) 

        self.fingerprint_label = tk.Label(id_frame, text="", bg=self.CONTROL_BAR_COLOR, fg="#a0a0a0", font=(self.default_font, 8), anchor="w")
        self.fingerprint_label.pack(side="left", anchor="w")

        self.status_label = tk.Label(self.control_panel, text="Iniciando...", bg=self.CONTROL_BAR_COLOR, fg=self.TEXT_COLOR, font=(self.default_font, 8), anchor="e")
        self.status_label.pack(side="right", padx=10, fill='y')

    def _create_title_bar_widgets(self):
        title_label = tk.Label(self.title_bar, text="lector (Modo Libre)", bg="black", fg=self.TEXT_COLOR, font=(self.default_font, 10, "bold"), padx=10, pady=5)
        title_label.pack(side="left")

        btn_exit = tk.Label(self.title_bar, text="✕", font=self.icon_font, bg="black", fg="#FF0000", padx=10, pady=0, cursor="hand2")
        btn_exit.pack(side="right")
        btn_exit.bind("<Button-1>", self.on_exit)
        btn_exit.bind("<Enter>", lambda e, w=btn_exit: w.config(bg="#7c0000", fg="white"))
        btn_exit.bind("<Leave>", lambda e, w=btn_exit: w.config(bg="black", fg="#FF0000"))

        self.title_bar.bind("<ButtonPress-1>", self.start_move)
        self.title_bar.bind("<B1-Motion>", self.do_move)
        title_label.bind("<ButtonPress-1>", self.start_move)
        title_label.bind("<B1-Motion>", self.do_move)

    def _create_control_buttons(self):
        buttons = [(" Zoom +", self.zoom_in, "+"),(" Zoom -", self.zoom_out, "-"),(" Ajustar ⛶", self.fit_to_screen, "F"),(" Rotar ⟲", self.rotate_left, "R"),(" Centrar ⌂", self.reset_view, "Inicio"),(" P. Completa ⤢", self.toggle_fullscreen, "F11")]

        button_container = tk.Frame(self.control_panel, bg=self.CONTROL_BAR_COLOR)
        button_container.pack(side="left", padx=5)
        for i, (text, command, shortcut) in enumerate(buttons):
            icon, desc = text.split(" ")[-1], " ".join(text.split(" ")[:-1]).strip()
            btn = tk.Label(button_container, text=icon, font=self.icon_font, bg=self.CONTROL_BAR_COLOR, fg=self.TEXT_COLOR, padx=10, pady=5, cursor="hand2")
            btn.pack(side="left")

            btn.bind("<Button-1>", lambda e, cmd=command: cmd())
            btn.bind("<Enter>", lambda e, w=btn: w.config(bg=self.BUTTON_HOVER_COLOR))
            btn.bind("<Leave>", lambda e, w=btn: w.config(bg=self.CONTROL_BAR_COLOR))
            Tooltip(btn, f"{desc} ({shortcut})")

    def _bind_events(self):
        self.canvas.bind("<ButtonPress-1>", self.start_pan)
        self.canvas.bind("<B1-Motion>", self.pan)
        self.canvas.bind("<ButtonRelease-1>", self.stop_pan)

        self.canvas.bind("<Double-Button-1>", self.toggle_fullscreen)
        self.canvas.bind("<MouseWheel>", self.zoom_on_scroll)
        self.canvas.bind("<Motion>", self.update_cursor_mode)

        self.canvas.bind("<Configure>", self._on_resize)
        self.bind("<Escape>", self.on_exit)
        self.bind("<F11>", self.toggle_fullscreen)
        self.bind("<plus>", self.zoom_in)
        self.bind("<minus>", self.zoom_out)
        self.bind("<r>", self.rotate_left)
        self.bind("f", self.fit_to_screen)
        self.bind("<Home>", self.reset_view)

    def on_exit(self, event=None):
        self.destroy()

    def start_reconstruction(self):
        if not TF_AVAILABLE:
            messagebox.showerror("Error de Dependencia", "TensorFlow no está instalado.\nEl lector no puede funcionar sin TensorFlow.")
            self.destroy()
            return
        self.update_status("Iniciando reconstrucción...");
        threading.Thread(target=self.reconstruct_in_memory, daemon=True).start()

    def load_model(self, model_name):
        if model_name not in self.models:
            self.after(0, lambda: self.update_status(f"Cargando {model_name}..."))
            path = self.models_dir / model_name
            if not path.exists(): raise FileNotFoundError(f"Modelo no encontrado: {model_name}. Revise que la carpeta de modelos esté en la ruta correcta: {self.models_dir}")
            if model_name.endswith('.keras'): self.models[model_name] = tf.keras.models.load_model(str(path), compile=False)
            elif model_name.endswith('.npy'): self.models[model_name] = np.load(path)
        return self.models[model_name]

    def prompt_for_password(self):
        password = simpledialog.askstring("Contraseña Requerida", "El archivo está protegido. Ingrese la clave:", parent=self, show='*')
        if password:
            self.password = password
            self.start_reconstruction()
        else:
            self.on_exit()

    def reconstruct_in_memory(self):
        if not self.crs_path: return
        original_author_value = None 

        try:
            with open(self.crs_path, "rb") as f:
                crs_data = pickle.load(f)
        except Exception as e:
            self.after(0, lambda e=e: messagebox.showerror("Error de Carga de Archivo (.crs)", f"No se pudo cargar el archivo .crs.\nError: {e}"))
            self.after(0, self.on_exit)
            return

        try:
            is_encrypted = crs_data.get('is_encrypted', False)

            if is_encrypted:
                if not self.password:
                    self.after(0, self.prompt_for_password)
                    return
                self.after(0, lambda: self.update_status("Desencriptando..."))
                crs_data = decrypt_data(crs_data, self.password)
            else:
                pass

            if crs_data is None:
                raise ValueError("Contraseña inválida.")

            original_author_value = crs_data.get("author_id") or crs_data.get("author")

            if original_author_value:
                self.q_dna_value = original_author_value
                self.after(0, lambda: self.fingerprint_label.config(text=f"ID Fingerprint: {original_author_value}"))

            file_version = crs_data.get("version", "legacy"); final_w, final_h = crs_data.get("true_original_shape", crs_data.get("original_shape"))[:2]

            self.after(0, lambda: self.update_status(f"Detectado: {file_version}..."))
            final_array = None

            if file_version.startswith("51."):
                khipu_lexicon=self.load_model(LEXICON_NAME);original_shape,compressed_tiles,tile_size=crs_data["original_shape"],crs_data["payload_list"],crs_data["tile_size"];reconstructed_array=np.zeros(original_shape,dtype=np.int16);tile_idx,total_tiles=0,len(compressed_tiles);border_pixel=np.array([0,0,0],dtype=np.int16)
                for y in range(0,original_shape[0],tile_size):
                    for x in range(0,original_shape[1],tile_size):
                        if tile_idx>=total_tiles:continue
                        encoded_array=np.frombuffer(zlib.decompress(compressed_tiles[tile_idx]),dtype=np.int16);flat_residual=[];i=0
                        while i<len(encoded_array):
                            if encoded_array[i]==32767:flat_residual.extend(khipu_lexicon[encoded_array[i+1]]);i+=2
                            else:flat_residual.append(encoded_array[i]);i+=1
                        h,w=min(tile_size,original_shape[0]-y),min(tile_size,original_shape[1]-x);residual_tile=np.array(flat_residual,dtype=np.int16).reshape((h,w,3))
                        for tile_y in range(h):
                            for tile_x in range(w):
                                abs_y,abs_x=y+tile_y,x+tile_x;a=reconstructed_array[abs_y,abs_x-1] if abs_x>0 else border_pixel;b=reconstructed_array[abs_y-1,abs_x] if abs_y>0 else border_pixel;c=reconstructed_array[abs_y-1,abs_x-1] if abs_y>0 and abs_x>0 else border_pixel;prediction=np.array([paeth_predictor(a[i],b[i],c[i]) for i in range(3)],dtype=np.int16);reconstructed_array[abs_y,abs_x]=prediction+residual_tile[tile_y,tile_x]
                        tile_idx+=1
                final_array=np.clip(reconstructed_array,0,255).astype(np.uint8)
            elif "Generalista" in file_version:
                generalista_model=self.load_model(GENERALISTA_NAME);core_seed,fidelity_seed=crs_data["core_seed"],crs_data["fidelity_seed"];encoder_output_shape=generalista_model.get_layer('max_pooling2d_2').output.shape[1:];decoder_input=tf.keras.Input(shape=encoder_output_shape);x=generalista_model.layers[7](decoder_input)
                for i in range(8,len(generalista_model.layers)):x=generalista_model.layers[i](x)
                decoder_g=tf.keras.models.Model(decoder_input,x);reconstructed_norm=decoder_g.predict(core_seed,verbose=0).squeeze();base_evoked_pil=Image.fromarray((reconstructed_norm*255).astype(np.uint8));base_evoked_resized=base_evoked_pil.resize((final_w,final_h),Image.Resampling.LANCZOS);base_evoked_array=np.array(base_evoked_resized);residual_map=np.array(Image.open(io.BytesIO(fidelity_seed))).astype(np.int32)-128;final_array=np.clip(base_evoked_array.astype(np.int32)+residual_map,0,255).astype(np.uint8)
            else:
                genesis_model,odin_model=self.load_model(GENESIS_NAME),self.load_model(ODIN_NAME);core_seed,fidelity_seed=crs_data["core_seed"],crs_data["fidelity_seed"];reconstructed_norm=genesis_model.predict(core_seed,verbose=0).squeeze();odin_corrected_norm=odin_model.predict(np.expand_dims(reconstructed_norm,axis=0),verbose=0).squeeze();base_evoked_pil=Image.fromarray((np.clip(odin_corrected_norm,0,1)*255).astype(np.uint8));base_evoked_resized=base_evoked_pil.resize((final_w,final_h),Image.Resampling.LANCZOS);base_evoked_array=np.array(base_evoked_resized,dtype=np.float32);residual_map=(np.array(Image.open(io.BytesIO(fidelity_seed)),dtype=np.float32)-128.0)*2.0;final_array=np.clip(base_evoked_array+residual_map,0,255).astype(np.uint8)

            # IMAGEN PURA - SIN FIRMA
            self.original_image = Image.fromarray(final_array)
            
            self.after(0, self.deiconify)
            self.after(110, self.fit_to_screen) 
            self.after(0, lambda: self.update_status("Reconstrucción completa."))

        except ValueError as e:
            self.after(0, lambda e=e: messagebox.showerror("Error de Contraseña/Archivo Corrupto", str(e)))
            self.after(0, self.on_exit)
        except FileNotFoundError as e:
            self.after(0, lambda e=e: messagebox.showerror("Error de Modelo Faltante", str(e)))
            self.after(0, self.on_exit)
        except Exception as e:
            self.after(0, lambda e=e: messagebox.showerror("Error Crítico de Reconstrucción", f"Ocurrió un error inesperado durante la reconstrucción.\nError: {e}"))
            self.after(0, self.on_exit)

    def toggle_fullscreen(self, event=None):
        if self.is_fullscreen:
            self.control_panel.grid(row=2, column=0, sticky="ew")
            self.title_bar.grid(row=0, column=0, sticky="new")
            self.canvas.grid(row=1, column=0, sticky="nsew", rowspan=1)
            self.is_fullscreen = False
            self.geometry(self.original_geometry)
            self.after(10, self.apply_window_visual_styles)
        else:
            self.original_geometry = self.geometry()
            self.update_idletasks()
            screen_width = self.winfo_screenwidth()
            screen_height = self.winfo_screenheight()
            if WINDOWS_ROUNDED_SUPPORT:
                self.clear_window_region()
            self.title_bar.grid_remove()
            self.control_panel.grid_remove()
            self.canvas.grid(row=0, column=0, sticky="nsew", rowspan=3)
            self.geometry(f"{screen_width}x{screen_height}+0+0")
            self.is_fullscreen = True

        self.after(10, self.update_cursor_mode)
        self.after(100, self.fit_to_screen)

    def _on_resize(self, event=None):
        if WINDOWS_ROUNDED_SUPPORT and not self.is_fullscreen and self.winfo_width() > 10 and self.winfo_height() > 10:
            self.set_window_rounded_corners()
        if self.original_image: self.after(100, self.fit_to_screen)
        else: self.update_display()

    def update_display(self, high_quality=False):
        if not self.original_image:
            canvas_w, canvas_h = self.canvas.winfo_width(), self.canvas.winfo_height()
            self.canvas.delete("image")
            self.canvas.create_text(canvas_w/2, canvas_h/2, text="Sin imagen cargada. Arrastre un archivo .crs.", fill=self.TEXT_COLOR, font=(self.default_font, 12), tags="no_image_text")
            self.update_status("Esperando archivo .crs (Arrastre y suelte o abra con argumentos).")
            return
        self.canvas.delete("no_image_text")
        if self.hq_render_job: self.after_cancel(self.hq_render_job); self.hq_render_job = None
        canvas_w, canvas_h = self.canvas.winfo_width(), self.canvas.winfo_height()
        if canvas_w <= 1 or canvas_h <= 1: self.after(50, lambda: self.update_display(high_quality)); return
        rotated = self.original_image.rotate(self.rotation_angle, expand=True); zoomed_w, zoomed_h = int(rotated.width * self.zoom_level), int(rotated.height * self.zoom_level)
        if zoomed_w < 1 or zoomed_h < 1: return
        resampling_filter = Image.Resampling.LANCZOS if high_quality else Image.Resampling.NEAREST
        display_image = rotated.resize((zoomed_w, zoomed_h), resampling_filter); self.display_photo = ImageTk.PhotoImage(display_image)
        self.canvas.delete("image"); self.canvas.create_image((canvas_w/2)+self.image_offset_x, (canvas_h/2)+self.image_offset_y, image=self.display_photo, anchor=tk.CENTER, tags="image")

        qdna_text = f"Q-DNA: {self.q_dna_value}" if self.q_dna_value else ""
        status_text = f"Zoom: {self.zoom_level:.2f}x" + (f" | {qdna_text}" if qdna_text else "")
        self.update_status(status_text)

        self.update_cursor_mode()
        
        if not high_quality:
            self.hq_render_job = self.after(250, lambda: self.update_display(True))

    def fit_to_screen(self, event=None):
        if not self.original_image: return
        canvas_w, canvas_h = self.canvas.winfo_width(), self.canvas.winfo_height()
        if canvas_w <= 1 or canvas_h <=1: self.after(50, self.fit_to_screen); return
        img_w, img_h = self.original_image.size
        if self.rotation_angle in[90, 270]: img_w, img_h = img_h, img_w
        if img_w == 0 or img_h == 0: return
        w_ratio, h_ratio = (canvas_w - 20) / img_w, (canvas_h - 40) / img_h
        self.zoom_level = min(w_ratio, h_ratio); self.image_offset_x, self.image_offset_y = 0, 0
        self.update_display(high_quality=True)

    def zoom(self, factor): self.zoom_level *= factor; self.update_display()
    def zoom_in(self, event=None): self.zoom(1.2)
    def zoom_out(self, event=None): self.zoom(0.8)
    def zoom_on_scroll(self, event): self.zoom(1.2 if event.delta > 0 else 0.8)
    def rotate(self, angle): self.rotation_angle = (self.rotation_angle + angle) % 360; self.update_display()
    def rotate_left(self, event=None): self.rotate(90)

    def can_pan_image(self):
        if not self.original_image: return False
        canvas_w, canvas_h = self.canvas.winfo_width(), self.canvas.winfo_height()
        if canvas_w < 10 or canvas_h < 10: return False
        img_w, img_h = self.original_image.size
        if self.rotation_angle in[90, 270]: img_w, img_h = img_h, img_w
        zoomed_w, zoomed_h = int(img_w * self.zoom_level), int(img_h * self.zoom_level)
        return zoomed_w > canvas_w or zoomed_h > canvas_h

    def update_cursor_mode(self, event=None):
        if self.is_panning: return
        if self.can_pan_image() or self.is_fullscreen:
            self.canvas.config(cursor="hand2")
        else:
            self.canvas.config(cursor="")

    def start_pan(self, event):
        if self.canvas.cget('cursor') == "hand2" or self.is_fullscreen:
            self.is_panning = True
            self.canvas.config(cursor="fleur")
            self.pan_start_x, self.pan_start_y = event.x, event.y
        else:
            self.is_panning = False

    def pan(self, event):
        if self.is_panning:
            dx, dy = event.x - self.pan_start_x, event.y - self.pan_start_y
            self.image_offset_x += dx
            self.image_offset_y += dy
            self.pan_start_x, self.pan_start_y = event.x, event.y
            self.update_display()

    def stop_pan(self, event=None):
        self.is_panning = False
        self.update_cursor_mode()

    def reset_view(self, event=None): self.rotation_angle = 0; self.fit_to_screen()

    def update_status(self, text, is_error=False): self.status_label.config(text=text, fg=("#ff5555" if is_error else self.TEXT_COLOR))

    def start_move(self, event): self.x, self.y = event.x, event.y
    def do_move(self, event): self.geometry(f"+{self.winfo_x() + event.x - self.x}+{self.winfo_y() + event.y - self.y}")

    def set_appwindow(self):
        if not WINDOWS_ROUNDED_SUPPORT:
            return
        try:
            hwnd = self.winfo_id()
            GWL_EXSTYLE = -20
            WS_EX_APPWINDOW = 0x00040000
            WS_EX_TOOLWINDOW = 0x00000080
            style = _user32.GetWindowLongW(hwnd, GWL_EXSTYLE)
            style = style & ~WS_EX_TOOLWINDOW | WS_EX_APPWINDOW
            _user32.SetWindowLongW(hwnd, GWL_EXSTYLE, style)

            self.wm_protocol("WM_DELETE_WINDOW", self.on_exit)
            self.update()
        except Exception:
            pass

class Tooltip:
    def __init__(self, widget, text):
        self.widget, self.text, self.tooltip_window = widget, text, None
        widget.bind("<Enter>", self.show_tooltip); widget.bind("<Leave>", self.hide_tooltip)

    def show_tooltip(self, event):
        x, y = self.widget.winfo_rootx(), self.widget.winfo_rooty() + self.widget.winfo_height() + 5
        self.tooltip_window = tk.Toplevel(self.widget); self.tooltip_window.wm_overrideredirect(True); self.tooltip_window.wm_geometry(f"+{x}+{y}")
        tk.Label(self.tooltip_window, text=self.text, bg="#3c3c3c", fg="white", relief="solid", borderwidth=1, font=("Segoe UI", 8)).pack()

    def hide_tooltip(self, event):
        if self.tooltip_window: self.tooltip_window.destroy(); self.tooltip_window = None

# ---------- Main runner ----------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Lector Universal XtremeRTX")
    parser.add_argument("--crs_path", type=Path, default=None, help="Ruta al archivo .crs para abrir.")
    parser.add_argument("--models_dir", type=Path, help="Ruta a la carpeta de modelos (opcional).")
    parser.add_argument("--password", type=str, default=None, help="Contraseña para desencriptar el archivo CRS.")

    args, unknown = parser.parse_known_args()
    file_path = args.crs_path

    if not file_path and unknown:
        for arg in unknown:
            try:
                temp_path_str = arg.strip().strip('"')
                temp_path = Path(temp_path_str)
                if temp_path.suffix.lower() == '.crs' and temp_path.is_file():
                    file_path = temp_path
                    break
            except Exception:
                continue

    if file_path and not file_path.is_file():
         file_path = None

    if check_for_lockdown_lector():
        sys.exit(1)

    # Verificación de Tracker y Strikes (SE MANTIENE)
    tracker_data = load_or_initialize_lector_tracker()
    if tracker_data is None:
        sys.exit(1)
    
    current_strikes = tracker_data.get("strikes", 0)
    
    if current_strikes > STRIKE_LIMIT:
        app = SoporteTecnicoWindow()
        app.mainloop()
        sys.exit(1)

    # (ELIMINADO): Bloqueo de procesos OBS/Grabadoras

    base_path = BASE_DIR
    models_directory = args.models_dir if args.models_dir else base_path / "xtremertx_ai" / "models"

    app = None
    try:
        if file_path:
            if not file_path.is_file():
                root = tk.Tk(); root.withdraw()
                messagebox.showerror("Error de Archivo", f"El archivo .crs especificado no se encontró: {file_path}")
                root.destroy(); sys.exit(1)

            app = ElegantViewer(crs_path=file_path, models_dir=models_directory, password=args.password)
            app.mainloop()
        else:
            root = tk.Tk(); root.withdraw()
            if sys.stdin and not sys.stdin.isatty():
                pass
            else:
                messagebox.showinfo("Lector Universal XtremeRTX", "Este es el visor de archivos .crs.\n\nPara usarlo, abre un archivo .crs directamente (asociación de archivos) o arrastra un .crs sobre el ejecutable.")
            root.destroy()
            sys.exit(0)

    except Exception as e:
        root = tk.Tk(); root.withdraw()
        messagebox.showerror("Error Crítico de Inicialización", f"No se pudo iniciar el lector.\nError: {e}"); root.destroy()
        sys.exit(1)
    
    sys.exit(0)