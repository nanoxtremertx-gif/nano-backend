// /pages/envioseguro.jsx (v3.0 - Consolidado en S4)
import { useEffect, useState } from "react";
import Navbar from "../components/Navbar";
import axios from "axios";
import {
  FaCloudUploadAlt, FaTimesCircle, FaExclamationTriangle,
  FaSpinner, FaBrain, FaBolt, FaDatabase, FaCheckCircle
} from "react-icons/fa";
import Image from "next/image";
import { useRouter } from "next/router";

// --- Constantes ---
const MAX_FILE_SIZE_MB = 25; // 25 MB Límite (coincide con S4)

// --- Lógica de Red (IP Dinámica) ---
const API_IP = process.env.NEXT_PUBLIC_API_SERVER_IP || '127.0.0.1';
const SERVER4_BASE_URL = `http://${API_IP}:5050`;
const SERVER4_CONVERT_URL = `${SERVER4_BASE_URL}/convert`; // <-- NUEVO ENDPOINT

export default function EnvioSeguroPage() {
  const router = useRouter();
  const [user, setUser] = useState(null);
  const [isLoading, setIsLoading] = useState(true);

  // --- Estado de Subida ---
  const [file, setFile] = useState(null);
  const [encoderType, setEncoderType] = useState(""); // "bitabit", "ultrav", "perceptual"
  const [progress, setProgress] = useState(0);
  const [uploading, setUploading] = useState(false);
  const [errorUpload, setErrorUpload] = useState("");
  const [successUpload, setSuccessUpload] = useState(""); // Para mensaje de éxito
  const [warningUpload, setWarningUpload] = useState("");
  const [location, setLocation] = useState("");
  const [locationError, setLocationError] = useState("");

  // --- Efecto Principal: Autenticación ---
  useEffect(() => {
    setIsLoading(true);
    const u = localStorage.getItem("user");
    if (!u) {
      router.replace("/login");
      return;
    }

    try {
        const currentUser = JSON.parse(u);
        setUser(currentUser);
    } catch {
        localStorage.removeItem("user");
        router.replace("/login");
        return;
    }
    
    setIsLoading(false);
  }, [router]);


  // --- Funciones de la vista de Subida ---
   const isCompressedLike = (mime, name) => {
    const m = (mime || "").toLowerCase(); const n = (name || "").toLowerCase(); const compressedMimes = ["image/jpeg","image/png","image/webp","image/avif","image/heic","image/heif","image/gif"]; const compressedExts = [".jpg",".jpeg",".png",".webp",".avif",".heic",".heif",".gif"]; return compressedMimes.includes(m) || compressedExts.some(ext => n.endsWith(ext));
   };
   
  const handleFileChange = (e) => {
    const f = e.target.files?.[0]; if (!f) return; 
    setErrorUpload(""); 
    setSuccessUpload(""); // Limpia éxito
    setWarningUpload("");
    const sizeMB = f.size / 1024 / 1024;
    if (sizeMB > MAX_FILE_SIZE_MB) {
        setErrorUpload(`Archivo grande (${sizeMB.toFixed(2)} MB). Límite ${MAX_FILE_SIZE_MB}MB.`);
        setFile(null); return;
    }
    if (isCompressedLike(f.type, f.name)) {
        setWarningUpload("⚠️ Advertencia: Es una imagen comprimida. El CRS final puede inflarse.");
    }
    setFile(f);
  };
  
  const getLocation = () => {
    return new Promise((resolve, reject) => { if (!navigator.geolocation) { reject("GPS no disponible"); } else { navigator.geolocation.getCurrentPosition( (pos) => { resolve(`Lat: ${pos.coords.latitude.toFixed(5)}, Lng: ${pos.coords.longitude.toFixed(5)}`); }, () => reject("Error GPS. Ingrese manual."), { timeout: 8000 } ); } });
  };

  // --- Función de Subida (handleUpload) ---
  const handleUpload = async () => {
    if (!file || !user || !encoderType) {
        if (!encoderType) setErrorUpload("Por favor, selecciona un tipo de encoder.");
        return;
    }
    setUploading(true); 
    setProgress(0); 
    setErrorUpload(""); 
    setSuccessUpload("");
    setLocationError("");
    
    let loc = location;
    if (!loc) {
        try { loc = await getLocation(); setLocation(loc); }
        catch (err) { setLocationError(err); setUploading(false); return; }
    }
    
    // --- Prepara FormData CON TODA LA INFORMACIÓN ---
    const formData = new FormData();
    formData.append("file", file);
    formData.append("username", user.username);
    formData.append("userRole", user.role || "user");
    formData.append("location", loc);
    formData.append("encoderType", encoderType); // <-- ¡NUEVO!
    formData.append("singleUseClientId", user.id || user.username); // Para cooldown

    try {
        console.log(`Enviando a: ${SERVER4_CONVERT_URL}`);
        const resp = await axios.post(SERVER4_CONVERT_URL, formData, {
            headers: { "Content-Type": "multipart/form-data" },
            onUploadProgress: (p) => { if (!p.total) return; setProgress(Math.round((p.loaded * 100) / p.total)); },
        });

        if (resp.data?.success && resp.data.record) {
            const metrics = resp.data.record;
            setSuccessUpload(`¡Conversión Exitosa! "${metrics.final_crs_name}" (${metrics.final_size_mb.toFixed(2)} MB) fue enviado a tu cuenta.`);
            setFile(null); // Limpia el formulario
            setEncoderType("");
            setWarningUpload("");
        } else {
            throw new Error(resp.data?.error || "Respuesta inválida del servidor");
        }
    } catch (err) {
        console.error("Error en handleUpload:", err);
        let errorMsg = "❌ Error al enviar.";
        if (err.message.includes('Network Error')) { errorMsg += ` No se pudo conectar a ${SERVER4_BASE_URL}. ¿S4 online?`; }
        else if (err.response) {
            if (err.response.status === 429) { // Cooldown
                errorMsg = `🚫 ${err.response.data?.error || "Límite alcanzado."}`;
            } else if (err.response.status === 413) { // Archivo grande
                 errorMsg = `🐘 ${err.response.data?.error || "Archivo demasiado grande."}`;
            } else {
                errorMsg += ` Servidor (${err.response.status}): ${err.response.data?.error || err.response.statusText}`;
            }
        }
        else { errorMsg += ` Detalles: ${err.message}`; }
        setErrorUpload(errorMsg);
    } finally {
        setUploading(false);
        setProgress(0);
    }
  };

  // --- Renderizado ---
  if (isLoading) {
    return ( <div className="min-h-screen bg-[url('/fondo.png')] bg-cover text-white flex flex-col items-center justify-center"> <FaSpinner className="animate-spin text-cyan-400 mb-4" size={48} /> <p className="text-xl">Cargando...</p> </div> );
  }

  return (
    <div className="min-h-screen bg-[url('/fondo.png')] bg-cover text-white">
      <Navbar />
      <main className="max-w-3xl mx-auto p-8 pt-28">
        <div className="bg-gray-900/80 p-8 rounded-xl shadow-2xl border border-cyan-500/30 text-center transition-all duration-300">

            {/* --- Vista Única de Subida --- */}
            <>
              <h1 className="text-3xl font-bold mb-6 text-cyan-400 flex items-center justify-center gap-3">
                <FaCloudUploadAlt /> Creación Web (v3.0)
              </h1>
              <p className="text-sm text-gray-400 mb-6 -mt-4">Límite: 1 conversión cada {48} horas por usuario.</p>

              <>
                  {/* --- 1. Selector de Archivo --- */}
                  <div
                    className={`flex flex-col items-center justify-center border-2 border-dashed border-gray-600 rounded-lg p-10 transition-all cursor-pointer ${ uploading ? "opacity-60 pointer-events-none" : "hover:border-cyan-400" }`}
                    onClick={() => !uploading && document.getElementById("fileInput").click()}
                    onDragOver={(e) => e.preventDefault()}
                    onDrop={(e) => { e.preventDefault(); if (uploading) return; if (e.dataTransfer.files?.length > 0) { handleFileChange({ target: { files: e.dataTransfer.files } }); } }}
                  >
                     <Image src="/carpeta.ico" alt="Subir archivo" width={64} height={64} />
                     <p className="text-gray-400 mt-2"> Arrastra tu archivo o{" "} <span className="text-cyan-400 font-bold hover:text-cyan-300"> haz clic aquí </span> </p>
                     <p className="text-xs text-gray-500 mt-1"> Ideal: TIFF/BMP/RAW. Límite {MAX_FILE_SIZE_MB}MB. </p>
                     <input id="fileInput" type="file" className="hidden" onChange={handleFileChange} accept="image/*,application/octet-stream,application/zip,application/x-tar,*/*" />
                  </div>

                  {file && (
                     <div className="mt-6 bg-gray-800/60 border border-gray-700 rounded-lg p-4 text-left">
                         <p className="text-cyan-300 font-semibold text-lg">{file.name}</p>
                         <p className="text-gray-400 text-sm"> Tamaño: {(file.size / 1024 / 1024).toFixed(2)} MB<br /> Tipo: {file.type || "desconocido"} </p>
                         {warningUpload && ( <div className="mt-3 p-3 bg-amber-900 border border-amber-600 rounded text-sm flex items-center gap-2"> <FaExclamationTriangle className="text-amber-400" /> {warningUpload} </div> )}
                     </div>
                  )}

                  {/* --- 2. Selector de Encoder --- */}
                  {file && !uploading && (
                    <div className="mt-6">
                        <p className="text-lg font-semibold text-gray-300 mb-3">Selecciona un Encoder:</p>
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                            {/* Botón Perceptual */}
                            <button
                                onClick={() => setEncoderType("perceptual")}
                                className={`p-4 rounded-lg border-2 transition-all ${encoderType === "perceptual" ? "border-cyan-400 bg-cyan-900/50 scale-105" : "border-gray-700 bg-gray-800/60 hover:bg-gray-700/60"}`}
                            >
                                <FaBrain className="text-cyan-400 text-3xl mx-auto mb-2" />
                                <p className="font-bold">Perceptual</p>
                                <p className="text-xs text-gray-400">Calidad 0% (Fijo)</p>
                            </button>
                            {/* Botón Ultra Visual */}
                            <button
                                onClick={() => setEncoderType("ultrav")}
                                className={`p-4 rounded-lg border-2 transition-all ${encoderType === "ultrav" ? "border-purple-400 bg-purple-900/50 scale-105" : "border-gray-700 bg-gray-800/60 hover:bg-gray-700/60"}`}
                            >
                                <FaBolt className="text-purple-400 text-3xl mx-auto mb-2" />
                                <p className="font-bold">Ultra Visual</p>
                                <p className="text-xs text-gray-400">(Encoder B)</p>
                            </button>
                            {/* Botón Bit a Bit */}
                            <button
                                onClick={() => setEncoderType("bitabit")}
                                className={`p-4 rounded-lg border-2 transition-all ${encoderType === "bitabit" ? "border-green-400 bg-green-900/50 scale-105" : "border-gray-700 bg-gray-800/60 hover:bg-gray-700/60"}`}
                            >
                                <FaDatabase className="text-green-400 text-3xl mx-auto mb-2" />
                                <p className="font-bold">Bit a Bit</p>
                                <p className="text-xs text-gray-400">(Encoder C)</p>
                            </button>
                        </div>
                    </div>
                  )}
                  
                  {/* --- Barra de Progreso --- */}
                  {uploading && ( 
                    <div className="mt-6"> 
                        <div className="h-2 bg-gray-700 rounded-full overflow-hidden"> 
                            <div className="h-2 bg-cyan-500 transition-all duration-300" style={{ width: `${progress}%` }}></div>
                        </div>
                        <p className="text-gray-400 mt-1 text-sm">{progress === 100 ? "Procesando en servidor..." : `Subiendo ${progress}%`}</p>
                    </div>
                  )}

                  {/* --- Errores / Ubicación / Éxito --- */}
                  {locationError && (
                     <div className="mt-4">
                         <label className="block text-sm text-gray-400 mb-1"> Ubicación manual: </label>
                         <input value={location} onChange={(e) => setLocation(e.target.value)} className="w-full p-2 bg-gray-800 border border-cyan-600 rounded text-sm" placeholder="Ej: Santiago, Chile" />
                         <p className="text-xs text-gray-400 mt-1"> Ingresa tu ciudad/sector y vuelve a enviar. </p>
                     </div>
                  )}
                  {errorUpload && (
                     <div className="mt-4 p-3 bg-red-900 border border-red-600 rounded text-sm flex items-center gap-2"> <FaTimesCircle className="text-red-400" /> {errorUpload} </div>
                  )}
                  {successUpload && (
                     <div className="mt-4 p-3 bg-green-900 border border-green-600 rounded text-sm flex items-center gap-2"> <FaCheckCircle className="text-green-400" /> {successUpload} </div>
                  )}

                  {/* --- 3. Botón de Envío --- */}
                  <div className="mt-6 flex flex-col items-center gap-2">
                     <button 
                        onClick={handleUpload} 
                        disabled={!file || !encoderType || uploading} 
                        className={`px-8 py-3 rounded-full font-bold text-lg transition flex items-center gap-2 ${ (!file || !encoderType || uploading) ? "bg-gray-600 cursor-not-allowed opacity-70" : "bg-cyan-600 hover:bg-cyan-500 shadow-lg shadow-cyan-600/30" }`} 
                     >
                         {uploading ? <FaSpinner className="animate-spin" /> : <FaCloudUploadAlt />}
                         {uploading ? "Convirtiendo..." : "Iniciar Conversión"}
                     </button>
                  </div>
              </>
            </>
          

        </div>
      </main>
    </div>
  );
}
