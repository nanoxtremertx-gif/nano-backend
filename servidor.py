import Link from "next/link";
import { useEffect, useState } from "react";
import { useRouter } from "next/router";
import {
  FaBars, FaTimes, FaUser, FaShoppingCart, FaCog, FaFileUpload,
  FaComments, FaFileAlt, FaFolderOpen, FaInbox,
  FaShieldAlt, FaThLarge, FaSearch, FaBook, FaDownload, FaFeatherAlt
} from "react-icons/fa";
import { motion, AnimatePresence } from "framer-motion";

export default function Navbar() {
  const [user, setUser] = useState(null);
  const router = useRouter();
  const [isVisible, setIsVisible] = useState(true);
  const [lastScrollY, setLastScrollY] = useState(0);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [dockOpen, setDockOpen] = useState(false);
  const [isMounted, setIsMounted] = useState(false); 

  useEffect(() => {
    const onScroll = () => {
      if (window.scrollY > lastScrollY && window.scrollY > 100) {
        setIsVisible(false);
      } else if (window.scrollY < lastScrollY) {
        setIsVisible(true);
      }
      if (window.scrollY <= 100) {
        setIsVisible(true);
      }
      setLastScrollY(window.scrollY);
    };

    window.addEventListener("scroll", onScroll, { passive: true });

    const u = localStorage.getItem("user");
    if (u) {
      try { setUser(JSON.parse(u)); } catch { localStorage.removeItem("user"); setUser(null); }
    } else {
      setUser(null);
    }
    
    setIsMounted(true);
    setIsMobileMenuOpen(false); 

    return () => window.removeEventListener("scroll", onScroll);
  }, [router.asPath]);

  const handleLogout = () => {
    localStorage.removeItem("user");
    setUser(null);
    router.push("/");
  };

  const goToLogin = () => router.push("/login");
   
  const getUserColor = (role) => {
    if (role === "admin") return "text-purple-400";
    if (role === "pro") return "text-amber-400";
    return "text-green-400";
  };

  const getDockIcon = () => {
    if (!user) return <FaUser size={22} className="text-gray-400" />;
    if (user.role === "admin") return <FaShieldAlt size={22} className="text-purple-400" />;
    if (user.role === "pro") return <FaThLarge size={22} className="text-amber-400" />;
    return <FaThLarge size={22} className="text-green-400" />;
  };
   
  if (!isMounted) {
      return (
        <nav className="fixed w-full z-50 bg-gray-900/95 border-b border-gray-800 h-14 flex items-center px-6">
            <span className="text-2xl font-extrabold text-cyan-400">NANO</span>
        </nav>
      );
  }

  return (
    <>
      {/* --- NAVBAR SUPERIOR (DELGADO h-14) --- */}
      <nav
        className={`fixed top-4 left-1/2 -translate-x-1/2 w-[95%] max-w-7xl bg-black bg-opacity-70 backdrop-blur-md text-white shadow-xl px-4 md:px-6 h-14 flex justify-between items-center z-50 border border-gray-400/40 rounded-full transition-all duration-500 overflow-visible ${
          isVisible ? "opacity-100 translate-y-0" : "opacity-0 -translate-y-[150%]"
        }`}
      >
          {/* Menú Izq */}
          <div className="hidden md:flex gap-6 text-sm font-medium items-center w-1/3"> 
            <Link href="/descargas" className="hover:text-cyan-400 transition flex items-center gap-1"><FaDownload /> Descargas</Link> 
            <Link href="/biblioteca" className="hover:text-cyan-400 transition flex items-center gap-1"><FaBook /> Biblioteca</Link> 
          </div>

          {/* LOGO CENTRAL (GIGANTE h-[400px] Y CENTRADO) */}
          <div className="flex justify-center items-center mx-auto pointer-events-auto h-full w-1/3 relative">
            <Link href="/info" className="relative flex items-center justify-center group">
              {/* AJUSTE FINAL EXTREMO:
                  - h-[400px]: Tamaño masivo.
                  - top-1/2 left-1/2: Posición absoluta al centro.
                  - -translate-x-1/2 -translate-y-1/2: Centrado matemático perfecto.
              */}
              <img 
                src="/nano.png" 
                alt="NANO-XtremeRTX" 
                className="absolute h-[400px] w-auto max-w-none object-contain top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 hover:scale-105 transition-transform duration-300 drop-shadow-[0_5px_25px_rgba(0,0,0,0.8)]" 
              />
            </Link>
          </div>

          {/* Menú Der */}
          <div className="hidden md:flex gap-6 text-sm font-medium items-center justify-end w-1/3">
            <Link href="/buscar" className="hover:text-cyan-400 transition flex items-center gap-1"><FaSearch /> Buscar</Link>
            <Link href="/procedencia" className="hover:text-cyan-400 transition flex items-center gap-1"><FaFeatherAlt /> Procedencia</Link>
          </div>

          {/* Hamburguesa */}
          <div className="md:hidden absolute top-1/2 -translate-y-1/2 right-6">
            <button onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)} className="text-2xl text-white">
              {isMobileMenuOpen ? <FaTimes /> : <FaBars />}
            </button>

            <AnimatePresence>
              {isMobileMenuOpen && (
               <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }} transition={{ duration: 0.25 }} className="absolute right-0 mt-6 bg-black/90 backdrop-blur-xl border border-gray-400/40 rounded-2xl p-4 text-sm flex flex-col gap-4 shadow-2xl min-w-[200px]">
                  <Link href="/descargas" className="hover:text-cyan-400 transition flex items-center gap-2"><FaDownload/> Descargas</Link>
                  <Link href="/biblioteca" className="hover:text-cyan-400 transition flex items-center gap-2"><FaBook/> Biblioteca</Link>
                  <Link href="/buscar" className="hover:text-cyan-400 transition flex items-center gap-2"><FaSearch/> Buscar</Link>
                  <Link href="/procedencia" className="hover:text-cyan-400 transition flex items-center gap-2"><FaFeatherAlt/> Procedencia</Link>
               </motion.div>
              )}
            </AnimatePresence>
          </div>
      </nav>

      {/* --- PANEL INFERIOR / DOCK --- */}
      <div className="fixed bottom-6 left-0 right-0 z-30 flex flex-col items-center justify-center pointer-events-none">

        {/* Botón Usuario (Izquierda) */}
        <AnimatePresence>
            {user && dockOpen && (
                <motion.div 
                    initial={{ opacity: 0, x: 20 }} 
                    animate={{ opacity: 1, x: 0 }} 
                    exit={{ opacity: 0, x: 20 }} 
                    className="absolute right-[50%] mr-12 pointer-events-auto"
                >
                    <div className="px-4 py-2 rounded-full bg-black/60 border border-gray-400/40 text-xs font-bold backdrop-blur-sm shadow-lg">
                        <span className={getUserColor(user.role)}>{user.username}</span>
                    </div>
                </motion.div>
            )}
        </AnimatePresence>

        {/* Botón Central */}
        <motion.button 
            onClick={() => { if (!user) goToLogin(); else setDockOpen((s) => !s); }} 
            whileHover={{ scale: 1.05 }} 
            whileTap={{ scale: 0.95 }} 
            className="relative z-40 w-16 h-16 rounded-full border border-gray-400/40 bg-gradient-to-b from-slate-900 to-black flex items-center justify-center pointer-events-auto shadow-lg shadow-cyan-500/10" 
        >
          {getDockIcon()}
        </motion.button>

        {/* Botón Cerrar (Derecha) */}
        <AnimatePresence>
            {user && dockOpen && (
                <motion.button 
                    onClick={handleLogout}
                    initial={{ opacity: 0, x: -20 }} 
                    animate={{ opacity: 1, x: 0 }} 
                    exit={{ opacity: 0, x: -20 }} 
                    className="absolute left-[50%] ml-12 px-4 py-2 rounded-full bg-red-900/40 border border-red-500/40 text-red-300 text-xs font-bold backdrop-blur-sm hover:bg-red-800/60 transition pointer-events-auto shadow-lg"
                >
                    Cerrar
                </motion.button>
            )}
        </AnimatePresence>

        {/* Menú de Iconos */}
        {user && (
          <AnimatePresence>
            {dockOpen && (
              <motion.div initial={{ opacity: 0, scaleX: 0, y: 20 }} animate={{ opacity: 1, scaleX: 1, y: 0 }} exit={{ opacity: 0, scaleX: 0, y: 20 }} transition={{ duration: 0.2 }} className="absolute bottom-[75px] flex justify-center z-30 w-full px-4" >
                <div className="flex items-center gap-3 md:gap-5 px-4 py-3 bg-black/60 backdrop-blur-xl border border-gray-400/40 rounded-full max-w-[95vw] overflow-x-auto scrollbar-hide pointer-events-auto">
                  {[
                    { href: "/mensajeria", icon: <FaComments size={18} />, label: "MSG" },
                    { href: "/miscompras", icon: <FaShoppingCart size={18} />, label: "CMP" },
                    { href: "/configuracion", icon: <FaCog size={18} />, label: "CFG" },
                    { href: `/canal/${user?.username || ""}`, icon: <FaUser size={18} />, label: "CAN" },
                    { href: "/misarchivos", icon: <FaFolderOpen size={18} />, label: "ARC" },
                    { href: "/subir", icon: <FaFileUpload size={18} />, label: "UPL" },
                    ...(user?.role === "admin"
                      ? [{ href: "/documentos", icon: <FaFileAlt size={18} />, label: "DOC" }]
                      : []),
                    { 
                      href: user?.role === "admin" ? "/archivosrecibidos" : "/envioseguro",
                      icon: user?.role === "admin" ? <FaInbox size={18} /> : <FaShieldAlt size={18} />,
                      label: user?.role === "admin" ? "RECIBIR" : "CREAR"
                    }
                  ].map((btn, i) => (
                    <div key={i} className="flex flex-col items-center justify-center min-w-[40px]">
                      <Link href={btn.href} className="w-10 h-10 border border-gray-500/30 rounded-full flex items-center justify-center bg-black/40 hover:bg-cyan-600 hover:border-cyan-400 transition-all">
                        {btn.icon}
                      </Link>
                      <span className="mt-1 text-[9px] text-gray-300 font-bold tracking-wide">{btn.label}</span>
                    </div>
                  ))}
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        )}
      </div>

      <style jsx global>{`
        .scrollbar-hide::-webkit-scrollbar { display: none; }
        .scrollbar-hide { -ms-overflow-style: none; scrollbar-width: none; }
      `}</style>
    </>
  );
}
