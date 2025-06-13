const express = require('express');
const { Client, LocalAuth, MessageMedia } = require('whatsapp-web.js');
const qrcode = require('qrcode-terminal');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult, param } = require('express-validator');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

// Configuración de variables de entorno
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const API_PASSWORD = process.env.API_PASSWORD || 'Learsi20';
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS ? 
  process.env.ALLOWED_ORIGINS.split(',') : ['http://localhost:3000'];
const MAX_FILE_SIZE = process.env.MAX_FILE_SIZE || 10; // MB
const RATE_LIMIT_WINDOW = process.env.RATE_LIMIT_WINDOW || 15; // minutos
const RATE_LIMIT_MAX = process.env.RATE_LIMIT_MAX || 100; // requests por ventana

// Inicializar Express
const app = express();

// Configuración de seguridad avanzada con Helmet
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// Configuración CORS más restrictiva
app.use(cors({
  origin: function (origin, callback) {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('No permitido por política CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key']
}));

// Rate limiting
const limitadorGeneral = rateLimit({
  windowMs: RATE_LIMIT_WINDOW * 60 * 1000,
  max: RATE_LIMIT_MAX,
  message: {
    error: 'Demasiadas solicitudes, intenta de nuevo más tarde',
    retryAfter: RATE_LIMIT_WINDOW
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const limitadorMensajes = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minuto
  max: 10, // máximo 10 mensajes por minuto
  message: {
    error: 'Límite de mensajes excedido, espera un minuto',
    retryAfter: 1
  }
});

app.use(limitadorGeneral);

// Middleware de parsing con límites de tamaño
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// Variables para el estado
let estadoBot = 'inicializando';
let codigoQR = null;
let clienteListo = false;
let mensajesEntrantes = [];

// Hash de la contraseña API
const hashContrasena = bcrypt.hashSync(API_PASSWORD, 10);

// Cliente WhatsApp con configuración de seguridad
const cliente = new Client({
  authStrategy: new LocalAuth({
    dataPath: './.wwebjs_auth'
  }),
  puppeteer: {
    headless: true,
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-accelerated-2d-canvas',
      '--no-first-run',
      '--no-zygote',
      '--single-process',
      '--disable-gpu',
      '--disable-web-security',
      '--disable-background-timer-throttling',
      '--disable-backgrounding-occluded-windows',
      '--disable-renderer-backgrounding'
    ],
  }
});

// Funciones de utilidad para seguridad
function limpiarEntrada(obj) {
  if (typeof obj !== 'object' || obj === null) {
    return obj;
  }
  
  const resultado = Array.isArray(obj) ? [] : {};
  
  for (const clave in obj) {
    if (Object.prototype.hasOwnProperty.call(obj, clave)) {
      let valor = obj[clave];
      
      if (typeof valor === 'string') {
        // Remover caracteres de control y limitar longitud
        valor = valor.replace(/[\x00-\x09\x0B\x0C\x0E-\x1F\x7F]/g, '').substring(0, 10000);
      } else if (typeof valor === 'object' && valor !== null) {
        valor = limpiarEntrada(valor);
      }
      
      resultado[clave] = valor;
    }
  }
  
  return resultado;
}

function validarNumeroTelefono(numero) {
  const patron = /^[\d\s\-\+\(\)]{7,20}$/;
  return patron.test(numero.replace(/\s/g, ''));
}

function generarToken(datos) {
  return jwt.sign(datos, JWT_SECRET, { expiresIn: '24h' });
}

function verificarToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    return null;
  }
}

// Middleware de autenticación
function requiereAutenticacion(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '') || 
                req.headers['x-api-key'];
  
  if (!token) {
    return res.status(401).json({
      exito: false,
      error: 'Token de autenticación requerido',
      mensaje: 'Incluye el token en el header Authorization: Bearer <token>'
    });
  }

  const datosToken = verificarToken(token);
  if (!datosToken) {
    return res.status(401).json({
      exito: false,
      error: 'Token inválido o expirado'
    });
  }

  req.usuario = datosToken;
  next();
}

// Middleware para verificar conexión
function requiereConexion(req, res, next) {
  if (!clienteListo || estadoBot !== 'conectado') {
    return res.status(503).json({
      exito: false,
      error: 'WhatsApp no está conectado',
      estado: estadoBot,
      mensaje: estadoBot === 'esperando_qr' 
        ? 'Escanea el código QR primero'
        : 'Espera a que WhatsApp se conecte'
    });
  }
  next();
}

// Eventos del cliente WhatsApp
cliente.on('qr', (qr) => {
  codigoQR = qr;
  estadoBot = 'esperando_qr';
  console.log('\n📱 ¡Escanea este código QR con tu WhatsApp!');
  qrcode.generate(qr, { small: true });
});

cliente.on('loading_screen', (porcentaje, mensaje) => {
  console.log(`⏳ Cargando... ${porcentaje}% - ${mensaje}`);
  estadoBot = `cargando_${porcentaje}`;
});

cliente.on('authenticated', () => {
  console.log('✅ Autenticación exitosa');
  estadoBot = 'autenticado';
});

cliente.on('auth_failure', mensaje => {
  console.error('❌ Error de autenticación:', mensaje);
  estadoBot = 'error_autenticacion';
  codigoQR = null;
});

cliente.on('ready', () => {
  clienteListo = true;
  estadoBot = 'conectado';
  codigoQR = null;
  console.log('🎉 ¡Cliente WhatsApp conectado y listo!');
});

cliente.on('disconnected', (razon) => {
  clienteListo = false;
  estadoBot = 'desconectado';
  codigoQR = null;
  console.log('🔌 Cliente WhatsApp desconectado:', razon);
  
  // Intentar reconectar después de 30 segundos
  setTimeout(() => {
    console.log('🔄 Intentando reconectar...');
    cliente.initialize();
  }, 30000);
});

cliente.on('message', async (mensaje) => {
  if (mensaje.from === 'status@broadcast') {
    return;
  }
  
  try {
    const esGrupo = mensaje.from.endsWith('@g.us');
    let infoMensaje = {
      de: mensaje.from,
      cuerpo: mensaje.body.substring(0, 1000), // Limitar longitud
      esGrupo: esGrupo,
      nombreGrupo: '',
      autor: mensaje.author || '',
      nombreAutor: '',
      numeroAutor: '',
      idMensaje: mensaje.id._serialized,
      marcaTiempo: new Date().toISOString()
    };

    if (esGrupo) {
      try {
        const chat = await mensaje.getChat();
        infoMensaje.nombreGrupo = chat.name;
        
        if (mensaje.author) {
          const contacto = await cliente.getContactById(mensaje.author);
          if (contacto) {
            infoMensaje.nombreAutor = contacto.name || contacto.pushname || '';
            infoMensaje.numeroAutor = contacto.id.user;
          }
        }
      } catch (error) {
        console.log('Error al obtener detalles del grupo:', error.message);
      }
    }

    console.log(`📨 Mensaje recibido de ${infoMensaje.de}: ${infoMensaje.cuerpo}`);
    
    // Mantener solo los últimos 100 mensajes
    mensajesEntrantes.push(infoMensaje);
    if (mensajesEntrantes.length > 100) {
      mensajesEntrantes = mensajesEntrantes.slice(-100);
    }
    
  } catch (error) {
    console.error('Error al procesar mensaje:', error);
  }
});

// RUTAS DE LA API

// Ruta de autenticación
app.post('/api/auth', [
  body('contrasena').isString().notEmpty()
], async (req, res) => {
  const errores = validationResult(req);
  if (!errores.isEmpty()) {
    return res.status(400).json({ exito: false, errores: errores.array() });
  }

  try {
    const { contrasena } = limpiarEntrada(req.body);
    
    const esValida = await bcrypt.compare(contrasena, hashContrasena);
    if (!esValida) {
      return res.status(401).json({
        exito: false,
        error: 'Contraseña incorrecta'
      });
    }

    const token = generarToken({
      usuario: 'api_user',
      permisos: ['enviar_mensajes', 'leer_mensajes']
    });

    res.json({
      exito: true,
      token: token,
      expira: '24 horas',
      mensaje: 'Autenticación exitosa'
    });

  } catch (error) {
    console.error('Error en autenticación:', error);
    res.status(500).json({
      exito: false,
      error: 'Error interno del servidor'
    });
  }
});

// Ruta de estado (no requiere autenticación)
app.get('/api/estado', async (req, res) => {
  res.json({
    estado: estadoBot,
    codigoQR: estadoBot === 'esperando_qr' ? codigoQR : null,
    listo: clienteListo,
    marcaTiempo: new Date().toISOString(),
    version: '2.0.0'
  });
});

// Ruta para enviar mensajes
app.post('/api/enviar-mensaje', 
  limitadorMensajes,
  requiereAutenticacion,
  requiereConexion,
  [
    body('destino').isString().notEmpty().isLength({ min: 7, max: 20 }),
    body('mensaje').isString().notEmpty().isLength({ min: 1, max: 4000 }),
    body('rutaArchivo').optional().isString().isLength({ max: 500 }),
    body('esGrupo').optional().isBoolean()
  ],
  async (req, res) => {
    const errores = validationResult(req);
    if (!errores.isEmpty()) {
      return res.status(400).json({ exito: false, errores: errores.array() });
    }
    
    try {
      const datosSanitizados = limpiarEntrada(req.body);
      const { destino, mensaje, rutaArchivo, esGrupo = false } = datosSanitizados;

      // Validar número de teléfono
      if (!esGrupo && !validarNumeroTelefono(destino)) {
        return res.status(400).json({
          exito: false,
          error: 'Formato de número de teléfono inválido'
        });
      }

      let chatId;
      if (esGrupo) {
        chatId = destino.endsWith('@g.us') ? destino : `${destino}@g.us`;
      } else {
        chatId = destino.endsWith('@c.us') ? destino : `${destino}@c.us`;
      }

      // Verificar si el número está registrado (solo para contactos individuales)
      if (!esGrupo) {
        const estaRegistrado = await cliente.isRegisteredUser(chatId);
        if (!estaRegistrado) {
          return res.status(400).json({
            exito: false,
            error: 'El número no está registrado en WhatsApp'
          });
        }
      }

      let respuesta;
      if (rutaArchivo) {
        const rutaAbsoluta = path.resolve(rutaArchivo);
        
        // Validaciones de seguridad para archivos
        if (!fs.existsSync(rutaAbsoluta)) {
          return res.status(400).json({
            exito: false,
            error: 'El archivo no existe'
          });
        }

        const stats = fs.statSync(rutaAbsoluta);
        if (stats.size > MAX_FILE_SIZE * 1024 * 1024) {
          return res.status(400).json({
            exito: false,
            error: `El archivo es demasiado grande. Máximo ${MAX_FILE_SIZE}MB`
          });
        }

        const media = MessageMedia.fromFilePath(rutaAbsoluta);
        respuesta = await cliente.sendMessage(chatId, media, { caption: mensaje });
      } else {
        respuesta = await cliente.sendMessage(chatId, mensaje);
      }

      console.log(`✅ Mensaje enviado a ${chatId}: ${mensaje.substring(0, 50)}...`);
      
      res.json({
        exito: true,
        idMensaje: respuesta.id.id,
        mensaje: 'Mensaje enviado correctamente'
      });

    } catch (error) {
      console.error('❌ Error al enviar mensaje:', error);
      res.status(500).json({
        exito: false,
        error: 'Error al enviar mensaje: ' + error.message
      });
    }
  }
);

// Ruta para obtener grupos
app.get('/api/grupos', requiereAutenticacion, requiereConexion, async (req, res) => {
  try {
    const chats = await cliente.getChats();
    const grupos = chats.filter(chat => chat.isGroup);
    
    const listaGrupos = grupos.map(grupo => ({
      id: grupo.id._serialized,
      nombre: grupo.name,
      participantes: grupo.participants.length
    }));
    
    res.json({
      exito: true,
      grupos: listaGrupos
    });
  } catch (error) {
    res.status(500).json({
      exito: false,
      error: error.message
    });
  }
});

// Ruta para obtener contactos
app.get('/api/contactos', requiereAutenticacion, requiereConexion, async (req, res) => {
  try {
    const contactos = await cliente.getContacts();
    
    const listaContactos = contactos
      .filter(contacto => !contacto.isGroup && !contacto.isMe && contacto.name)
      .slice(0, 100) // Limitar a 100 contactos
      .map(contacto => ({
        id: contacto.id._serialized,
        nombre: contacto.name || contacto.pushname || '',
        numero: contacto.number
      }));
    
    res.json({
      exito: true,
      contactos: listaContactos
    });
  } catch (error) {
    res.status(500).json({
      exito: false,
      error: error.message
    });
  }
});

// Ruta para obtener mensajes recibidos
app.get('/api/mensajes-recibidos', requiereAutenticacion, async (req, res) => {
  try {
    if (req.query.limpiar === 'true') {
      const copiaMensajes = [...mensajesEntrantes];
      mensajesEntrantes = [];
      res.json({
        exito: true,
        mensajesLimpiados: true,
        mensajesEliminados: copiaMensajes.length
      });
    } else {
      res.json({
        exito: true,
        mensajes: mensajesEntrantes
      });
    }
  } catch (error) {
    res.status(500).json({
      exito: false,
      error: error.message
    });
  }
});

// Ruta para verificar número
app.get('/api/verificar-numero/:numero', 
  requiereAutenticacion,
  requiereConexion,
  [param('numero').isString().isLength({ min: 7, max: 20 })],
  async (req, res) => {
    try {
      const errores = validationResult(req);
      if (!errores.isEmpty()) {
        return res.status(400).json({ exito: false, errores: errores.array() });
      }

      const numero = req.params.numero;
      
      if (!validarNumeroTelefono(numero)) {
        return res.status(400).json({
          exito: false,
          error: 'Formato de número inválido'
        });
      }

      const chatId = `${numero}@c.us`;
      const estaRegistrado = await cliente.isRegisteredUser(chatId);
      
      res.json({
        exito: true,
        existe: estaRegistrado,
        numero: numero
      });
    } catch (error) {
      console.error('Error verificando número:', error);
      res.status(500).json({
        exito: false,
        error: error.message
      });
    }
  }
);

// Página web de estado (página principal)
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="es">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>WhatsApp API - Estado</title>
      <style>
        body { 
          font-family: 'Segoe UI', Arial, sans-serif; 
          max-width: 900px; 
          margin: 0 auto; 
          padding: 20px;
          background: #f0f2f5;
          color: #1f2937;
        }
        .contenedor {
          background: white;
          padding: 30px;
          border-radius: 12px;
          box-shadow: 0 4px 6px rgba(0,0,0,0.1);
          margin-bottom: 20px;
        }
        .estado {
          padding: 16px;
          border-radius: 8px;
          margin: 16px 0;
          font-weight: 600;
          text-align: center;
        }
        .conectado { background: #dcfce7; color: #166534; border: 2px solid #bbf7d0; }
        .desconectado { background: #fef2f2; color: #dc2626; border: 2px solid #fecaca; }
        .esperando { background: #fefce8; color: #ca8a04; border: 2px solid #fef08a; }
        .cargando { background: #eff6ff; color: #1d4ed8; border: 2px solid #bfdbfe; }
        
        .qr-contenedor {
          text-align: center;
          margin: 20px 0;
          padding: 20px;
          background: #f8fafc;
          border-radius: 8px;
          border: 2px dashed #94a3b8;
        }
        .qr-datos {
          font-family: 'Courier New', monospace;
          font-size: 8px;
          background: #1f2937;
          color: #f9fafb;
          padding: 20px;
          border-radius: 8px;
          overflow: auto;
          line-height: 1;
        }
        .instrucciones {
          background: #f1f5f9;
          padding: 20px;
          border-radius: 8px;
          margin: 20px 0;
          border-left: 4px solid #3b82f6;
        }
        .endpoint {
          background: #f8fafc;
          padding: 12px;
          border-radius: 6px;
          margin: 8px 0;
          font-family: 'Courier New', monospace;
          border-left: 4px solid #10b981;
        }
        .alerta {
          background: #fef2f2;
          border: 1px solid #fecaca;
          color: #dc2626;
          padding: 16px;
          border-radius: 8px;
          margin: 16px 0;
        }
        h1 { color: #1f2937; margin-bottom: 10px; }
        h2 { color: #374151; margin-top: 30px; }
        h3 { color: #4b5563; }
        .version { 
          position: absolute; 
          top: 20px; 
          right: 20px; 
          background: #e5e7eb; 
          padding: 8px 12px; 
          border-radius: 16px; 
          font-size: 12px;
          color: #6b7280;
        }
      </style>
      <script>
        function obtenerClaseEstado(estado) {
          if (estado === 'conectado') return 'conectado';
          if (estado.includes('cargando') || estado === 'autenticado' || estado === 'inicializando') return 'cargando';
          if (estado === 'esperando_qr') return 'esperando';
          return 'desconectado';
        }
        
        function obtenerMensajeEstado(estado) {
          switch(estado) {
            case 'conectado': return '✅ Conectado y listo para usar';
            case 'esperando_qr': return '📱 Esperando escaneo del código QR';
            case 'autenticado': return '🔑 Autenticado, cargando...';
            case 'inicializando': return '🚀 Inicializando...';
            case 'desconectado': return '❌ Desconectado';
            case 'error_autenticacion': return '❌ Error de autenticación';
            default:
              if (estado.includes('cargando_')) {
                const porcentaje = estado.split('_')[1];
                return '⏳ Cargando... ' + porcentaje + '%';
              }
              return estado;
          }
        }

        function verificarEstado() {
          fetch('/api/estado')
          .then(response => response.json())
          .then(datos => {
            const elementoEstado = document.getElementById('estado');
            const claseEstado = obtenerClaseEstado(datos.estado);
            const mensajeEstado = obtenerMensajeEstado(datos.estado);
            
            elementoEstado.textContent = mensajeEstado;
            elementoEstado.className = 'estado ' + claseEstado;
            
            const contenedorQr = document.getElementById('qr-contenedor');
            if (datos.codigoQR && datos.estado === 'esperando_qr') {
              contenedorQr.style.display = 'block';
              document.getElementById('qr-datos').textContent = datos.codigoQR;
            } else {
              contenedorQr.style.display = 'none';
            }

            document.getElementById('version').textContent = 'v' + (datos.version || '1.0.0');
          })
          .catch(error => {
            console.error('Error:', error);
            document.getElementById('estado').textContent = '❌ Error de conexión';
            document.getElementById('estado').className = 'estado desconectado';
          });
        }

        document.addEventListener('DOMContentLoaded', () => {
          verificarEstado();
          setInterval(verificarEstado, 3000);
        });
      </script>
    </head>
    <body>
      <div class="version" id="version">v2.0.0</div>
      
      <div class="contenedor">
        <h1>🚀 WhatsApp API - Estado del Servicio</h1>
        
        <div id="estado" class="estado cargando">⏳ Cargando...</div>
        
        <div id="qr-contenedor" class="qr-contenedor" style="display: none;">
          <h3>📱 Escanea este código QR con tu WhatsApp:</h3>
          <div class="instrucciones">
            <strong>Pasos para conectar:</strong><br>
            1. Abre WhatsApp en tu teléfono<br>
            2. Ve a <strong>Configuración → Dispositivos vinculados</strong><br>
            3. Toca <strong>"Vincular un dispositivo"</strong><br>
            4. Escanea el código QR que aparece abajo
          </div>
          <pre id="qr-datos" class="qr-datos"></pre>
        </div>
        
        <div class="alerta">
          <strong>⚠️ Seguridad:</strong> Esta API requiere autenticación para todas las operaciones. 
          Usa <code>POST /api/auth</code> con tu contraseña para obtener un token JWT.
        </div>
      </div>

      <div class="contenedor">
        <h2>📋 Endpoints Disponibles</h2>
        
        <h3>🔐 Autenticación:</h3>
        <div class="endpoint">POST /api/auth - Obtener token de autenticación</div>
        
        <h3>📊 Estado:</h3>
        <div class="endpoint">GET /api/estado - Estado del bot (público)</div>
        
        <h3>💬 Mensajes:</h3>
        <div class="endpoint">POST /api/enviar-mensaje - Enviar mensaje</div>
        <div class="endpoint">GET /api/mensajes-recibidos - Obtener mensajes recibidos</div>
        
        <h3>📞 Contactos:</h3>
        <div class="endpoint">GET /api/contactos - Listar contactos</div>
        <div class="endpoint">GET /api/grupos - Listar grupos</div>
        <div class="endpoint">GET /api/verificar-numero/:numero - Verificar si un número existe</div>
        
        <div class="instrucciones">
          <h3>🔑 Cómo usar la API:</h3>
          <ol>
            <li>Primero, auténticate: <code>POST /api/auth</code> con tu contraseña</li>
            <li>Usa el token JWT recibido en el header: <code>Authorization: Bearer &lt;token&gt;</code></li>
            <li>Todos los endpoints (excepto /api/estado) requieren autenticación</li>
            <li>Los tokens expiran en 24 horas</li>
          </ol>
        </div>
      </div>
    </body>
    </html>
  `);
});

// Manejo de errores
app.use((error, req, res, next) => {
  console.error('❌ Error del servidor:', error.stack);
  
  if (error.type === 'entity.too.large') {
    return res.status(413).json({
      exito: false,
      error: 'Payload demasiado grande'
    });
  }
  
  res.status(500).json({
    exito: false,
    error: 'Error interno del servidor'
  });
});

// Manejo de rutas no encontradas
app.use('*', (req, res) => {
  res.status(404).json({
    exito: false,
    error: 'Endpoint no encontrado',
    mensaje: 'Visita / para ver los endpoints disponibles'
  });
});

// Función para cerrar limpiamente
const cerrarAplicacion = (signal) => {
  console.log(`\n[${signal}] Cerrando aplicación...`);
  
  if (servidor) {
    servidor.close(() => {
      console.log('✅ Servidor Express cerrado correctamente');
      
      if (cliente && clienteListo) {
        cliente.destroy().then(() => {
          console.log('✅ Cliente WhatsApp desconectado correctamente');
          process.exit(0);
        }).catch((error) => {
          console.error('❌ Error al cerrar cliente WhatsApp:', error);
          process.exit(1);
        });
      } else {
        process.exit(0);
      }
    });
  } else {
    process.exit(0);
  }
};

// Manejo de señales del sistema
process.on('SIGINT', () => cerrarAplicacion('SIGINT'));
process.on('SIGTERM', () => cerrarAplicacion('SIGTERM'));
process.on('SIGUSR2', () => cerrarAplicacion('SIGUSR2')); // Para nodemon

// Manejo de errores no capturados
process.on('uncaughtException', (error) => {
  console.error('❌ Excepción no capturada:', error);
  cerrarAplicacion('UNCAUGHT_EXCEPTION');
});

process.on('unhandledRejection', (razon, promesa) => {
  console.error('❌ Promesa rechazada no manejada:', razon);
  console.error('Promesa:', promesa);
  cerrarAplicacion('UNHANDLED_REJECTION');
});

// Inicializar el cliente WhatsApp
console.log('🚀 Iniciando cliente WhatsApp...');
cliente.initialize();

// Iniciar el servidor
const servidor = aplicacion.listen(PUERTO, () => {
  console.log(`🌐 Servidor API ejecutándose en puerto ${PUERTO}`);
  console.log(`📱 Dashboard disponible en: http://localhost:${PUERTO}`);
  console.log(`🔐 Contraseña API actual: ${API_PASSWORD}`);
  console.log('⚠️  IMPORTANTE: Cambia la contraseña en producción usando la variable API_PASSWORD');
  console.log('\n📋 Variables de entorno disponibles:');
  console.log('   - PORT: Puerto del servidor');
  console.log('   - JWT_SECRET: Secreto para tokens JWT');
  console.log('   - API_PASSWORD: Contraseña para autenticación');
  console.log('   - ALLOWED_ORIGINS: Orígenes CORS permitidos (separados por coma)');
  console.log('   - MAX_FILE_SIZE: Tamaño máximo de archivo en MB');
  console.log('   - RATE_LIMIT_WINDOW: Ventana de límite de tasa en minutos');
  console.log('   - RATE_LIMIT_MAX: Máximo de requests por ventana');
  console.log('\n🔗 Endpoints principales:');
  console.log(`   - GET  http://localhost:${PUERTO}/ (Dashboard)`);
  console.log(`   - POST http://localhost:${PUERTO}/api/auth (Autenticación)`);
  console.log(`   - GET  http://localhost:${PUERTO}/api/estado (Estado público)`);
  console.log(`   - POST http://localhost:${PUERTO}/api/enviar-mensaje (Enviar mensaje)`);
  console.log(`   - GET  http://localhost:${PUERTO}/api/mensajes-recibidos (Mensajes recibidos)`);
  console.log(`   - GET  http://localhost:${PUERTO}/api/contactos (Lista de contactos)`);
  console.log(`   - GET  http://localhost:${PUERTO}/api/grupos (Lista de grupos)`);
  console.log(`   - GET  http://localhost:${PUERTO}/api/verificar-numero/:numero (Verificar número)`);
});

// Configurar timeout del servidor
servidor.timeout = 30000; // 30 segundos

// Exportar para pruebas
module.exports = {
  aplicacion,
  cliente,
  cerrarAplicacion
};