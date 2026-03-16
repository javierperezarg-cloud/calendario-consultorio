/**
 * DentaCal API — Sistema de Citas Odontológicas
 * Stack: Node.js + Express + PostgreSQL (pg)
 *
 * Instalar: npm install express pg cors dotenv bcryptjs jsonwebtoken express-rate-limit
 * Correr:   node server.js
 */

require('dotenv').config();
const express      = require('express');
const { Pool }     = require('pg');
const cors         = require('cors');
const bcrypt       = require('bcryptjs');
const jwt          = require('jsonwebtoken');
const rateLimit    = require('express-rate-limit');

const app = express();

// ─── CORS — solo permite el dominio del calendario ──────────────────────────
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);

app.use(cors({
  origin: function(origin, callback) {
    // Permitir requests sin origin (n8n, curl, Postman)
    if (!origin) return callback(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    return callback(new Error('CORS: origen no permitido'));
  },
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-Api-Key', 'Authorization']
}));

app.use(express.json({ limit: '10kb' })); // limitar tamaño del body

// ─── RATE LIMITING ───────────────────────────────────────────────────────────

// Login: máximo 10 intentos por 15 minutos por IP
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Demasiados intentos. Espera 15 minutos.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// API general: máximo 200 requests por minuto por IP
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 200,
  message: { error: 'Demasiadas solicitudes. Intenta en un momento.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/login', loginLimiter);
app.use('/api', apiLimiter);

// ─── HELPER: normalizar fecha a YYYY-MM-DD ──────────────────────────────────
function normalizarFecha(fecha) {
  if (!fecha) return fecha;
  return fecha.toString().split('T')[0];
}

// ─── CONEXIÓN POSTGRESQL ───────────────────────────────────────────────────
const pool = new Pool({
  host:     process.env.DB_HOST     || 'localhost',
  port:     process.env.DB_PORT     || 5432,
  database: process.env.DB_NAME     || 'dentacal',
  user:     process.env.DB_USER     || 'postgres',
  password: process.env.DB_PASSWORD || '',
});

// ─── CLAVES ─────────────────────────────────────────────────────────────────
const API_KEY    = process.env.API_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

// Verificar que las claves críticas estén configuradas
if (!API_KEY || !JWT_SECRET) {
  console.error('❌ ERROR: API_KEY y JWT_SECRET son requeridos como variables de entorno');
  process.exit(1);
}

// ─── MIDDLEWARE: API KEY (para n8n) ─────────────────────────────────────────
function auth(req, res, next) {
  const key = req.headers['x-api-key'];
  if (!key || key !== API_KEY) return res.status(401).json({ error: 'No autorizado' });
  next();
}

// ─── MIDDLEWARE: JWT (para el calendario) ───────────────────────────────────
function authJWT(req, res, next) {
  const header = req.headers['authorization'];
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }
  const token = header.split(' ')[1];
  try {
    req.usuario = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Token inválido o expirado' });
  }
}

// ─── MIDDLEWARE: API KEY O JWT (acepta ambos) ────────────────────────────────
function authAny(req, res, next) {
  const key    = req.headers['x-api-key'];
  const header = req.headers['authorization'];
  if (key && key === API_KEY) return next();
  if (header && header.startsWith('Bearer ')) {
    const token = header.split(' ')[1];
    try {
      req.usuario = jwt.verify(token, JWT_SECRET);
      return next();
    } catch {}
  }
  return res.status(401).json({ error: 'No autorizado' });
}

// ─── HEALTH CHECK (con auth para no exponer info) ───────────────────────────
app.get('/health', authAny, (req, res) => res.json({ status: 'ok' }));

// Health público mínimo — solo para EasyPanel
app.get('/ping', (req, res) => res.json({ ok: true }));


// ══════════════════════════════════════════════════════════════════════════════
// AUTENTICACIÓN
// ══════════════════════════════════════════════════════════════════════════════

app.post('/login', loginLimiter, async (req, res) => {
  try {
    const { usuario, password } = req.body;
    if (!usuario || !password) {
      return res.status(400).json({ error: 'Usuario y contraseña son requeridos' });
    }

    // Sanitizar input
    const usuarioClean = usuario.toLowerCase().trim().substring(0, 50);

    const result = await pool.query(
      'SELECT * FROM usuarios WHERE usuario = $1 AND activo = true',
      [usuarioClean]
    );

    // Siempre comparar hash aunque no exista usuario (evita timing attacks)
    const dummyHash = '$2b$10$abcdefghijklmnopqrstuvuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu';
    const hash = result.rows[0]?.password_hash || dummyHash;
    const passwordOk = await bcrypt.compare(password, hash);

    if (!result.rows.length || !passwordOk) {
      return res.status(401).json({ error: 'Credenciales incorrectas' });
    }

    const user = result.rows[0];
    const token = jwt.sign(
      { id: user.id, usuario: user.usuario, nombre: user.nombre },
      JWT_SECRET,
      { expiresIn: '8h' }
    );

    res.json({
      success: true,
      token,
      usuario: { id: user.id, nombre: user.nombre, usuario: user.usuario }
    });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ error: 'Error interno' });
  }
});


// ══════════════════════════════════════════════════════════════════════════════
// ENDPOINTS DE CITAS
// ══════════════════════════════════════════════════════════════════════════════

app.get('/citas', authAny, async (req, res) => {
  try {
    const { fecha, desde, hasta, estado, paciente } = req.query;
    let query = 'SELECT * FROM citas WHERE 1=1';
    const params = [];
    let i = 1;

    if (fecha)    { query += ` AND fecha::date = $${i++}`;         params.push(normalizarFecha(fecha)); }
    if (desde)    { query += ` AND fecha::date >= $${i++}`;        params.push(normalizarFecha(desde)); }
    if (hasta)    { query += ` AND fecha::date <= $${i++}`;        params.push(normalizarFecha(hasta)); }
    if (estado)   { query += ` AND estado = $${i++}`;              params.push(estado); }
    if (paciente) { query += ` AND paciente_nombre ILIKE $${i++}`; params.push(`%${paciente}%`); }

    query += ' ORDER BY fecha ASC, hora ASC';
    const result = await pool.query(query, params);
    res.json({ citas: result.rows, total: result.rowCount });
  } catch (err) {
    res.status(500).json({ error: 'Error interno' });
  }
});


app.get('/citas/:id', authAny, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'ID inválido' });
    const result = await pool.query('SELECT * FROM citas WHERE id = $1', [id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Cita no encontrada' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Error interno' });
  }
});


app.post('/citas', authAny, async (req, res) => {
  try {
    let {
      paciente_nombre, paciente_telefono = null, paciente_email = null,
      tipo, doctor, fecha, hora, duracion_min = 30, notas = null, canal = 'manual',
    } = req.body;

    if (paciente_nombre) paciente_nombre = paciente_nombre.replace(/^=/, '').trim();
    if (tipo)            tipo            = tipo.replace(/^=/, '').trim();
    if (doctor)          doctor          = doctor.replace(/^=/, '').trim();
    fecha = normalizarFecha(fecha);

    if (!paciente_nombre) return res.status(400).json({ error: 'paciente_nombre es requerido' });
    if (!tipo)            return res.status(400).json({ error: 'tipo es requerido' });
    if (!fecha)           return res.status(400).json({ error: 'fecha es requerida' });
    if (!hora)            return res.status(400).json({ error: 'hora es requerida' });

    const conflict = await pool.query(
      `SELECT id FROM citas WHERE doctor = $1 AND fecha::date = $2 AND hora = $3 AND estado != 'cancelada'`,
      [doctor, fecha, hora]
    );
    if (conflict.rows.length > 0) {
      return res.status(409).json({ error: 'Horario no disponible', cita_id: conflict.rows[0].id });
    }

    const result = await pool.query(
      `INSERT INTO citas (paciente_nombre, paciente_telefono, paciente_email, tipo, doctor, fecha, hora, duracion_min, notas, canal, estado)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'confirmada') RETURNING *`,
      [paciente_nombre, paciente_telefono, paciente_email, tipo, doctor, fecha, hora, duracion_min, notas, canal]
    );

    res.status(201).json({ success: true, cita: result.rows[0], mensaje: `Cita creada para ${paciente_nombre} el ${fecha} a las ${hora}` });
  } catch (err) {
    res.status(500).json({ error: 'Error interno' });
  }
});


app.patch('/citas/:id', authAny, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'ID inválido' });

    const campos = ['paciente_nombre','paciente_telefono','paciente_email','tipo','doctor','fecha','hora','duracion_min','notas','estado'];
    const updates = [], values = [];
    let i = 1;

    for (const campo of campos) {
      if (req.body[campo] !== undefined) {
        let val = req.body[campo];
        if (campo === 'fecha') val = normalizarFecha(val);
        updates.push(`${campo} = $${i++}`);
        values.push(val);
      }
    }

    if (!updates.length) return res.status(400).json({ error: 'No hay campos para actualizar' });
    updates.push(`actualizado_en = NOW()`);
    values.push(id);

    const result = await pool.query(
      `UPDATE citas SET ${updates.join(', ')} WHERE id = $${i} RETURNING *`, values
    );

    if (!result.rows.length) return res.status(404).json({ error: 'Cita no encontrada' });
    res.json({ success: true, cita: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Error interno' });
  }
});


app.delete('/citas/:id', authAny, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'ID inválido' });

    const { motivo = null } = req.body || {};
    const result = await pool.query(
      `UPDATE citas SET estado = 'cancelada', notas = COALESCE(notas || ' | ', '') || $1, actualizado_en = NOW()
       WHERE id = $2 RETURNING *`,
      [motivo ? `Cancelada: ${motivo}` : 'Cancelada', id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Cita no encontrada' });
    res.json({ success: true, mensaje: 'Cita cancelada', cita: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Error interno' });
  }
});


app.get('/disponibilidad', authAny, async (req, res) => {
  try {
    const { fecha, doctor, duracion = 30 } = req.query;
    if (!fecha || !doctor) return res.status(400).json({ error: 'fecha y doctor son requeridos' });

    const fechaNorm   = normalizarFecha(fecha);
    const HORA_INICIO = 8, HORA_FIN = 18;
    const INTERVALO   = parseInt(duracion);

    const ocupadas = await pool.query(
      `SELECT hora FROM citas WHERE fecha::date = $1 AND doctor = $2 AND estado != 'cancelada'`,
      [fechaNorm, doctor]
    );
    const horasOcupadas = ocupadas.rows.map(r => r.hora.slice(0,5));

    const slots = [];
    for (let h = HORA_INICIO; h < HORA_FIN; h++) {
      for (let m = 0; m < 60; m += INTERVALO) {
        const slot = `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}`;
        if (!horasOcupadas.includes(slot)) slots.push(slot);
      }
    }

    res.json({ fecha: fechaNorm, doctor, disponibles: slots, ocupadas: horasOcupadas });
  } catch (err) {
    res.status(500).json({ error: 'Error interno' });
  }
});


app.get('/doctores', authAny, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM doctores ORDER BY nombre');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Error interno' });
  }
});


app.post('/buscar', auth, async (req, res) => {
  try {
    const paciente = req.body.paciente_nombre || req.body.paciente;
    if (!paciente) return res.status(400).json({ error: 'paciente_nombre es requerido' });

    const result = await pool.query(
      `SELECT * FROM citas 
       WHERE unaccent(lower(paciente_nombre)) ILIKE unaccent(lower($1)) 
       AND estado != 'cancelada' ORDER BY fecha ASC`,
      [`%${paciente}%`]
    );
    res.json({ citas: result.rows, total: result.rowCount });
  } catch (err) {
    res.status(500).json({ error: 'Error interno' });
  }
});


app.post('/cancelar', auth, async (req, res) => {
  try {
    const cita_id = parseInt(req.body.cita_id);
    if (!cita_id || isNaN(cita_id)) return res.status(400).json({ error: 'cita_id es requerido' });

    const { motivo = null } = req.body;
    const result = await pool.query(
      `UPDATE citas SET estado = 'cancelada', notas = COALESCE(notas || ' | ', '') || $1, actualizado_en = NOW()
       WHERE id = $2 RETURNING *`,
      [motivo ? `Cancelada: ${motivo}` : 'Cancelada', cita_id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Cita no encontrada' });
    res.json({ success: true, mensaje: 'Cita cancelada', cita: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Error interno' });
  }
});


// ─── START SERVER ───────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ DentaCal API corriendo en puerto ${PORT}`);
});
