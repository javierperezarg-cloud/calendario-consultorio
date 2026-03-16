/**
 * DentaCal API — Sistema de Citas Odontológicas
 * Stack: Node.js + Express + PostgreSQL (pg)
 *
 * Instalar: npm install express pg cors dotenv bcryptjs jsonwebtoken
 * Correr:   node server.js
 */

require('dotenv').config();
const express    = require('express');
const { Pool }   = require('pg');
const cors       = require('cors');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');

const app = express();
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-Api-Key', 'Authorization']
}));
app.use(express.json());

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
  password: process.env.DB_PASSWORD || 'Ebarcas88*',
});

// ─── CLAVES ─────────────────────────────────────────────────────────────────
const API_KEY   = process.env.API_KEY   || 'dentacal-secret-2024';
const JWT_SECRET = process.env.JWT_SECRET || 'dentacal-jwt-95624378';

// ─── MIDDLEWARE: API KEY (para n8n) ─────────────────────────────────────────
function auth(req, res, next) {
  const key = req.headers['x-api-key'];
  if (key !== API_KEY) return res.status(401).json({ error: 'No autorizado' });
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
    const payload = jwt.verify(token, JWT_SECRET);
    req.usuario = payload;
    next();
  } catch {
    return res.status(401).json({ error: 'Token inválido o expirado' });
  }
}

// ─── MIDDLEWARE: API KEY O JWT (acepta ambos) ────────────────────────────────
function authAny(req, res, next) {
  const key    = req.headers['x-api-key'];
  const header = req.headers['authorization'];
  if (key === API_KEY) return next();
  if (header && header.startsWith('Bearer ')) {
    const token = header.split(' ')[1];
    try {
      req.usuario = jwt.verify(token, JWT_SECRET);
      return next();
    } catch {}
  }
  return res.status(401).json({ error: 'No autorizado' });
}

// ─── HEALTH CHECK ───────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok', timestamp: new Date() }));


// ══════════════════════════════════════════════════════════════════════════════
// AUTENTICACIÓN DEL CALENDARIO
// ══════════════════════════════════════════════════════════════════════════════

/**
 * POST /login
 * Body: { usuario, password }
 */
app.post('/login', async (req, res) => {
  try {
    const { usuario, password } = req.body;
    if (!usuario || !password) {
      return res.status(400).json({ error: 'Usuario y contraseña son requeridos' });
    }

    // Buscar usuario — query parametrizada, sin SQL injection
    const result = await pool.query(
      'SELECT * FROM usuarios WHERE usuario = $1 AND activo = true',
      [usuario.toLowerCase().trim()]
    );

    if (!result.rows.length) {
      return res.status(401).json({ error: 'Credenciales incorrectas' });
    }

    const user = result.rows[0];
    const passwordOk = await bcrypt.compare(password, user.password_hash);

    if (!passwordOk) {
      return res.status(401).json({ error: 'Credenciales incorrectas' });
    }

    // Generar token JWT — expira en 8 horas
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
    res.status(500).json({ error: err.message });
  }
});


// ══════════════════════════════════════════════════════════════════════════════
// ENDPOINTS DE CITAS (acepta API Key de n8n o JWT del calendario)
// ══════════════════════════════════════════════════════════════════════════════

/**
 * GET /citas
 */
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
    res.status(500).json({ error: err.message });
  }
});


/**
 * GET /citas/:id
 */
app.get('/citas/:id', authAny, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM citas WHERE id = $1', [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Cita no encontrada' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


/**
 * POST /citas — Crear nueva cita
 */
app.post('/citas', authAny, async (req, res) => {
  try {
    let {
      paciente_nombre,
      paciente_telefono = null,
      paciente_email    = null,
      tipo,
      doctor,
      fecha,
      hora,
      duracion_min = 30,
      notas = null,
      canal = 'manual',
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

    res.status(201).json({
      success: true,
      cita: result.rows[0],
      mensaje: `Cita creada para ${paciente_nombre} el ${fecha} a las ${hora}`
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


/**
 * PATCH /citas/:id
 */
app.patch('/citas/:id', authAny, async (req, res) => {
  try {
    const campos = ['paciente_nombre','paciente_telefono','paciente_email','tipo','doctor','fecha','hora','duracion_min','notas','estado'];
    const updates = [];
    const values  = [];
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
    values.push(req.params.id);

    const result = await pool.query(
      `UPDATE citas SET ${updates.join(', ')} WHERE id = $${i} RETURNING *`,
      values
    );

    if (!result.rows.length) return res.status(404).json({ error: 'Cita no encontrada' });
    res.json({ success: true, cita: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


/**
 * DELETE /citas/:id
 */
app.delete('/citas/:id', authAny, async (req, res) => {
  try {
    const { motivo = null } = req.body || {};
    const result = await pool.query(
      `UPDATE citas SET estado = 'cancelada', notas = COALESCE(notas || ' | ', '') || $1, actualizado_en = NOW()
       WHERE id = $2 RETURNING *`,
      [motivo ? `Cancelada: ${motivo}` : 'Cancelada', req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Cita no encontrada' });
    res.json({ success: true, mensaje: 'Cita cancelada', cita: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


/**
 * GET /disponibilidad
 */
app.get('/disponibilidad', authAny, async (req, res) => {
  try {
    const { fecha, doctor, duracion = 30 } = req.query;
    if (!fecha || !doctor) return res.status(400).json({ error: 'fecha y doctor son requeridos' });

    const fechaNorm  = normalizarFecha(fecha);
    const HORA_INICIO = 8;
    const HORA_FIN    = 18;
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
    res.status(500).json({ error: err.message });
  }
});


/**
 * GET /doctores
 */
app.get('/doctores', authAny, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM doctores ORDER BY nombre');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


/**
 * POST /buscar — Buscar citas por nombre de paciente
 */
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
    res.status(500).json({ error: err.message });
  }
});


/**
 * POST /cancelar — Cancelar cita por ID en el body
 */
app.post('/cancelar', auth, async (req, res) => {
  try {
    const { cita_id, motivo = null } = req.body;
    if (!cita_id) return res.status(400).json({ error: 'cita_id es requerido' });

    const result = await pool.query(
      `UPDATE citas SET estado = 'cancelada', notas = COALESCE(notas || ' | ', '') || $1, actualizado_en = NOW()
       WHERE id = $2 RETURNING *`,
      [motivo ? `Cancelada: ${motivo}` : 'Cancelada', cita_id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Cita no encontrada' });
    res.json({ success: true, mensaje: 'Cita cancelada', cita: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ─── START SERVER ───────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ DentaCal API corriendo en puerto ${PORT}`);
  console.log(`   Health: http://localhost:${PORT}/health`);
});
