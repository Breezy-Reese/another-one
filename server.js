// server.js
const express = require('express');
const cors = require('cors');
const path = require('path');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();

// =======================
// Middleware
// =======================
app.use(cors());
app.use(express.json());

// Serve static files (frontend)
// Public frontend files (e.g., patient portal)
app.use(express.static(path.join(__dirname)));

// Serve admin folder
app.use('/admin', express.static(path.join(__dirname, 'admin')));

// =======================
// MySQL Connection
// =======================
const dbConfig = {
  host: 'localhost',
  user: 'root',
  password: '' // update if you set a MySQL password
};

let connection;
async function initDB() {
  connection = await mysql.createConnection(dbConfig);
  console.log('Connected to MySQL server');

  await connection.query(`CREATE DATABASE IF NOT EXISTS hospital_system`);
  await connection.query(`USE hospital_system`);

  // Users table
  await connection.execute(`
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(50) NOT NULL UNIQUE,
      email VARCHAR(100) NOT NULL UNIQUE,
      password VARCHAR(255) NOT NULL,
      role ENUM('admin','doctor','nurse','staff','patient') DEFAULT 'patient',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Patients table
  await connection.execute(`
    CREATE TABLE IF NOT EXISTS patients (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(100),
      email VARCHAR(100),
      phone VARCHAR(20),
      age INT,
      ailment VARCHAR(255),
      doctor_assigned INT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (doctor_assigned) REFERENCES users(id) ON DELETE SET NULL
    )
  `);

  // Appointments table
  await connection.execute(`
    CREATE TABLE IF NOT EXISTS appointments (
      id INT AUTO_INCREMENT PRIMARY KEY,
      full_name VARCHAR(100),
      email VARCHAR(100),
      phone VARCHAR(20),
      department VARCHAR(50),
      appointment_date DATE,
      appointment_time TIME,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Default admin
  const [rows] = await connection.execute(
    `SELECT * FROM users WHERE email = ?`,
    ['admin@hospital.com']
  );
  if (rows.length === 0) {
    const hashed = await bcrypt.hash('StrongPass123!', 10);
    await connection.execute(
      `INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)`,
      ['adminuser', 'admin@hospital.com', hashed, 'admin']
    );
    console.log('Default admin created: admin@hospital.com / StrongPass123!');
  }
}
initDB().catch(err => console.error('DB init error:', err));

// =======================
// JWT Authentication
// =======================
const JWT_SECRET = 'secret123'; // move to env variable in production

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });
  }
}

function isAdmin(req, res, next) {
  if (req.user && req.user.role === 'admin') return next();
  return res.status(403).json({ message: 'Access denied: Admins only' });
}

// =======================
// Routes
// =======================

// Serve default patient dashboard (if you have one)
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'dashboard.html'));
});

// Serve admin dashboard
app.get('/admin-dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin', 'admin.html'));
});

// Login
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const [rows] = await connection.execute(
      `SELECT * FROM users WHERE email = ?`,
      [email]
    );
    if (!rows.length) return res.status(404).json({ message: 'User not found' });

    const user = rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ message: 'Invalid password' });

    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, {
      expiresIn: '1d'
    });
    res.json({ token, user: { username: user.username, role: user.role } });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// =======================
// Patient Portal Routes
// =======================

// Book appointment (public)
app.post('/appointments', async (req, res) => {
  try {
    const { full_name, email, phone, department, appointment_date, appointment_time } =
      req.body;

    const [result] = await connection.execute(
      `INSERT INTO appointments (full_name, email, phone, department, appointment_date, appointment_time) 
       VALUES (?, ?, ?, ?, ?, ?)`,
      [full_name, email, phone, department, appointment_date, appointment_time]
    );

    res.json({
      message: 'Appointment booked successfully',
      appointmentId: result.insertId
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// List all appointments (public)
app.get('/appointments', async (req, res) => {
  try {
    const [rows] = await connection.execute(`
      SELECT id, full_name, email, phone, department, 
             DATE_FORMAT(appointment_date, '%Y-%m-%d') AS appointment_date, 
             DATE_FORMAT(appointment_time, '%H:%i:%s') AS appointment_time, 
             created_at
      FROM appointments
      ORDER BY appointment_date ASC, appointment_time ASC
    `);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// =======================
// Admin Routes
// =======================
app.use('/api/admin', authenticateToken, isAdmin);

// --- Manage Users ---
app.post('/api/admin/create-user', async (req, res) => {
  try {
    const { username, email, password, role } = req.body;
    const hashed = await bcrypt.hash(password, 10);
    const [result] = await connection.execute(
      `INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)`,
      [username, email, hashed, role]
    );
    res.json({ message: 'User created', userId: result.insertId });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get('/api/admin/users', async (req, res) => {
  try {
    const [rows] = await connection.execute(
      `SELECT id, username, email, role, created_at FROM users`
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// --- Manage Patients ---
app.get('/api/admin/patients', async (req, res) => {
  try {
    const [rows] = await connection.execute(`
      SELECT p.*, u.username AS doctor_name, u.email AS doctor_email
      FROM patients p
      LEFT JOIN users u ON p.doctor_assigned = u.id
    `);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// --- Manage Appointments ---
app.get('/api/admin/appointments', async (req, res) => {
  try {
    const [rows] = await connection.execute(`
      SELECT id, full_name, email, phone, department, 
             DATE_FORMAT(appointment_date, '%Y-%m-%d') AS appointment_date, 
             DATE_FORMAT(appointment_time, '%H:%i:%s') AS appointment_time,
             created_at
      FROM appointments
      ORDER BY appointment_date ASC, appointment_time ASC
    `);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// =======================
// Start server
// =======================
const PORT = 4000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
