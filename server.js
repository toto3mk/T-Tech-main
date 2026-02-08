if (process.env.NODE_ENV !== 'production') {
  require("dotenv").config();
}const express = require("express");
const path = require("path");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { Pool } = require('pg'); // Changed from sqlite3

const app = express();
const port = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!process.env.JWT_SECRET) {
  console.warn("WARNING: JWT_SECRET is missing from environment variables.");
}

// Database Setup for Vercel/Postgres
const db = new Pool({
  connectionString: process.env.DATABASE_URL, 
  ssl: { rejectUnauthorized: false }
});

// Initialize Tables (Postgres Syntax)
const initDb = async () => {
  try {
    await db.query(`
      CREATE TABLE IF NOT EXISTS inquiries (
        id SERIAL PRIMARY KEY,
        submissionDate TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        status TEXT DEFAULT 'New',
        clientName TEXT,
        contactPerson TEXT,
        email TEXT,
        phone TEXT,
        projectName TEXT,
        projectDescription TEXT,
        dueDate TEXT,
        budget DECIMAL,
        duration INTEGER
      );
    `);
    
    await db.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE,
        passwordHash TEXT,
        role TEXT DEFAULT 'admin'
      );
    `);
  } catch (err) {
    console.error("Initialization Error:", err);
  }
};
initDb();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname)));

// Auth Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token provided" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Token invalid/expired" });
    req.user = user;
    next();
  });
}

// --- UPDATED ROUTES (Postgres uses $1 instead of ?) ---

app.post("/api/project-submission", async (req, res) => {
  const data = req.body;
  const sql = `INSERT INTO inquiries (clientName, contactPerson, email, phone, projectName, projectDescription, dueDate, budget, duration) 
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`;
  const params = [
    data.clientName, data.contactPerson, data.email, data.phone,
    data.projectName, data.projectDescription, data.dueDate, data.budget, data.duration,
  ];

  try {
    const result = await db.query(sql, params);
    res.status(201).json({ message: "Inquiry received", id: result.rows[0].id });
  } catch (err) {
    res.status(500).json({ message: "Database error", error: err.message });
  }
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await db.query("SELECT * FROM users WHERE username = $1", [username]);
    const user = result.rows[0];

    if (!user) return res.status(401).json({ message: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (isMatch) {
      const token = jwt.sign(
        { id: user.id, username: user.username, role: user.role },
        JWT_SECRET,
        { expiresIn: "2h" }
      );
      res.json({ message: "Login successful", token, username: user.username });
    } else {
      res.status(401).json({ message: "Invalid credentials" });
    }
  } catch (err) {
    res.status(500).json({ message: "Database error" });
  }
});

app.get("/api/projects", authenticateToken, async (req, res) => {
  try {
    const result = await db.query("SELECT * FROM inquiries ORDER BY submissionDate DESC");
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete("/api/projects/:id", authenticateToken, async (req, res) => {
  try {
    await db.query("DELETE FROM inquiries WHERE id = $1", [req.params.id]);
    res.json({ message: "Project deleted" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put("/api/projects/:id", authenticateToken, async (req, res) => {
  const d = req.body;
  const sql = `UPDATE inquiries SET clientName=$1, contactPerson=$2, email=$3, phone=$4, projectName=$5, projectDescription=$6, dueDate=$7, budget=$8, duration=$9 WHERE id=$10`;
  const params = [
    d.clientName, d.contactPerson, d.email, d.phone, d.projectName,
    d.projectDescription || null, d.dueDate, d.budget, d.duration, req.params.id
  ];
  try {
    await db.query(sql, params);
    res.json({ message: "Project updated" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch("/api/projects/:id/status", authenticateToken, async (req, res) => {
  const { status } = req.body;
  try {
    await db.query("UPDATE inquiries SET status = $1 WHERE id = $2", [status, req.params.id]);
    res.json({ message: `Status updated to ${status}` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Start Server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});