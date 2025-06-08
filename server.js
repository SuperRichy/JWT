const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const jwt = require("jsonwebtoken");
const path = require("path");

const app = express();
const port = 3000;
const secretKey = "secret";

// Middleware
app.use(express.json());

// Base de datos SQLite
const db = new sqlite3.Database(path.join(__dirname, "clientes.db"), (err) => {
  if (err) return console.error("Error conectando a la base de datos:", err.message);
  console.log("Conectado a la base de datos SQLite.");
});

// Login y generación de token
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ message: "usuario y contraseña requeridos" });

  if (username === "admin" && password === "123") {
    const token = jwt.sign({ username }, secretKey, { expiresIn: "1h" });
    return res.status(200).json({ token });
  } else {
    return res.status(401).json({ message: "Autenticación incorrecta" });
  }
});

// Middleware para verificar el token
function verifyToken(req, res, next) {
  const header = req.header("Authorization") || "";
  const token = header.split(" ")[1];

  if (!token) return res.status(401).json({ message: "Token no proporcionado" });

  try {
    const payload = jwt.verify(token, secretKey);
    req.username = payload.username;
    next();
  } catch (error) {
    return res.status(403).json({ message: "Token no válido" });
  }
}

// Ruta protegida de ejemplo
app.get("/protected", verifyToken, (req, res) => {
  return res.status(200).json({ message: "Acceso permitido", usuario: req.username });
});

//
// CRUD de Clientes (protegido con JWT)
//

// Crear cliente
app.post("/clientes", verifyToken, (req, res) => {
  const { nombre, correo, telefono, direccion } = req.body;
  const sql = "INSERT INTO clientes (nombre, correo, telefono, direccion) VALUES (?, ?, ?, ?)";
  db.run(sql, [nombre, correo, telefono, direccion], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.status(201).json({ id: this.lastID, nombre, correo, telefono, direccion });
  });
});

// Obtener todos los clientes
app.get("/clientes", verifyToken, (req, res) => {
  db.all("SELECT * FROM clientes", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Obtener cliente por ID
app.get("/clientes/:id", verifyToken, (req, res) => {
  db.get("SELECT * FROM clientes WHERE id = ?", [req.params.id], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(404).json({ message: "Cliente no encontrado" });
    res.json(row);
  });
});

// Actualizar cliente
app.put("/clientes/:id", verifyToken, (req, res) => {
  const { nombre, correo, telefono, direccion } = req.body;
  const sql = "UPDATE clientes SET nombre = ?, correo = ?, telefono = ?, direccion = ? WHERE id = ?";
  db.run(sql, [nombre, correo, telefono, direccion, req.params.id], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ message: "Cliente no encontrado" });
    res.json({ id: req.params.id, nombre, correo, telefono, direccion });
  });
});

// Eliminar cliente
app.delete("/clientes/:id", verifyToken, (req, res) => {
  db.run("DELETE FROM clientes WHERE id = ?", [req.params.id], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ message: "Cliente no encontrado" });
    res.json({ message: "Cliente eliminado" });
  });
});

// Iniciar servidor
app.listen(port, () => {
  console.log(`Servidor corriendo en http://localhost:${port}`);
});
