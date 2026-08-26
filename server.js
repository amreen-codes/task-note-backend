const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const path = require("path");
const cors = require("cors");

const app = express();
const USERS_FILE = path.join(__dirname, "users.json");
const JWT_SECRET = process.env.JWT_SECRET || "change-this-secret-later";

app.use(cors());
app.use(express.json());

function readUsers() {
  if (!fs.existsSync(USERS_FILE)) return [];
  const data = fs.readFileSync(USERS_FILE, "utf-8");
  return data ? JSON.parse(data) : [];
}

function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Login zaroori hai." });
  }
  try {
    const decoded = jwt.verify(authHeader.split(" ")[1], JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch {
    return res.status(401).json({ error: "Session expire ho gaya, dobara login karein." });
  }
}

// SIGNUP
app.post("/api/register", (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: "Sab fields zaroori hain." });
  }

  const users = readUsers();
  const exists = users.find((u) => u.email.toLowerCase() === email.toLowerCase());
  if (exists) {
    return res.status(400).json({ error: "Ye email pehle se registered hai." });
  }

  const hashedPassword = bcrypt.hashSync(password, 10);
  const newUser = { id: Date.now().toString(), name, email, password: hashedPassword };
  users.push(newUser);
  saveUsers(users);

  const token = jwt.sign({ userId: newUser.id }, JWT_SECRET, { expiresIn: "30d" });
  res.json({
    success: true,
    token,
    user: { id: newUser.id, name: newUser.name, email: newUser.email },
  });
});

// LOGIN
app.post("/api/login", (req, res) => {
  const { email, password } = req.body;
  const users = readUsers();

  const user = users.find((u) => u.email.toLowerCase() === email.toLowerCase());
  if (!user) {
    return res.status(401).json({ error: "Email ya password galat hai." });
  }

  const isMatch = bcrypt.compareSync(password, user.password);
  if (!isMatch) {
    return res.status(401).json({ error: "Email ya password galat hai." });
  }

  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: "30d" });
  res.json({
    success: true,
    token,
    user: { id: user.id, name: user.name, email: user.email },
  });
});

// CURRENT USER (auto-login check)
app.get("/api/me", requireAuth, (req, res) => {
  const users = readUsers();
  const user = users.find((u) => u.id === req.userId);
  if (!user) return res.status(404).json({ error: "User nahi mila." });
  res.json({ id: user.id, name: user.name, email: user.email });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server chal raha hai: http://localhost:${PORT}`));