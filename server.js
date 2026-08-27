const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const path = require("path");
const cors = require("cors");

const app = express();
const USERS_FILE = path.join(__dirname, "users.json");
const JWT_SECRET = process.env.JWT_SECRET || "change-this-secret-later";

// ⚠️ Yahan apna email daalein — isi email wala account "Owner/Admin" banega.
// Railway ke dashboard mein OWNER_EMAIL environment variable set karke bhi change kar sakti hain.
const OWNER_EMAIL = (process.env.OWNER_EMAIL || "amreen@gmail.com").toLowerCase();

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

function isOwnerEmail(email) {
  return email.toLowerCase() === OWNER_EMAIL;
}

// Password kabhi frontend ko wapas nahi bhejna — sirf safe data
function toPublicUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    isOwner: isOwnerEmail(user.email),
    createdAt: user.createdAt || null,
    lastLoginAt: user.lastLoginAt || null,
    loginCount: user.loginCount || 0,
    totalActiveMinutes: user.totalActiveMinutes || 0,
  };
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

// Sirf owner hi admin routes use kar sake
function requireOwner(req, res, next) {
  const users = readUsers();
  const user = users.find((u) => u.id === req.userId);
  if (!user || !isOwnerEmail(user.email)) {
    return res.status(403).json({ error: "Sirf app owner hi ye dekh sakta hai." });
  }
  next();
}

// SIGNUP
app.post("/api/register", (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: "Sab fields zaroori hain." });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: "Password kam se kam 6 characters ka ho." });
  }

  const users = readUsers();
  const exists = users.find((u) => u.email.toLowerCase() === email.toLowerCase());
  if (exists) {
    return res.status(400).json({ error: "Ye email pehle se registered hai." });
  }

  const hashedPassword = bcrypt.hashSync(password, 10);
  const newUser = {
    id: Date.now().toString(),
    name,
    email,
    password: hashedPassword,
    createdAt: new Date().toISOString(),
    lastLoginAt: new Date().toISOString(),
    loginCount: 1,
    totalActiveMinutes: 0,
  };
  users.push(newUser);
  saveUsers(users);

  const token = jwt.sign({ userId: newUser.id }, JWT_SECRET, { expiresIn: "30d" });
  res.json({ success: true, token, user: toPublicUser(newUser) });
});

// LOGIN
app.post("/api/login", (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "Email aur password zaroori hain." });
  }
  const users = readUsers();

  const user = users.find((u) => u.email.toLowerCase() === email.toLowerCase());
  if (!user) {
    return res.status(401).json({ error: "Email ya password galat hai." });
  }

  const isMatch = bcrypt.compareSync(password, user.password);
  if (!isMatch) {
    return res.status(401).json({ error: "Email ya password galat hai." });
  }

  user.lastLoginAt = new Date().toISOString();
  user.loginCount = (user.loginCount || 0) + 1;
  saveUsers(users);

  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: "30d" });
  res.json({ success: true, token, user: toPublicUser(user) });
});

// CURRENT USER (auto-login check)
app.get("/api/me", requireAuth, (req, res) => {
  const users = readUsers();
  const user = users.find((u) => u.id === req.userId);
  if (!user) return res.status(404).json({ error: "User nahi mila." });
  res.json(toPublicUser(user));
});

// App har 1 min mein ping karti hai jab tak login hai — isi se "kitni der use hua" pata chalta hai
app.post("/api/heartbeat", requireAuth, (req, res) => {
  const users = readUsers();
  const user = users.find((u) => u.id === req.userId);
  if (!user) return res.status(404).json({ error: "User nahi mila." });

  user.totalActiveMinutes = (user.totalActiveMinutes || 0) + 1;
  saveUsers(users);
  res.json({ success: true });
});

// OWNER DASHBOARD: sab users ki list
app.get("/api/admin/users", requireAuth, requireOwner, (req, res) => {
  const users = readUsers();
  const list = users
    .map(toPublicUser)
    .sort((a, b) => new Date(b.lastLoginAt || 0) - new Date(a.lastLoginAt || 0));
  res.json({ users: list });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server chal raha hai: http://localhost:${PORT}`));