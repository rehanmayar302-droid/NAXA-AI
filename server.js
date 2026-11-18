import "dotenv/config";
import express from "express";
import multer from "multer";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import Database from "better-sqlite3";
import OpenAI from "openai";
import pdfParse from "pdf-parse";
import mammoth from "mammoth";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const port = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_ME";
const db = new Database(path.join(__dirname, "my-ai.db"));
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS chats (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  title TEXT NOT NULL DEFAULT 'New chat',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  chat_id INTEGER NOT NULL,
  role TEXT NOT NULL,
  content TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(chat_id) REFERENCES chats(id) ON DELETE CASCADE
);
`);

const openai = new OpenAI({
  apiKey: process.env.GEMINI_API_KEY,
  baseURL: "https://generativelanguage.googleapis.com/v1beta/openai/",
  timeout: 60000,
});
function seedAdmin() {}
  const email = String(process.env.ADMIN_EMAIL || "admin@example.com").toLowerCase();
  const existing = db.prepare("SELECT id FROM users WHERE email=?").get(email);
  if (!existing) {
    const hash = bcrypt.hashSync(process.env.ADMIN_PASSWORD || "ChangeThisAdminPassword123!", 12);
    db.prepare("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)")
      .run("Administrator", email, hash, "admin");
    console.log("Admin account created:", email);
   }
seedAdmin();

app.use(express.json({ limit: "20mb" }));
app.use(express.static(path.join(__dirname, "public")));

function sign(user) {
  return jwt.sign({ id: user.id, role: user.role, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
}
function auth(req, res, next) {
  try {
    const token = (req.headers.authorization || "").replace("Bearer ", "");
    const data = jwt.verify(token, JWT_SECRET);
    req.user = db.prepare("SELECT id,name,email,role,created_at FROM users WHERE id=?").get(data.id);
    if (!req.user) throw new Error("User not found");
    next();
  } catch {
    res.status(401).json({ error: "Please log in again." });
  }
}
function admin(req, res, next) {
  if (req.user?.role !== "admin") return res.status(403).json({ error: "Admin only." });
  next();
}

app.post("/api/auth/signup", async (req,res) => {
  try {
    const name = String(req.body.name || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    if (name.length < 2 || !email.includes("@") || password.length < 8)
      return res.status(400).json({ error: "Use a name, valid email, and password of at least 8 characters." });
    if (db.prepare("SELECT id FROM users WHERE email=?").get(email))
      return res.status(409).json({ error: "Email is already registered." });
    const hash = await bcrypt.hash(password, 12);
    const result = db.prepare("INSERT INTO users(name,email,password_hash) VALUES(?,?,?)").run(name,email,hash);
    const user = db.prepare("SELECT id,name,email,role,created_at FROM users WHERE id=?").get(result.lastInsertRowid);
    res.json({ token: sign(user), user });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post("/api/auth/login", async (req,res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    const row = db.prepare("SELECT * FROM users WHERE email=?").get(email);
    if (!row || !(await bcrypt.compare(password,row.password_hash)))
      return res.status(401).json({ error: "Invalid email or password." });
    const user = { id:row.id,name:row.name,email:row.email,role:row.role,created_at:row.created_at };
    res.json({ token: sign(user), user });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.get("/api/me", auth, (req,res) => res.json({ user:req.user }));

app.get("/api/chats", auth, (req,res) => {
  const chats = db.prepare("SELECT id,title,created_at,updated_at FROM chats WHERE user_id=? ORDER BY updated_at DESC").all(req.user.id);
  res.json({ chats });
});
app.post("/api/chats", auth, (req,res) => {
  const title = String(req.body.title || "New chat").slice(0,80);
  const r = db.prepare("INSERT INTO chats(user_id,title) VALUES(?,?)").run(req.user.id,title);
  res.json({ chat: db.prepare("SELECT * FROM chats WHERE id=?").get(r.lastInsertRowid) });
});
app.get("/api/chats/:id/messages", auth, (req,res) => {
  const chat = db.prepare("SELECT * FROM chats WHERE id=? AND user_id=?").get(req.params.id,req.user.id);
  if (!chat) return res.status(404).json({error:"Chat not found."});
  res.json({ chat, messages:db.prepare("SELECT id,role,content,created_at FROM messages WHERE chat_id=? ORDER BY id").all(chat.id) });
});
app.delete("/api/chats/:id", auth, (req,res) => {
  db.prepare("DELETE FROM chats WHERE id=? AND user_id=?").run(req.params.id,req.user.id);
  res.json({ok:true});
});

async function extractFile(file) {
  const name = file.originalname.toLowerCase();
  if (name.endsWith(".pdf")) {
    const out = await pdfParse(file.buffer);
    return out.text.slice(0, 50000);
  }
  if (name.endsWith(".docx")) {
    const out = await mammoth.extractRawText({ buffer:file.buffer });
    return out.value.slice(0, 50000);
  }
  if (name.endsWith(".txt") || name.endsWith(".md") || name.endsWith(".csv")) {
    return file.buffer.toString("utf8").slice(0,50000);
  }
  throw new Error("Supported document types: PDF, DOCX, TXT, MD, CSV.");
}

app.post("/api/chat", auth, upload.array("files",5), async (req,res) => {
  try {
    const chatId = Number(req.body.chatId);
    const message = String(req.body.message || "").trim();
    const webSearch = req.body.webSearch === "true";
    if (!chatId || !message) return res.status(400).json({error:"Chat and message are required."});
    const chat = db.prepare("SELECT * FROM chats WHERE id=? AND user_id=?").get(chatId,req.user.id);
    if (!chat) return res.status(404).json({error:"Chat not found."});

    let extra = "";
    for (const file of (req.files || [])) {
      try { extra += `\n\n[Uploaded file: ${file.originalname}]\n${await extractFile(file)}`; }
      catch(e) { extra += `\n\n[Could not read ${file.originalname}: ${e.message}]`; }
    }

    db.prepare("INSERT INTO messages(chat_id,role,content) VALUES(?,?,?)").run(chatId,"user",message);
    const history = db.prepare("SELECT role,content FROM messages WHERE chat_id=? ORDER BY id DESC LIMIT 30").all(chatId).reverse();

    const input = history.map(m => ({ role:m.role, content:m.content }));
    if (extra) input[input.length-1].content += extra;
const response = await openai.chat.completions.create({
  model: process.env.GEMINI_MODEL || "gemini-1.5-flash",
  messages: [{ role: "system", content: "You are NAXA AI, a helpful general-purpose assistant. Be accurate, concise, and helpful." }, ...input],
});
const reply = response.choices?.[0]?.message?.content || "I could not generate a response.";
    db.prepare("INSERT INTO messages(chat_id,role,content) VALUES(?,?,?)").run(chatId,"assistant",reply);
    db.prepare("UPDATE chats SET updated_at=CURRENT_TIMESTAMP WHERE id=?").run(chatId);

    if (chat.title === "New chat") {
      const title = message.slice(0,60) || "New chat";
      db.prepare("UPDATE chats SET title=? WHERE id=?").run(title,chatId);
    }
    res.json({ reply });
  } catch(e) {
    console.error(e);
    res.status(500).json({error:e?.message || "AI request failed."});
  }
});

app.post("/api/image", auth, async (req,res) => {
  try {
    const prompt = String(req.body.prompt || "").trim();
    if (!prompt) return res.status(400).json({error:"Enter an image prompt."});
    const result = await openai.images.generate({
      model: process.env.IMAGE_MODEL || "gpt-image-2",
      prompt,
      size: "1024x1024"
    });
    const b64 = result.data?.[0]?.b64_json;
    if (!b64) throw new Error("No image was returned.");
    res.json({ image:`data:image/png;base64,${b64}` });
  } catch(e) {
    console.error(e);
    res.status(500).json({error:e?.message || "Image generation failed."});
  }
});

app.get("/api/admin/stats", auth, admin, (req,res) => {
  res.json({
    users: db.prepare("SELECT COUNT(*) c FROM users").get().c,
    chats: db.prepare("SELECT COUNT(*) c FROM chats").get().c,
    messages: db.prepare("SELECT COUNT(*) c FROM messages").get().c
  });
});
app.get("/api/admin/users", auth, admin, (req,res) => {
  res.json({users:db.prepare("SELECT id,name,email,role,created_at FROM users ORDER BY id DESC").all()});
});
app.delete("/api/admin/users/:id", auth, admin, (req,res) => {
  if (Number(req.params.id) === req.user.id) return res.status(400).json({error:"You cannot delete yourself."});
  db.prepare("DELETE FROM users WHERE id=?").run(req.params.id);
  res.json({ok:true});
});

app.get("*splat", (req,res) => res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(port,()=>console.log(`NAXA AI: http://localhost:${port}`));