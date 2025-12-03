/**
 * Authelia UserAdmin (app.mjs)
 *
 * Features:
 * - Read/write Authelia users.yml (path /config/users.yml)
 * - Create / delete / update users
 * - Change password endpoint
 * - Invite workflow (magic link) with optional SMTP sending
 * - Admin protection (middleware reads forwarded groups/header from Traefik+Authelia)
 * - Logging to file (/config/useradmin.log) and console via winston
 *
 * Notes:
 * - Mount your authelia /config directory into the container (so users.yml is visible)
 * - Provide SMTP settings via ENV if you want email invitations
 * - Traefik should forward Authelia headers (Remote-Groups/Remote-User or X-Forwarded-User etc.)
 */

import express from "express";
import fs from "fs";
import { dirname, resolve } from "path";
import yaml from "js-yaml";
import bodyParser from "body-parser";
import argon2 from "argon2";
import nodemailer from "nodemailer";
import { v4 as uuidv4 } from "uuid";
import winston from "winston";
import { execSync } from "child_process";

const app = express();
app.use(bodyParser.json());
app.use(express.static("public"));

// Configurable paths (mount /config for production)
const CONFIG_DIR = process.env.CONFIG_DIR || "/config";
const USERS_FILE = process.env.USERS_FILE || resolve(CONFIG_DIR, "users.yml");
const INVITES_FILE = process.env.INVITES_FILE || resolve(CONFIG_DIR, "useradmin-invites.json");
const LOG_FILE = process.env.LOG_FILE || resolve(CONFIG_DIR, "useradmin.log");

// Ensure config dir exists
try {
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
} catch (e) {
  // ignore
}

// Winston logger
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ timestamp, level, message }) => `${timestamp} ${level}: ${message}`)
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: LOG_FILE })
  ]
});

// Helper: load users.yml (returns object of users)
function loadUsers() {
  if (!fs.existsSync(USERS_FILE)) {
    logger.warn(`users file missing: ${USERS_FILE}, creating empty skeleton`);
    const data = yaml.dump({ users: {} });
    fs.writeFileSync(USERS_FILE, data, "utf8");
  }
  const txt = fs.readFileSync(USERS_FILE, "utf8");
  const parsed = yaml.load(txt) || {};
  return parsed.users || {};
}

// Helper: save users object
function saveUsers(usersObj) {
  const data = yaml.dump({ users: usersObj }, { lineWidth: 1000 });
  fs.writeFileSync(USERS_FILE, data, "utf8");
  logger.info("users.yml saved");
}

// Invites storage helpers
function loadInvites() {
  if (!fs.existsSync(INVITES_FILE)) return {};
  try {
    const t = fs.readFileSync(INVITES_FILE, "utf8");
    return JSON.parse(t || "{}");
  } catch (e) {
    logger.error("Failed to parse invites file, resetting: " + e.message);
    return {};
  }
}
function saveInvites(invites) {
  fs.writeFileSync(INVITES_FILE, JSON.stringify(invites, null, 2), "utf8");
}

// // Hash generation using argon2 (PHC format compatible with Authelia)
// async function generateHash(password) {
//   // parameters similar to Authelia defaults
//   const hash = await argon2.hash(password, {
//     type: argon2.argon2id,
//     timeCost: 3,
//     memoryCost: 65536,
//     parallelism: 4
//   });
//   return hash; // returns $argon2id$v=...$...$...
// }

async function generateHash(password) {
  try {
    const hash = execSync(
      `authelia crypto hash generate --password "${password}"`,
      { encoding: "utf8" }
    ).trim();

    // Authelia gibt sowas aus:
    // Digest: $argon2id$v=19$m=65536,t=3,p=2$....
    // wir brauchen NUR den Teil nach "Digest: "
    if (hash.includes("Digest:")) {
      return hash.split("Digest:")[1].trim();
    }

    return hash;
  } catch (e) {
    console.error("Hash error:", e);
    throw new Error("Password hash generation failed");
  }
}


// Admin-check middleware
function getGroupsFromHeaders(req) {
  // try a list of common headers Traefik+Authelia or other providers may forward.
  const candidates = [
    "x-forwarded-groups",
    "remote-groups",
    "x-authentik-groups",
    "x-authelia-groups",
    "x-forwarded-user", // sometimes groups are encoded elsewhere - keep for future
    "x-remote-groups"
  ];
  for (const h of candidates) {
    const val = req.header(h);
    if (val) return val;
  }
  return null;
}

function checkAdmin(req, res, next) {
  const groupsRaw = getGroupsFromHeaders(req);
  if (!groupsRaw) {
    logger.warn(`Admin check failed: no groups header for request from ${req.ip}`);
    return res.status(403).json({ error: "forbidden (no groups)" });
  }
  const groups = groupsRaw.split(/[,\s]+/).map(g => g.trim()).filter(Boolean);
  if (!groups.includes("admins")) {
    logger.warn(`Admin check failed: user not in admins: groups=${groups.join(",")}`);
    return res.status(403).json({ error: "forbidden (not admin)" });
  }
  next();
}

// SMTP transporter (optional)
let transporter = null;
const SMTP_CONFIGURED = !!process.env.SMTP_HOST && !!process.env.SMTP_PORT;
if (SMTP_CONFIGURED) {
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT, 10),
    secure: (process.env.SMTP_SECURE === "true"), // true for 465, false for other ports
    auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined
  });
  transporter.verify().then(() => {
    logger.info("SMTP transporter ready");
  }).catch(err => {
    logger.warn("SMTP verify failed: " + err.message);
  });
} else {
  logger.info("SMTP not configured - invites will be returned but not emailed");
}

// ---------- API: read users (passwords removed for safety) ----------
app.get("/api/users", checkAdmin, (req, res) => {
  try {
    const users = loadUsers();
    const safe = {};
    for (const [k, v] of Object.entries(users)) {
      safe[k] = { ...v };
      if (safe[k].password) delete safe[k].password; // do not leak password hashes
    }
    res.json(safe);
  } catch (e) {
    logger.error("GET /api/users error: " + e.message);
    res.status(500).json({ error: e.message });
  }
});

// ---------- API: create user ----------
app.post("/api/users", checkAdmin, async (req, res) => {
  try {
    const { username, email, groups, password, displayname } = req.body;
    if (!username) return res.status(400).json({ error: "username fehlt" });
    if (!password) return res.status(400).json({ error: "password fehlt" });

    const users = loadUsers();
    if (users[username]) return res.status(400).json({ error: "User exists" });

    const hash = await generateHash(password);

    users[username] = {
      displayname: displayname || username,
      email,
      password: hash,
      groups: Array.isArray(groups) ? groups : (groups ? [groups] : ["users"])
    };

    saveUsers(users);
    logger.info(`User "${username}" created by admin`);
    res.json({ ok: true });
  } catch (e) {
    console.error("POST /api/users error:", e); // explicit console log as requested
    logger.error("POST /api/users error: " + e.message);
    res.status(500).json({ error: e.message });
  }
});

// ---------- API: update user (without password change) ----------
app.put("/api/users/:username", checkAdmin, (req, res) => {
  try {
    const username = req.params.username;
    const users = loadUsers();
    if (!users[username]) return res.status(404).json({ error: "User not found" });

    const { email, groups, displayname } = req.body;
    if (email !== undefined) users[username].email = email;
    if (displayname !== undefined) users[username].displayname = displayname;
    if (groups !== undefined) users[username].groups = Array.isArray(groups) ? groups : [groups];

    saveUsers(users);
    logger.info(`User "${username}" updated`);
    res.json({ ok: true });
  } catch (e) {
    logger.error("PUT /api/users/:username error: " + e.message);
    res.status(500).json({ error: e.message });
  }
});

// ---------- API: change password ----------
app.post("/api/users/:username/password", checkAdmin, async (req, res) => {
  try {
    const username = req.params.username;
    const { password } = req.body;
    if (!password) return res.status(400).json({ error: "password fehlt" });

    const users = loadUsers();
    if (!users[username]) return res.status(404).json({ error: "User not found" });

    users[username].password = await generateHash(password);
    saveUsers(users);
    logger.info(`Password changed for "${username}"`);
    res.json({ ok: true });
  } catch (e) {
    logger.error("POST /api/users/:username/password error: " + e.message);
    res.status(500).json({ error: e.message });
  }
});

// ---------- API: delete user ----------
app.delete("/api/users/:username", checkAdmin, (req, res) => {
  try {
    const users = loadUsers();
    const username = req.params.username;
    if (!users[username]) return res.status(404).json({ error: "User not found" });

    delete users[username];
    saveUsers(users);
    logger.info(`User "${username}" deleted`);
    res.json({ ok: true });
  } catch (e) {
    logger.error("DELETE /api/users/:username error: " + e.message);
    res.status(500).json({ error: e.message });
  }
});

// ---------- Invite creation (magic link) ----------
app.post("/api/invite", checkAdmin, (req, res) => {
  try {
    const { email, groups, displayname, expiresMinutes = 60 } = req.body;
    if (!email) return res.status(400).json({ error: "email fehlt" });

    const token = uuidv4();
    const invites = loadInvites();

    invites[token] = {
      email,
      groups: Array.isArray(groups) ? groups : (groups ? [groups] : ["users"]),
      displayname: displayname || "",
      createdAt: Date.now(),
      expiresAt: Date.now() + expiresMinutes * 60 * 1000
    };

    saveInvites(invites);

    const base = process.env.BASE_URL || ""; // e.g. https://authelia.home.smallfamilybusiness.net
    const link = `${base}/admin/invite/accept.html?token=${token}`;

    // send mail if configured
    if (transporter) {
      const from = process.env.SMTP_FROM || `Authelia <${process.env.SMTP_USER || "authelia@example.com"}>`;
      transporter.sendMail({
        from,
        to: email,
        subject: "Invite to SmallFamilyBusiness.net Authelia",
        text: `You were invited. Open the link to register: ${link}`,
        html: `<p>You were invited. Open the link to register:</p><p><a href="${link}">${link}</a></p>`
      }).then(() => {
        logger.info(`Invite mail sent to ${email}`);
      }).catch(err => {
        logger.warn(`Failed to send invite mail: ${err.message}`);
      });
    } else {
      logger.info(`Invite created for ${email} (no SMTP configured). Link: ${link}`);
    }

    res.json({ ok: true, token, link });
  } catch (e) {
    logger.error("POST /api/invite error: " + e.message);
    res.status(500).json({ error: e.message });
  }
});

// ---------- Accept invite (create user using token) ----------
app.post("/api/invite/accept", async (req, res) => {
  try {
    const { token, username, password } = req.body;
    if (!token || !username || !password) return res.status(400).json({ error: "token/username/password required" });

    const invites = loadInvites();
    const invite = invites[token];
    if (!invite) return res.status(400).json({ error: "invalid token" });
    if (Date.now() > invite.expiresAt) {
      delete invites[token];
      saveInvites(invites);
      return res.status(400).json({ error: "token expired" });
    }

    const users = loadUsers();
    if (users[username]) return res.status(400).json({ error: "username exists" });

    const hash = await generateHash(password);
    users[username] = {
      displayname: invite.displayname || username,
      email: invite.email,
      password: hash,
      groups: invite.groups
    };
    saveUsers(users);

    // remove invite
    delete invites[token];
    saveInvites(invites);

    logger.info(`Invite accepted -> created user ${username}`);
    res.json({ ok: true });
  } catch (e) {
    logger.error("POST /api/invite/accept error: " + e.message);
    res.status(500).json({ error: e.message });
  }
});

// ---------- Simple health and logging endpoints ----------
app.get("/health", (req, res) => res.json({ ok: true }));

app.get("/api/logfile", checkAdmin, (req, res) => {
  try {
    if (!fs.existsSync(LOG_FILE)) return res.status(404).json({ error: "no logfile" });
    res.sendFile(LOG_FILE);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------- Serve admin UI (index) ----------
app.get("/", (req, res) => {
  res.sendFile(resolve("public", "admin.html"));
});
app.get("/invite/accept.html", (req, res) => {
  res.sendFile(resolve("public", "invite-accept.html"));
});

// start
const PORT = parseInt(process.env.PORT || "3000", 10);
app.listen(PORT, () => {
  logger.info(`UserAdmin läuft auf Port ${PORT}`);
});

app.get("/ping", (req, res) => {
  res.send("pong");
});

app.get("/api/debug/headers", (req, res) => {
  res.json(req.headers);
});

app.get("/api/test", (req, res) => {
  res.json({
    ok: true,
    message: "UserAdmin API reached!",
    path: req.path,
    prefix: req.header("X-Forwarded-Prefix") || null,
    groups: req.header("Remote-Groups") || null,
    user: req.header("Remote-User") || null
  });
});
