const http = require("node:http");
const crypto = require("node:crypto");
const fsSync = require("node:fs");
const fs = require("node:fs/promises");
const path = require("node:path");

loadEnvFile(path.join(__dirname, ".env"));

const PORT = Number(process.env.PORT || 3000);
const PUBLIC_DIR = __dirname;
const DISCORD_API = "https://discord.com/api/v10";

const config = {
  clientId: process.env.DISCORD_CLIENT_ID,
  clientSecret: process.env.DISCORD_CLIENT_SECRET,
  botToken: process.env.DISCORD_BOT_TOKEN,
  guildId: process.env.DISCORD_GUILD_ID,
  redirectUri: process.env.DISCORD_REDIRECT_URI || `http://127.0.0.1:${PORT}/auth/discord/callback`,
  staffManagerRoleId: process.env.STAFF_MANAGER_ROLE_ID,
  staffRoleIds: parseJsonEnv("STAFF_ROLE_IDS", []),
  staffRoleMap: parseJsonEnv("STAFF_ROLE_MAP", {}),
  responsibilityRoleIds: parseJsonEnv("RESPONSIBILITY_ROLE_IDS", []),
  responsibilityRoleMap: parseJsonEnv("RESPONSIBILITY_ROLE_MAP", {})
};

const sessions = new Map();

function loadEnvFile(filePath) {
  if (!fsSync.existsSync(filePath)) return;

  const rows = fsSync.readFileSync(filePath, "utf8").split(/\r?\n/);
  for (const row of rows) {
    const trimmed = row.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    const separator = trimmed.indexOf("=");
    if (separator === -1) continue;

    const key = trimmed.slice(0, separator).trim();
    const value = trimmed.slice(separator + 1).trim().replace(/^["']|["']$/g, "");
    if (key && !process.env[key]) {
      process.env[key] = value;
    }
  }
}

function parseJsonEnv(name, fallback) {
  try {
    return process.env[name] ? JSON.parse(process.env[name]) : fallback;
  } catch {
    return fallback;
  }
}

function send(res, status, body, headers = {}) {
  res.writeHead(status, headers);
  res.end(body);
}

function json(res, status, body) {
  send(res, status, JSON.stringify(body), { "content-type": "application/json; charset=utf-8" });
}

function getCookie(req, name) {
  const cookies = req.headers.cookie?.split(";").map((cookie) => cookie.trim()) || [];
  const match = cookies.find((cookie) => cookie.startsWith(`${name}=`));
  return match ? decodeURIComponent(match.slice(name.length + 1)) : "";
}

function createSession(user) {
  const id = crypto.randomUUID();
  sessions.set(id, user);
  return id;
}

async function discordFetch(url, options = {}) {
  const response = await fetch(`${DISCORD_API}${url}`, options);
  if (!response.ok) {
    throw new Error(`Discord API ${response.status}: ${await response.text()}`);
  }
  return response.json();
}

async function exchangeCode(code) {
  const body = new URLSearchParams({
    client_id: config.clientId,
    client_secret: config.clientSecret,
    grant_type: "authorization_code",
    code,
    redirect_uri: config.redirectUri
  });

  const response = await fetch(`${DISCORD_API}/oauth2/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body
  });

  if (!response.ok) {
    throw new Error(`OAuth failed: ${await response.text()}`);
  }

  return response.json();
}

async function getDiscordUser(accessToken) {
  return discordFetch("/users/@me", {
    headers: { authorization: `Bearer ${accessToken}` }
  });
}

async function getGuildMember(userId) {
  return discordFetch(`/guilds/${config.guildId}/members/${userId}`, {
    headers: { authorization: `Bot ${config.botToken}` }
  });
}

function requireConfig(res) {
  const missing = Object.entries(config)
    .filter(([key, value]) => ![
      "responsibilityRoleIds",
      "responsibilityRoleMap",
      "staffRoleIds",
      "staffRoleMap"
    ].includes(key) && !value)
    .map(([key]) => key);

  if (missing.length) {
    json(res, 500, { error: "Missing Discord config", missing });
    return false;
  }

  return true;
}

async function handleDiscordLogin(req, res) {
  if (!requireConfig(res)) return;

  const state = crypto.randomUUID();
  const params = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    response_type: "code",
    scope: "identify",
    state
  });

  send(res, 302, "", {
    location: `https://discord.com/oauth2/authorize?${params}`,
    "set-cookie": `discord_oauth_state=${encodeURIComponent(state)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=600`
  });
}

async function handleDiscordCallback(req, res) {
  if (!requireConfig(res)) return;

  const url = new URL(req.url, `http://${req.headers.host}`);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const expectedState = getCookie(req, "discord_oauth_state");

  if (!code || !state || state !== expectedState) {
    json(res, 401, { error: "Invalid Discord OAuth state" });
    return;
  }

  const token = await exchangeCode(code);
  const user = await getDiscordUser(token.access_token);
  const member = await getGuildMember(user.id);
  const roles = member.roles || [];

  if (!roles.includes(config.staffManagerRoleId)) {
    json(res, 403, { error: "Du behöver Staff manager-rollen i Discord." });
    return;
  }

  const sessionId = createSession({
    id: user.id,
    username: user.global_name || user.username,
    roles
  });

  send(res, 302, "", {
    location: "/login.html",
    "set-cookie": `staff_session=${encodeURIComponent(sessionId)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=28800`
  });
}

async function handleMe(req, res) {
  const user = sessions.get(getCookie(req, "staff_session"));
  if (!user) {
    json(res, 401, { authenticated: false });
    return;
  }

  json(res, 200, {
    authenticated: true,
    user: {
      id: user.id,
      username: user.username,
      roles: ["Staff manager"]
    }
  });
}

async function handleLogout(req, res) {
  const sessionId = getCookie(req, "staff_session");
  if (sessionId) {
    sessions.delete(sessionId);
  }

  send(res, 302, "", {
    location: "/login.html",
    "set-cookie": "staff_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"
  });
}

async function handleStaff(req, res) {
  const user = sessions.get(getCookie(req, "staff_session"));
  if (!user) {
    json(res, 401, { error: "Not authenticated" });
    return;
  }

  const members = await discordFetch(`/guilds/${config.guildId}/members?limit=1000`, {
    headers: { authorization: `Bot ${config.botToken}` }
  });

  const staff = members
    .map((member) => {
      const roleId = member.roles.find((id) => config.staffRoleIds.includes(id));
      if (!roleId) return null;
      const responsibilityRoleId = member.roles.find((id) => config.responsibilityRoleIds.includes(id));

      return {
        username: member.user.global_name || member.user.username,
        role: config.staffRoleMap[roleId] || roleId,
        area: config.responsibilityRoleMap[responsibilityRoleId] || "Ej satt",
        status: "Aktiv",
        lastSeen: new Date().toLocaleDateString("sv-SE")
      };
    })
    .filter(Boolean);

  json(res, 200, { staff });
}

async function serveFile(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const fileName = url.pathname === "/" ? "login.html" : url.pathname.slice(1);
  const filePath = path.join(PUBLIC_DIR, fileName);
  const ext = path.extname(filePath).toLowerCase();
  const types = {
    ".html": "text/html; charset=utf-8",
    ".png": "image/png",
    ".js": "text/javascript; charset=utf-8"
  };

  try {
    const data = await fs.readFile(filePath);
    send(res, 200, data, { "content-type": types[ext] || "application/octet-stream" });
  } catch {
    send(res, 404, "Not found", { "content-type": "text/plain; charset=utf-8" });
  }
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);

    if (url.pathname === "/auth/discord") return handleDiscordLogin(req, res);
    if (url.pathname === "/auth/discord/callback") return handleDiscordCallback(req, res);
    if (url.pathname === "/auth/logout") return handleLogout(req, res);
    if (url.pathname === "/api/me") return handleMe(req, res);
    if (url.pathname === "/api/staff") return handleStaff(req, res);

    return serveFile(req, res);
  } catch (error) {
    json(res, 500, { error: error.message });
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Staff panel server running on port ${PORT}`);
});
