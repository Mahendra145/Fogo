import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import pg from "pg";
import fetch from "node-fetch";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(express.static(path.join(process.cwd(), "Public")));

// === DB Setup ===
console.log("🔌 Connecting to NeonDB...");
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  // Recommended settings to prevent memory issues on free tiers
  max: 3,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 30000,
});

pool.on("error", (err, client) => {
  console.error("❌ Unexpected error on idle client:", err);
});

(async () => {
  try {
    const client = await pool.connect();
    console.log("✅ Connected to NeonDB");
    client.on("error", err => {
      console.error("❌ Client error during connection:", err);
    });
    client.release();
  } catch (err) {
    console.error("❌ NeonDB connection failed at startup:", err);
  }
})();

process.on("unhandledRejection", (reason, promise) => {
  console.error("❌ Unhandled Rejection:", reason);
});

process.on("uncaughtException", (err) => {
  console.error("❌ Uncaught Exception:", err);
});

// Middleware
app.use(express.json());
app.use((req, res, next) => {
  console.log(`➡️ Incoming ${req.method} ${req.url}`);
  res.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
  next();
});

// === AUTH ROUTES ===

app.get("/auth/login", (req, res) => {
  console.log("📡 /auth/login hit");

  const params = new URLSearchParams({
    response_type: "code",
    client_id: process.env.X_CLIENT_ID,
    redirect_uri: "https://fogo-1ubw.onrender.com/auth/x/callback", 
    scope: "tweet.read users.read follows.read like.read offline.access",
    state: "fogo123",
    code_challenge: "challenge",
    code_challenge_method: "plain"
  });

  const url = `https://twitter.com/i/oauth2/authorize?${params.toString()}`;
  console.log("🔀 Redirecting user to:", url);
  res.redirect(url);
});

app.get("/auth/x/callback", async (req, res) => {
  console.log("📡 /auth/x/callback hit");
  console.log("➡️ Query params:", req.query);

  const { code } = req.query;
  if (!code) {
    console.error("❌ No code provided by X");
    return res.status(400).send("Missing code");
  }

  try {
    console.log("🔑 Exchanging code for token...");

    const tokenRes = await fetch("https://api.twitter.com/2/oauth2/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": "Basic " + Buffer.from(
          process.env.X_CLIENT_ID + ":" + process.env.X_CLIENT_SECRET
        ).toString("base64")
      },
      body: new URLSearchParams({
        code,
        grant_type: "authorization_code",
        redirect_uri: "https://fogo-1ubw.onrender.com/auth/x/callback", 
        code_verifier: "challenge"
      }),
    });

    const tokenData = await tokenRes.json();
    console.log("📄 Token response:", tokenData);

    if (!tokenData.access_token) {
      console.error("❌ No access_token from X!");
      return res.status(400).json(tokenData);
    }

    console.log("👤 Fetching user info with token...");
    const meRes = await fetch("https://api.twitter.com/2/users/me", {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const meData = await meRes.json();
    console.log("📄 User info:", meData);

    if (!meData.data) {
      console.error("❌ Failed to fetch user info");
      return res.status(500).json(meData);
    }

    console.log("🗄️ Saving user into DB...");
    await pool.query(
      `INSERT INTO users (x_user_id, username, access_token, points)
       VALUES ($1, $2, $3, 0)
       ON CONFLICT (x_user_id)
       DO UPDATE SET username=$2, access_token=$3`,
      [meData.data.id, meData.data.username, tokenData.access_token]
    );

    console.log("✅ User saved:", meData.data.username);
    res.redirect(`/index.html?x_user_id=${meData.data.id}&username=${meData.data.username}`);
  } catch (err) {
    console.error("❌ OAuth callback error:", err);
    res.status(500).send("OAuth callback failed (see logs)");
  }
});

// === API ROUTES ===
app.get("/api/fogo/me", async (req, res) => {
  console.log("📡 /api/fogo/me query:", req.query);
  try {
    const dbRes = await pool.query("SELECT * FROM users WHERE x_user_id=$1", [req.query.x_user_id]);
    res.json({ user: dbRes.rows[0] || null });
  } catch (err) {
    console.error("❌ DB error in /me:", err);
    res.status(500).json({ error: "DB error" });
  }
});

app.get("/api/fogo/leaderboard", async (req, res) => {
  console.log("📡 /api/fogo/leaderboard called");
  try {
    const dbRes = await pool.query("SELECT username, points FROM users ORDER BY points DESC LIMIT 10");
    res.json(dbRes.rows);
  } catch (err) {
    console.error("❌ DB error leaderboard:", err);
    res.status(500).json({ error: "DB error" });
  }
});

// Admin routes - left unchanged as they are for internal use
app.get("/admin.html", (req, res) => {
  res.sendFile(path.join(__dirname, "Public", "admin.html"));
});
app.get("/api/admin/resolve-username", async (req, res) => { /* ... unchanged ... */ });
app.post("/api/admin/tasks", async (req, res) => { /* ... unchanged ... */ });
app.delete("/api/admin/tasks/:id", async (req, res) => { /* ... unchanged ... */ });

app.get("/api/fogo/tasks", async (req, res) => {
  const { x_user_id } = req.query;
  try {
    const dbRes = await pool.query("SELECT * FROM tasks ORDER BY id DESC");
    const tasks = dbRes.rows;

    if (!x_user_id) {
      return res.json(tasks.map(t => ({ ...t, claimed: false })));
    }

    const userRes = await pool.query(
      "SELECT task_id FROM user_tasks WHERE user_id = (SELECT id FROM users WHERE x_user_id=$1)",
      [x_user_id]
    );
    const claimedIds = userRes.rows.map(r => r.task_id);

    const result = tasks.map(t => ({ ...t, claimed: claimedIds.includes(t.id) }));
    res.json(result);
  } catch (err) {
    console.error("❌ DB error tasks:", err);
    res.status(500).json({ error: "DB error" });
  }
});

app.post("/api/fogo/claim", async (req, res) => {
  const { x_user_id, taskId } = req.body;
  if (!x_user_id || !taskId) return res.status(400).json({ error: "Missing x_user_id or taskId" });

  try {
    const userRes = await pool.query("SELECT * FROM users WHERE x_user_id=$1", [x_user_id]);
    const user = userRes.rows[0];
    if (!user) return res.status(404).json({ error: "User not found" });

    const token = user.access_token;

    const taskRes = await pool.query("SELECT * FROM tasks WHERE id=$1", [taskId]);
    const task = taskRes.rows[0];
    if (!task) return res.status(404).json({ error: "Task not found" });

    const claimedRes = await pool.query(
      "SELECT * FROM user_tasks WHERE user_id=$1 AND task_id=$2",
      [user.id, task.id]
    );
    if (claimedRes.rows.length > 0) {
      return res.status(400).json({ error: "Task already claimed" });
    }

    let verified = false;
    
    // FIX: Removed the duplicate verification logic block
    if (task.type === "link.task") { 
        verified = true; 
    } else if (task.type === "social.follow") { 
        const followRes = await fetch(`https://api.twitter.com/2/users/${x_user_id}/following`, { headers: { Authorization: `Bearer ${token}` } }); 
        const followData = await followRes.json(); 
        verified = followData.data?.some(u => String(u.id) === String(task.target_user_id)); 
    } else if (task.type === "social.like") { 
        const likeRes = await fetch(`https://api.twitter.com/2/users/${x_user_id}/liked_tweets`, { headers: { Authorization: `Bearer ${token}` } }); 
        const likeData = await likeRes.json(); 
        verified = likeData.data?.some(t => String(t.id) === String(task.tweet_id)); 
    } else if (task.type === "social.retweet") { 
        const rtRes = await fetch(`https://api.twitter.com/2/tweets/${task.tweet_id}/retweeted_by`, { headers: { Authorization: `Bearer ${token}` } }); 
        const rtData = await rtRes.json(); 
        verified = rtData.data?.some(u => String(u.id) === String(x_user_id)); 
    } else if (task.type === "social.reply") { 
        if (!user.username) { 
            return res.status(400).json({ error: "Username not stored" }); 
        } 
        const replyRes = await fetch(`https://api.twitter.com/2/tweets/search/recent?query=from:${user.username} conversation_id:${task.tweet_id}`, { headers: { Authorization: `Bearer ${token}` } }); 
        const replyData = await replyRes.json(); 
        verified = replyData.meta?.result_count > 0; 
    } else { 
        return res.status(400).json({ error: "Unknown task type" }); 
    }

    if (!verified) {
      return res.status(400).json({ error: "Verification failed. Complete the task on X first." });
    }

    await pool.query("INSERT INTO user_tasks(user_id, task_id) VALUES($1, $2)", [user.id, task.id]);

    const newPoints = (user.points || 0) + task.points;
    await pool.query("UPDATE users SET points=$1 WHERE id=$2", [newPoints, user.id]);

    res.json({ message: "Task claimed successfully!", points: newPoints });

  } catch (err) {
    console.error("❌ Claim error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// === FRONTEND FALLBACK (must be last) ===
app.get(/^(?!\/api|\/auth).*$/, (req, res) => {
  console.log("📄 Serving frontend for", req.url);
  res.sendFile(path.join(__dirname, "Public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});



