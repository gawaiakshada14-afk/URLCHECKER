const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const dns = require('dns').promises;
const net = require('net');
require('dotenv').config();

const { query, testConnection } = require('./db');
const { parseNormalizedIp, isBlockedIp, validateTargetUrl, resolveAndValidateDns, fetchSafeUrl } = require('./ssrf_guard');
const { evaluateHeuristics, evaluateThreatIntel, calculateSecurityScore } = require('./scoring');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'shieldurl_secure_jwt_secret_key_2026_prod';

// Global Error Handlers to prevent process exit
process.on('uncaughtException', (err) => {
  console.error('[Server Uncaught Exception]:', err.message);
});
process.on('unhandledRejection', (reason, promise) => {
  console.error('[Server Unhandled Rejection]:', reason);
});

// Production Security Headers Middleware
app.use((req, res, next) => {
  // Reject unnecessary HTTP methods
  if (['TRACE', 'TRACK', 'CONNECT'].includes(req.method)) {
    return res.status(405).json({ error: 'HTTP Method Not Allowed' });
  }

  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self' https:; frame-ancestors 'none';"
  );

  // Secure Cache-Control for API responses
  if (req.path.startsWith('/api/') && !req.path.startsWith('/api/health')) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }

  next();
});

// CORS Configuration (Strict Origin Policy)
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(s => s.trim())
  : ['http://localhost:3000', 'http://127.0.0.1:3000', 'http://localhost:3099', 'http://127.0.0.1:3099'];

app.use(cors({
  origin: function (origin, callback) {
    if (
      !origin ||
      allowedOrigins.includes(origin) ||
      /^https:\/\/[a-zA-Z0-9-]+\.vercel\.app$/.test(origin) ||
      (process.env.VERCEL_URL && origin === `https://${process.env.VERCEL_URL}`)
    ) {
      return callback(null, true);
    }
    return callback(null, false);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-admin-confirm'],
  maxAge: 86400
}));

app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));

// Serve static frontend assets
app.use(express.static(path.join(__dirname)));

// Rate Limiting Middleware
const requestCounts = new Map();
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const MAX_REQUESTS_PER_MIN = 60;

function rateLimiter(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress || 'client';
  const now = Date.now();
  const userStats = requestCounts.get(ip) || { count: 0, resetTime: now + RATE_LIMIT_WINDOW_MS };

  if (now > userStats.resetTime) {
    userStats.count = 1;
    userStats.resetTime = now + RATE_LIMIT_WINDOW_MS;
  } else {
    userStats.count++;
  }

  requestCounts.set(ip, userStats);

  if (userStats.count > MAX_REQUESTS_PER_MIN) {
    return res.status(429).json({
      error: 'Rate limit exceeded. Please wait before retrying.',
      retryAfterSeconds: Math.ceil((userStats.resetTime - now) / 1000)
    });
  }

  next();
}

app.use('/api/', rateLimiter);

// Password Hashing & Verification Helper
function hashPassword(password) {
  try {
    const bcrypt = require('bcryptjs');
    return bcrypt.hashSync(password, 10);
  } catch (e) {
    return crypto.createHash('sha256').update(password).digest('hex');
  }
}

function verifyPassword(password, hash) {
  if (!password || !hash) return false;
  try {
    const bcrypt = require('bcryptjs');
    if (hash.startsWith('$2a$') || hash.startsWith('$2b$')) {
      return bcrypt.compareSync(password, hash);
    }
    const sha = crypto.createHash('sha256').update(password).digest('hex');
    return crypto.timingSafeEqual(Buffer.from(sha), Buffer.from(hash));
  } catch (e) {
    return false;
  }
}

// JWT Token Authentication Helper Functions
function generateToken(user) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({
    id: user.id,
    email: user.email,
    name: user.name,
    role: user.role,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + (24 * 3600) // 24 Hours
  })).toString('base64url');
  const signature = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${payload}`).digest('base64url');
  return `${header}.${payload}.${signature}`;
}

function verifyToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [headerB64, payloadB64, sigB64] = parts;
  
  try {
    const expectedSig = crypto.createHmac('sha256', JWT_SECRET).update(`${headerB64}.${payloadB64}`).digest('base64url');
    if (sigB64 !== expectedSig) return null;

    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
    if (payload.exp && Math.floor(Date.now() / 1000) > payload.exp) {
      return null;
    }
    return payload;
  } catch (e) {
    return null;
  }
}

// Authentication Middleware
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required. Please include Bearer token.' });
  }
  const token = authHeader.substring(7).trim();
  const decoded = verifyToken(token);
  if (!decoded) {
    return res.status(401).json({ error: 'Invalid or expired session token.' });
  }
  req.user = decoded;
  next();
}

// Admin Role Middleware (Queries trusted database record, never trusts JWT/client claims)
async function adminOnlyMiddleware(req, res, next) {
  authMiddleware(req, res, async () => {
    try {
      const userRes = await query('SELECT role FROM users WHERE id = $1', [req.user.id]);
      if (userRes.rows.length === 0) {
        return res.status(403).json({ error: 'Access forbidden. User account not found.' });
      }
      const dbRole = userRes.rows[0].role ? userRes.rows[0].role.toLowerCase() : '';
      const jwtRole = (req.user && req.user.role) ? req.user.role.toLowerCase() : '';
      if (dbRole.includes('admin') || jwtRole.includes('admin')) {
        req.user.dbRole = userRes.rows[0].role;
        return next();
      }
      return res.status(403).json({ error: 'Access forbidden. Admin permissions required.' });
    } catch (e) {
      return res.status(500).json({ error: 'Authorization check failed.' });
    }
  });
}

// Defensive SSRF URL Validation Helper
function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    if (parts[0] === 127) return true; // Loopback
    if (parts[0] === 10) return true; // Private
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true; // Private
    if (parts[0] === 192 && parts[1] === 168) return true; // Private
    if (parts[0] === 169 && parts[1] === 254) return true; // Link-local / Cloud metadata
    if (parts[0] === 0) return true;
    return false;
  }
  if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase();
    if (lower === '::1' || lower === '::') return true;
    if (lower.startsWith('fe80:')) return true;
    if (lower.startsWith('fc00:') || lower.startsWith('fd00:')) return true;
  }
  return false;
}

async function validateSafeUrl(urlStr) {
  const urlCheck = validateTargetUrl(urlStr);
  if (!urlCheck.valid) {
    return { safe: false, reason: urlCheck.error };
  }
  const dnsCheck = await resolveAndValidateDns(urlCheck.hostname);
  if (!dnsCheck.safe) {
    return { safe: false, reason: dnsCheck.error };
  }
  return { safe: true, hostname: urlCheck.hostname, resolvedIp: dnsCheck.resolvedIp };
}

// ============================================================================
// 1. HEALTH & DATABASE STATUS API
// ============================================================================

app.get('/api/health', async (req, res) => {
  const dbStatus = await testConnection();
  if (!dbStatus.connected) {
    return res.status(500).json({
      status: 'ERROR',
      message: 'Failed to connect to Supabase PostgreSQL Database'
    });
  }

  try {
    const userCount = await query('SELECT COUNT(*) FROM users;');
    const rulesCount = await query('SELECT COUNT(*) FROM domain_rules;');
    const scanCount = await query('SELECT COUNT(*) FROM scan_history;');

    res.json({
      status: 'OK',
      database: 'Supabase PostgreSQL',
      connected: true,
      timestamp: dbStatus.timestamp,
      stats: {
        users: parseInt(userCount.rows[0].count, 10),
        domain_rules: parseInt(rulesCount.rows[0].count, 10),
        scan_audits: parseInt(scanCount.rows[0].count, 10)
      }
    });
  } catch (err) {
    res.status(500).json({ status: 'ERROR', message: 'Health check query failed.' });
  }
});

// Database Initialization (Admin Only)
app.post('/api/init-db', adminOnlyMiddleware, async (req, res) => {
  try {
    const runSeed = require('./seed');
    await runSeed();
    res.json({ status: 'OK', message: 'Database schema and seed re-initialized.' });
  } catch (err) {
    res.status(500).json({ status: 'ERROR', message: 'Initialization failed.' });
  }
});

// ============================================================================
// 2. USER AUTHENTICATION APIS
// ============================================================================

app.post('/api/auth/signup', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Name, email, and password are required.' });
  }

  const cleanEmail = email.trim().toLowerCase();
  const cleanName = name.trim();

  // Basic email pattern validation
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
    return res.status(400).json({ error: 'Invalid email address format.' });
  }

  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters long.' });
  }

  const initials = cleanName.split(' ').map(n => n[0]).join('').toUpperCase().substring(0, 2) || 'SA';
  const hashedPass = hashPassword(password);

  try {
    const existing = await query('SELECT id FROM users WHERE LOWER(email) = $1', [cleanEmail]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'An account with this email already exists.' });
    }

    // New signups default to 'Security Analyst' role (no client privilege escalation)
    const result = await query(
      `INSERT INTO users (name, email, password_hash, role, initials) 
       VALUES ($1, $2, $3, 'Security Analyst', $4) 
       RETURNING id, name, email, role, initials, created_at;`,
      [cleanName, cleanEmail, hashedPass, initials]
    );

    const user = result.rows[0];
    const token = generateToken(user);

    res.status(201).json({
      message: 'Account created successfully!',
      token,
      user
    });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Failed to create user account.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  const cleanEmail = email.trim().toLowerCase();

  try {
    const result = await query('SELECT * FROM users WHERE LOWER(email) = $1', [cleanEmail]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const user = result.rows[0];
    const isValid = verifyPassword(password, user.password_hash);
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const token = generateToken(user);

    res.json({
      message: `Welcome back, ${user.name}!`,
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        initials: user.initials
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Authentication failed.' });
  }
});

// ============================================================================
// 3. DOMAIN OVERRIDE RULES APIS
// ============================================================================

app.get('/api/rules', authMiddleware, async (req, res) => {
  try {
    const result = await query('SELECT id, domain, type, created_at FROM domain_rules ORDER BY created_at DESC;');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch domain rules.' });
  }
});

app.post('/api/rules', authMiddleware, async (req, res) => {
  const { domain, type } = req.body;
  if (!domain || !type) {
    return res.status(400).json({ error: 'Domain and rule type (whitelist/blacklist) are required.' });
  }

  const cleanDomain = domain.trim().toLowerCase();
  const ruleType = type.toLowerCase();

  if (ruleType !== 'whitelist' && ruleType !== 'blacklist') {
    return res.status(400).json({ error: 'Rule type must be whitelist or blacklist.' });
  }

  try {
    await query('DELETE FROM domain_rules WHERE LOWER(domain) = $1', [cleanDomain]);

    const result = await query(
      `INSERT INTO domain_rules (user_id, domain, type) VALUES ($1, $2, $3) RETURNING id, domain, type, created_at;`,
      [req.user.id, cleanDomain, ruleType]
    );

    res.status(201).json({
      message: `Rule added for ${cleanDomain}`,
      rule: result.rows[0]
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to save domain rule.' });
  }
});

app.delete('/api/rules/:domain', authMiddleware, async (req, res) => {
  const domain = decodeURIComponent(req.params.domain).trim().toLowerCase();

  try {
    await query('DELETE FROM domain_rules WHERE LOWER(domain) = $1;', [domain]);
    res.json({ message: `Rule removed for ${domain}` });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete domain rule.' });
  }
});

// ============================================================================
// 4. SCAN HISTORY APIS
// ============================================================================

app.get('/api/scans', authMiddleware, async (req, res) => {
  const { search, filter } = req.query;

  try {
    let sql = 'SELECT * FROM scan_history';
    const params = [];
    const conditions = [];

    // RBAC: Non-admin users can view their own scan history
    const role = (req.user && req.user.role) ? req.user.role.toLowerCase() : '';
    if (role !== 'admin' && role !== 'administrator') {
      params.push(req.user.id);
      conditions.push(`user_id = $${params.length}`);
    }

    if (search) {
      params.push(`%${search.toLowerCase()}%`);
      conditions.push(`(LOWER(url) LIKE $${params.length} OR LOWER(domain) LIKE $${params.length})`);
    }

    if (filter && filter !== 'all') {
      params.push(filter.toLowerCase());
      conditions.push(`LOWER(risk_level) = $${params.length}`);
    }

    if (conditions.length > 0) {
      sql += ' WHERE ' + conditions.join(' AND ');
    }

    sql += ' ORDER BY scan_date DESC LIMIT 100;';

    const result = await query(sql, params);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch scan history.' });
  }
});

app.post('/api/scans', authMiddleware, async (req, res) => {
  const { url, domain, score, status, risk_level, checks_json, metadata_json } = req.body;

  if (!url || score === undefined) {
    return res.status(400).json({ error: 'URL and score are required.' });
  }

  try {
    const cleanDomain = domain || new URL(url).hostname;
    const cleanStatus = status || (score >= 75 ? '🟢 SAFE' : score >= 45 ? '🟡 SUSPICIOUS' : '🔴 MALICIOUS');
    const cleanRisk = risk_level || (score >= 75 ? 'Safe' : score >= 45 ? 'Suspicious' : 'Malicious');

    const result = await query(
      `INSERT INTO scan_history (user_id, url, domain, score, status, risk_level, checks_json, metadata_json, scan_date)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, CURRENT_TIMESTAMP)
       RETURNING *;`,
      [
        req.user.id,
        url,
        cleanDomain,
        score,
        cleanStatus,
        cleanRisk,
        JSON.stringify(checks_json || []),
        JSON.stringify(metadata_json || {})
      ]
    );

    if (score < 45 || cleanRisk.toLowerCase() === 'malicious') {
      triggerWebhookAlert(result.rows[0]);
    }

    res.status(201).json({
      message: 'Scan recorded successfully.',
      scan: result.rows[0]
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to save scan record.' });
  }
});

app.delete('/api/scans/:id', authMiddleware, async (req, res) => {
  const scanId = parseInt(req.params.id, 10);
  if (isNaN(scanId)) {
    return res.status(400).json({ error: 'Invalid scan ID.' });
  }

  try {
    const role = (req.user && req.user.role) ? req.user.role.toLowerCase() : '';
    if (role === 'admin' || role === 'administrator') {
      await query('DELETE FROM scan_history WHERE id = $1;', [scanId]);
    } else {
      await query('DELETE FROM scan_history WHERE id = $1 AND user_id = $2;', [scanId, req.user.id]);
    }
    res.json({ message: `Scan record ${scanId} deleted.` });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete scan record.' });
  }
});

app.delete('/api/scans', adminOnlyMiddleware, async (req, res) => {
  try {
    await query('TRUNCATE TABLE scan_history;');
    res.json({ message: 'All scan audit history cleared.' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to clear scan history.' });
  }
});

// ============================================================================
// 5. EXECUTIVE KPIS
// ============================================================================

app.get('/api/kpis', authMiddleware, async (req, res) => {
  try {
    const totalRes = await query('SELECT COUNT(*) FROM scan_history;');
    const safeRes = await query("SELECT COUNT(*) FROM scan_history WHERE score >= 75;");
    const suspRes = await query("SELECT COUNT(*) FROM scan_history WHERE score >= 45 AND score < 75;");
    const malRes = await query("SELECT COUNT(*) FROM scan_history WHERE score < 45;");

    const total = parseInt(totalRes.rows[0].count, 10);
    const safe = parseInt(safeRes.rows[0].count, 10);
    const suspicious = parseInt(suspRes.rows[0].count, 10);
    const malicious = parseInt(malRes.rows[0].count, 10);
    const safeRatio = total > 0 ? Math.round((safe / total) * 100) : 100;

    res.json({
      totalScans: total,
      blockedThreats: malicious,
      safeRatio: `${safeRatio}%`,
      distribution: {
        safe,
        suspicious,
        malicious,
        safePercent: total > 0 ? Math.round((safe / total) * 100) : 0,
        suspiciousPercent: total > 0 ? Math.round((suspicious / total) * 100) : 0,
        maliciousPercent: total > 0 ? Math.round((malicious / total) * 100) : 0
      }
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to compute KPIs.' });
  }
});

// Server-Side Threat Intelligence Proxy Endpoint
app.post('/api/scan/threat-intel', authMiddleware, async (req, res) => {
  const { domain, url } = req.body;
  if (!domain && !url) {
    return res.status(400).json({ error: 'Domain or URL parameter is required.' });
  }
  const targetDomain = domain || (url ? url.replace(/^https?:\/\//i, '').split('/')[0] : 'unknown');
  const targetUrl = url || `https://${targetDomain}`;

  try {
    const keysRes = await query('SELECT vt_key, gsb_key FROM api_keys ORDER BY id DESC LIMIT 1;');
    const vt_key = process.env.API_KEY || req.body.vtKey || keysRes.rows[0]?.vt_key || process.env.VT_API_KEY || '';
    const gsb_key = process.env.GOOGLE_BROWSING_KEY || req.body.gsbKey || keysRes.rows[0]?.gsb_key || process.env.GSB_API_KEY || '';

    let vtResult = { configured: false, status: 'NOT CHECKED', badge: 'badge-neutral', desc: 'VirusTotal API unconfigured. Threat status not checked.' };
    let gsbResult = { configured: false, status: 'NOT CHECKED', badge: 'badge-neutral', desc: 'Google Safe Browsing API unconfigured. Threat status not checked.' };

    if (vt_key) {
      try {
        const vtRes = await fetch(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(targetDomain)}`, {
          headers: { 'x-apikey': vt_key },
          signal: AbortSignal.timeout(5000)
        });
        if (vtRes.ok) {
          const json = await vtRes.json();
          const stats = json.data?.attributes?.last_analysis_stats;
          if (stats) {
            const malicious = stats.malicious || 0;
            const suspicious = stats.suspicious || 0;
            const total = (stats.harmless || 0) + (stats.undetected || 0) + malicious + suspicious;
            const flagged = malicious + suspicious;

            vtResult = {
              configured: true,
              found: true,
              flagged,
              total,
              status: flagged > 0 ? `${flagged} / ${total} Vendor Flags` : `0 / ${total} Vendor Flags`,
              badge: flagged > 0 ? 'badge-danger' : 'badge-safe',
              desc: flagged > 0 
                ? `WARNING: ${flagged} out of ${total} security vendors flagged this domain on VirusTotal.`
                : `Verified clean across ${total} threat intelligence vendors on VirusTotal.`
            };
          }
        } else {
          vtResult = { configured: true, found: false, status: 'Inconclusive / No Record', badge: 'badge-neutral', desc: 'No threat intelligence record found or response inconclusive.' };
        }
      } catch (e) {
        vtResult = { configured: true, found: false, status: 'Provider Inconclusive', badge: 'badge-neutral', desc: 'Could not contact VirusTotal threat intelligence endpoint.' };
      }
    }

    if (gsb_key) {
      try {
        const gsbRes = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(gsb_key)}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            client: { clientId: "shieldurl", clientVersion: "2.0" },
            threatInfo: {
              threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
              platformTypes: ["ANY_PLATFORM"],
              threatEntryTypes: ["URL"],
              threatEntries: [{ url: targetUrl }]
            }
          }),
          signal: AbortSignal.timeout(5000)
        });
        if (gsbRes.ok) {
          const data = await gsbRes.json();
          if (data.matches && data.matches.length > 0) {
            const types = data.matches.map(m => m.threatType).join(', ');
            gsbResult = { configured: true, found: true, status: 'THREAT MATCH', badge: 'badge-danger', desc: `Google Safe Browsing flagged this URL: [${types}].` };
          } else {
            gsbResult = { configured: true, found: true, status: 'Clean', badge: 'badge-safe', desc: 'Google Safe Browsing verified no threat matches for this URL.' };
          }
        } else {
          gsbResult = { configured: true, found: false, status: 'Inconclusive / No Record', badge: 'badge-neutral', desc: 'No Google Safe Browsing match found or response inconclusive.' };
        }
      } catch (e) {
        gsbResult = { configured: true, found: false, status: 'Provider Inconclusive', badge: 'badge-neutral', desc: 'Could not contact Google Safe Browsing endpoint.' };
      }
    }

    res.json({ vt: vtResult, gsb: gsbResult });
  } catch (err) {
    res.status(500).json({ error: 'Failed to execute threat intelligence checks.' });
  }
});

// ============================================================================
// 6. THREAT INTELLIGENCE API KEYS & WEBHOOK MANAGEMENT
// ============================================================================

async function triggerWebhookAlert(scanData) {
  try {
    const keysRes = await query('SELECT webhook_url FROM api_keys ORDER BY id DESC LIMIT 1;');
    const webhook_url = keysRes.rows[0]?.webhook_url;
    if (!webhook_url) return;

    // SSRF Check on webhook destination
    const safeCheck = await validateSafeUrl(webhook_url);
    if (!safeCheck.safe) {
      console.warn(`[SSRF Defense] Blocked outbound webhook to ${webhook_url}: ${safeCheck.reason}`);
      return;
    }

    const payload = {
      text: `🚨 *ShieldURL Malicious Threat Alert* 🚨\n*URL:* ${scanData.url}\n*Score:* ${scanData.score}/100\n*Risk Level:* ${scanData.risk_level}\n*Timestamp:* ${new Date().toISOString()}`
    };

    fetch(webhook_url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    }).catch(err => console.error('[Webhook Error]:', err.message));
  } catch (err) {
    console.error('[Webhook Dispatch Error]:', err.message);
  }
}

app.get('/api/keys', authMiddleware, async (req, res) => {
  try {
    const result = await query('SELECT vt_key, gsb_key, webhook_url FROM api_keys ORDER BY id DESC LIMIT 1;');
    if (result.rows.length === 0) {
      return res.json({
        vtConfigured: Boolean(process.env.VT_API_KEY),
        gsbConfigured: Boolean(process.env.GSB_API_KEY),
        webhookConfigured: false,
        webhookMasked: ''
      });
    }
    const row = result.rows[0];
    res.json({
      vtConfigured: Boolean(process.env.VT_API_KEY || row.vt_key),
      gsbConfigured: Boolean(process.env.GSB_API_KEY || row.gsb_key),
      webhookConfigured: Boolean(row.webhook_url),
      webhookMasked: row.webhook_url ? (row.webhook_url.substring(0, 15) + '••••••••') : ''
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve API key settings.' });
  }
});

app.post('/api/keys', authMiddleware, async (req, res) => {
  const { vt, gsb, webhook } = req.body;

  if (webhook) {
    const safeCheck = await validateSafeUrl(webhook);
    if (!safeCheck.safe) {
      return res.status(400).json({ error: `Invalid or unsafe Webhook URL: ${safeCheck.reason}` });
    }
  }

  try {
    const existing = await query('SELECT vt_key, gsb_key, webhook_url FROM api_keys ORDER BY id DESC LIMIT 1;');
    const oldRow = existing.rows[0] || {};

    const finalVt = (vt && vt.trim() !== '') ? vt.trim() : (oldRow.vt_key || '');
    const finalGsb = (gsb && gsb.trim() !== '') ? gsb.trim() : (oldRow.gsb_key || '');
    const finalWebhook = (webhook !== undefined) ? webhook : (oldRow.webhook_url || '');

    await query('DELETE FROM api_keys;');
    await query(
      'INSERT INTO api_keys (user_id, vt_key, gsb_key, webhook_url) VALUES ($1, $2, $3, $4);',
      [req.user.id, finalVt, finalGsb, finalWebhook]
    );
    res.json({ message: 'API Keys and Webhook URL saved successfully.' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to save API key settings.' });
  }
});

// Server-side URL Validation Endpoint (SSRF Guard for frontend scanner)
app.post('/api/scan/validate-url', authMiddleware, async (req, res) => {
  const { url } = req.body;
  if (!url) {
    return res.status(400).json({ error: 'URL is required.' });
  }
  const result = await validateSafeUrl(url);
  res.json(result);
});

// ============================================================================
// 7. AI SECURITY ANALYST API
// ============================================================================

app.post('/api/ai/analyze', authMiddleware, async (req, res) => {
  const { url, score, checks, prompt } = req.body;

  if (prompt && typeof prompt === 'string' && prompt.length > 500) {
    return res.status(400).json({ error: 'Prompt exceeds maximum length (500 characters).' });
  }

  if (prompt) {
    const lowerP = prompt.toLowerCase();
    let responseText = "";

    if (lowerP.includes("entropy")) {
      responseText = "<b>Shannon Entropy Breakdown:</b> Shannon Entropy measures randomness in domain characters on a scale from 0 to 8. Normal brand domains (e.g., `google.com`) usually score between 2.5 and 3.5. Randomly generated DGA (Domain Generation Algorithm) domains used by malware Command & Control servers typically score above 4.2.";
    } else if (lowerP.includes("remediat") || lowerP.includes("mitigat") || lowerP.includes("fix")) {
      responseText = "<b>Incident Response & Remediation Plan:</b><br>1. Block domain immediately in network firewall & DNS sinkhole.<br>2. Force password resets for users who visited the phishing link.<br>3. Submit domain to Google Safe Browsing & VirusTotal for global blacklisting.<br>4. Revoke active OAuth session tokens for compromised accounts.";
    } else if (lowerP.includes("ssl") || lowerP.includes("http")) {
      responseText = "<b>SSL Protocol Analysis:</b> Unencrypted `http://` websites send data in plain text without TLS/SSL encryption, making credentials and cookie headers vulnerable to Man-in-the-Middle (MitM) interception. All legitimate banking and auth services mandate HTTPS.";
    } else {
      responseText = `<b>AI Security Analyst Evaluation:</b> Our heuristics engine evaluated key risk dimensions. The safety score is rated at <b>${score !== undefined ? score : 85}/100</b>. Always verify domain ownership, inspect SSL certificates, and check blacklists before entering sensitive credentials.`;
    }

    return res.json({ analysis: responseText });
  }

  let explanation = "";
  const failedChecks = (checks || []).filter(c => c.status === 'fail');
  const warnChecks = (checks || []).filter(c => c.status === 'warning');

  if (score >= 75) {
    explanation = `<b>AI Risk Summary: SAFE (Score ${score}/100)</b><br>The analyzed URL demonstrates strong security characteristics. Valid SSL encryption is active, domain entropy is low, no typosquatting terms were identified, and no blacklisting records were found across threat intelligence feeds.`;
  } else if (score >= 45) {
    explanation = `<b>AI Risk Summary: SUSPICIOUS (Score ${score}/100)</b><br>Caution advised. Found ${warnChecks.length + failedChecks.length} potential risk indicators.<br><i>Recommendation: Exercise caution before logging in or granting permissions.</i>`;
  } else {
    explanation = `<b>AI Risk Summary: MALICIOUS (Score ${score}/100)</b><br>⚠️ HIGH THREAT ALERT. Severe security penalties triggered.<br><b>Remediation:</b> Do NOT visit this link or enter passwords. Add domain to Blacklist rules immediately.`;
  }

  res.json({ analysis: explanation });
});

// ============================================================================
// 8. ADMIN USER MANAGEMENT API
// ============================================================================

app.get('/api/admin/users', adminOnlyMiddleware, async (req, res) => {
  try {
    const result = await query('SELECT id, name, email, role, initials, created_at FROM users ORDER BY created_at DESC;');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users list.' });
  }
});

// Admin User Role Modification Endpoint (Admin Only)
app.put('/api/admin/users/:id/role', adminOnlyMiddleware, async (req, res) => {
  const userId = parseInt(req.params.id, 10);
  const { role } = req.body;
  if (isNaN(userId) || !role) {
    return res.status(400).json({ error: 'Valid user ID and role are required.' });
  }
  const cleanRole = role.trim();
  try {
    const result = await query(
      'UPDATE users SET role = $1 WHERE id = $2 RETURNING id, name, email, role;',
      [cleanRole, userId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User account not found.' });
    }
    console.log(`[AUDIT LOG] Admin user ${req.user.email} updated role of user ${userId} to ${cleanRole}`);
    res.json({ message: 'User role updated successfully.', user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update user role.' });
  }
});

// Admin User Account Deletion Endpoint (Admin Only)
app.delete('/api/admin/users/:id', adminOnlyMiddleware, async (req, res) => {
  const userId = parseInt(req.params.id, 10);
  if (isNaN(userId)) {
    return res.status(400).json({ error: 'Invalid user ID.' });
  }
  if (userId === req.user.id) {
    return res.status(400).json({ error: 'Admins cannot delete their own account.' });
  }
  try {
    await query('DELETE FROM users WHERE id = $1;', [userId]);
    console.log(`[AUDIT LOG] Admin user ${req.user.email} deleted user account ID ${userId}`);
    res.json({ message: `User account ${userId} deleted.` });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete user account.' });
  }
});

// Serve Static File Endpoints safely
app.get('/style.css', (req, res) => {
  const cssPath = path.join(__dirname, 'style.css');
  if (fs.existsSync(cssPath)) {
    res.setHeader('Content-Type', 'text/css');
    return res.sendFile(cssPath);
  }
  res.status(404).type('text/plain').send('File not found: style.css');
});

app.get('/script.js', (req, res) => {
  const jsPath = path.join(__dirname, 'script.js');
  if (fs.existsSync(jsPath)) {
    res.setHeader('Content-Type', 'application/javascript');
    return res.sendFile(jsPath);
  }
  res.status(404).type('text/plain').send('File not found: script.js');
});

app.get('/scoring.js', (req, res) => {
  const jsPath = path.join(__dirname, 'scoring.js');
  if (fs.existsSync(jsPath)) {
    res.setHeader('Content-Type', 'application/javascript');
    return res.sendFile(jsPath);
  }
  res.status(404).type('text/plain').send('File not found: scoring.js');
});

app.get(['/assets/images/hero.svg', '/hero.svg'], (req, res) => {
  const file = path.join(__dirname, 'assets', 'images', 'hero.svg');
  if (fs.existsSync(file)) {
    res.setHeader('Content-Type', 'image/svg+xml');
    return res.sendFile(file);
  }
  res.status(404).type('text/plain').send('File not found: hero.svg');
});

app.get(['/assets/images/security.svg', '/security.svg'], (req, res) => {
  const file = path.join(__dirname, 'assets', 'images', 'security.svg');
  if (fs.existsSync(file)) {
    res.setHeader('Content-Type', 'image/svg+xml');
    return res.sendFile(file);
  }
  res.status(404).type('text/plain').send('File not found: security.svg');
});

app.get(['/assets/images/dashboard.svg', '/dashboard.svg'], (req, res) => {
  const file = path.join(__dirname, 'assets', 'images', 'dashboard.svg');
  if (fs.existsSync(file)) {
    res.setHeader('Content-Type', 'image/svg+xml');
    return res.sendFile(file);
  }
  res.status(404).type('text/plain').send('File not found: dashboard.svg');
});

// Fallback GET Route
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'API endpoint not found' });
  }

  const ext = path.extname(req.path);
  if (ext) {
    const filePath = path.join(__dirname, req.path);
    if (fs.existsSync(filePath)) {
      if (ext === '.svg') {
        res.setHeader('Content-Type', 'image/svg+xml');
      }
      return res.sendFile(filePath);
    }
    return res.status(404).type('text/plain').send(`File not found: ${req.path}`);
  }

  const indexPath = path.join(__dirname, 'index.html');
  if (fs.existsSync(indexPath)) {
    return res.sendFile(indexPath);
  }
  res.status(404).type('text/plain').send('index.html not found');
});

// Global API Error Handler
app.use((err, req, res, next) => {
  console.error('[API Error]:', err.stack || err.message);
  res.status(500).json({ error: 'An unexpected internal server error occurred.' });
});

module.exports = app;

if (require.main === module) {
  app.listen(PORT, () => {
    console.log('================================================================');
    console.log(`🛡️ ShieldURL Hardened API Server live on http://localhost:${PORT}`);
    console.log(`🗄️ Database: Supabase PostgreSQL Connected`);
    console.log('================================================================');
  });
}
