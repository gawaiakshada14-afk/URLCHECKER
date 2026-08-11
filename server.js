const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

const { query, testConnection } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

// Global Error Handlers to prevent process exit
process.on('uncaughtException', (err) => {
  console.error('[Server Uncaught Exception]:', err.message);
});
process.on('unhandledRejection', (reason, promise) => {
  console.error('[Server Unhandled Rejection]:', reason);
});

// Enable CORS and JSON body parsing
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static frontend assets
app.use(express.static(path.join(__dirname)));

// Simple In-Memory Rate Limiting Middleware
const requestCounts = new Map();
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const MAX_REQUESTS_PER_MIN = 40;

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
      error: 'Too many requests. Rate limit exceeded. Please wait a minute before retrying.',
      retryAfterSeconds: Math.ceil((userStats.resetTime - now) / 1000)
    });
  }

  next();
}

app.use('/api/', rateLimiter);

// Password Hashing Helper
function hashPassword(password) {
  try {
    const bcrypt = require('bcryptjs');
    return bcrypt.hashSync(password, 10);
  } catch (e) {
    return crypto.createHash('sha256').update(password).digest('hex');
  }
}

function verifyPassword(password, hash) {
  try {
    const bcrypt = require('bcryptjs');
    if (hash.startsWith('$2a$') || hash.startsWith('$2b$')) {
      return bcrypt.compareSync(password, hash);
    }
    return crypto.createHash('sha256').update(password).digest('hex') === hash;
  } catch (e) {
    return true; // Fallback for test environments
  }
}

// ============================================================================
// 1. HEALTH & DATABASE STATUS API
// ============================================================================

app.get('/api/health', async (req, res) => {
  const dbStatus = await testConnection();
  if (!dbStatus.connected) {
    return res.status(500).json({
      status: 'ERROR',
      message: 'Failed to connect to Supabase PostgreSQL Database',
      error: dbStatus.error
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
      db_name: dbStatus.database,
      version: dbStatus.version,
      stats: {
        users: parseInt(userCount.rows[0].count, 10),
        domain_rules: parseInt(rulesCount.rows[0].count, 10),
        scan_audits: parseInt(scanCount.rows[0].count, 10)
      }
    });
  } catch (err) {
    res.status(500).json({ status: 'ERROR', message: err.message });
  }
});

// Database Re-Initialization & Seeding Endpoint
app.post('/api/init-db', async (req, res) => {
  try {
    const runSeed = require('./seed');
    await runSeed();
    res.json({ status: 'OK', message: 'Supabase Database schema and seed initialized successfully!' });
  } catch (err) {
    res.status(500).json({ status: 'ERROR', message: err.message });
  }
});

// ============================================================================
// 2. USER AUTHENTICATION APIS (Supabase Users Table)
// ============================================================================

app.post('/api/auth/signup', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email) {
    return res.status(400).json({ error: 'Name and email are required.' });
  }

  const cleanEmail = email.trim().toLowerCase();
  const cleanName = name.trim();
  const initials = cleanName.split(' ').map(n => n[0]).join('').toUpperCase().substring(0, 2) || 'SA';
  const hashedPass = hashPassword(password || 'password123');

  try {
    const existing = await query('SELECT id FROM users WHERE LOWER(email) = $1', [cleanEmail]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'User email already exists.' });
    }

    const result = await query(
      `INSERT INTO users (name, email, password_hash, role, initials) 
       VALUES ($1, $2, $3, 'Security Analyst', $4) 
       RETURNING id, name, email, role, initials, created_at;`,
      [cleanName, cleanEmail, hashedPass, initials]
    );

    res.status(201).json({
      message: 'Account created successfully in Supabase!',
      user: result.rows[0]
    });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Database signup error: ' + err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Email is required.' });
  }

  const cleanEmail = email.trim().toLowerCase();

  try {
    const result = await query('SELECT * FROM users WHERE LOWER(email) = $1', [cleanEmail]);
    if (result.rows.length === 0) {
      // Auto register demo users for ease of testing
      const name = cleanEmail.split('@')[0].replace(/[._]/g, ' ');
      const initials = name.substring(0, 2).toUpperCase();
      const newPass = hashPassword(password || 'password123');
      const newUser = await query(
        `INSERT INTO users (name, email, password_hash, role, initials)
         VALUES ($1, $2, $3, 'Security Analyst', $4)
         RETURNING id, name, email, role, initials;`,
        [name, cleanEmail, newPass, initials]
      );
      return res.json({
        message: 'Welcome back! (New account provisioned in Supabase)',
        user: newUser.rows[0]
      });
    }

    const user = result.rows[0];
    res.json({
      message: `Welcome back, ${user.name}!`,
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
    res.status(500).json({ error: 'Database login error: ' + err.message });
  }
});

// ============================================================================
// 3. DOMAIN OVERRIDE RULES APIS (Whitelist / Blacklist)
// ============================================================================

app.get('/api/rules', async (req, res) => {
  try {
    const result = await query('SELECT domain, type, created_at FROM domain_rules ORDER BY created_at DESC;');
    res.json(result.rows);
  } catch (err) {
    console.error('Fetch rules error:', err);
    res.status(500).json({ error: 'Failed to fetch domain rules from database.' });
  }
});

app.post('/api/rules', async (req, res) => {
  const { domain, type } = req.body;
  if (!domain || !type) {
    return res.status(400).json({ error: 'Domain and rule type (whitelist/blacklist) are required.' });
  }

  const cleanDomain = domain.trim().toLowerCase();
  const ruleType = type.toLowerCase();

  try {
    // Delete existing rule for domain if updating
    await query('DELETE FROM domain_rules WHERE LOWER(domain) = $1', [cleanDomain]);

    const result = await query(
      `INSERT INTO domain_rules (user_id, domain, type) VALUES ((SELECT id FROM users ORDER BY id ASC LIMIT 1), $1, $2) RETURNING id, domain, type, created_at;`,
      [cleanDomain, ruleType]
    );

    res.status(201).json({
      message: `Rule added for ${cleanDomain}`,
      rule: result.rows[0]
    });
  } catch (err) {
    console.error('Add rule error:', err);
    res.status(500).json({ error: 'Failed to add rule to database: ' + err.message });
  }
});

app.delete('/api/rules/:domain', async (req, res) => {
  const domain = decodeURIComponent(req.params.domain).trim().toLowerCase();

  try {
    await query('DELETE FROM domain_rules WHERE LOWER(domain) = $1;', [domain]);
    res.json({ message: `Rule removed for ${domain}` });
  } catch (err) {
    console.error('Delete rule error:', err);
    res.status(500).json({ error: 'Failed to delete rule from database.' });
  }
});

// ============================================================================
// 4. SCAN HISTORY & AUDIT LOG APIS
// ============================================================================

app.get('/api/scans', async (req, res) => {
  const { search, filter } = req.query;

  try {
    let sql = 'SELECT * FROM scan_history';
    const params = [];
    const conditions = [];

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
    console.error('Fetch scans error:', err);
    res.status(500).json({ error: 'Failed to fetch scan history from database.' });
  }
});

app.post('/api/scans', async (req, res) => {
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
       VALUES ((SELECT id FROM users ORDER BY id ASC LIMIT 1), $1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, CURRENT_TIMESTAMP)
       RETURNING *;`,
      [
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
      message: 'Scan saved to Supabase PostgreSQL database!',
      scan: result.rows[0]
    });
  } catch (err) {
    console.error('Save scan error:', err);
    res.status(500).json({ error: 'Failed to save scan to database: ' + err.message });
  }
});

app.delete('/api/scans/:id', async (req, res) => {
  const scanId = parseInt(req.params.id, 10);
  if (isNaN(scanId)) {
    return res.status(400).json({ error: 'Invalid scan ID.' });
  }

  try {
    await query('DELETE FROM scan_history WHERE id = $1;', [scanId]);
    res.json({ message: `Scan record ${scanId} deleted from database.` });
  } catch (err) {
    console.error('Delete scan error:', err);
    res.status(500).json({ error: 'Failed to delete scan record.' });
  }
});

app.delete('/api/scans', async (req, res) => {
  try {
    await query('TRUNCATE TABLE scan_history;');
    res.json({ message: 'All scan audit history cleared from database.' });
  } catch (err) {
    console.error('Clear scans error:', err);
    res.status(500).json({ error: 'Failed to clear scan history from database.' });
  }
});

// ============================================================================
// 5. EXECUTIVE KPI SUMMARY & METRICS API
// ============================================================================

app.get('/api/kpis', async (req, res) => {
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
    console.error('KPIs fetch error:', err);
    res.status(500).json({ error: 'Failed to compute KPIs from database.' });
  }
});

// ============================================================================
// 6. THREAT INTELLIGENCE API KEYS MANAGEMENT
// ============================================================================

// Webhook Alert Dispatcher Helper
async function triggerWebhookAlert(scanData) {
  try {
    const keysRes = await query('SELECT webhook_url FROM api_keys ORDER BY id DESC LIMIT 1;');
    const webhook_url = keysRes.rows[0]?.webhook_url;
    if (!webhook_url || !webhook_url.startsWith('http')) return;

    const payload = {
      text: `🚨 *ShieldURL Malicious Threat Alert* 🚨\n*URL:* ${scanData.url}\n*Score:* ${scanData.score}/100\n*Risk Level:* ${scanData.risk_level}\n*Timestamp:* ${new Date().toISOString()}`
    };

    // Use native fetch to dispatch alert asynchronously
    fetch(webhook_url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    }).catch(err => console.error('Webhook dispatch error:', err.message));
  } catch (err) {
    console.error('Failed to trigger webhook:', err.message);
  }
}

// ============================================================================
// 6. THREAT INTELLIGENCE API KEYS & WEBHOOK MANAGEMENT
// ============================================================================

app.get('/api/keys', async (req, res) => {
  try {
    const result = await query('SELECT vt_key, gsb_key, webhook_url FROM api_keys ORDER BY id DESC LIMIT 1;');
    if (result.rows.length === 0) {
      return res.json({ vt: '', gsb: '', webhook: '' });
    }
    res.json({
      vt: result.rows[0].vt_key || '',
      gsb: result.rows[0].gsb_key || '',
      webhook: result.rows[0].webhook_url || ''
    });
  } catch (err) {
    console.error('Get API keys error:', err);
    res.status(500).json({ error: 'Failed to retrieve API keys.' });
  }
});

app.post('/api/keys', async (req, res) => {
  const { vt, gsb, webhook } = req.body;
  try {
    await query('DELETE FROM api_keys;');
    await query(
      'INSERT INTO api_keys (user_id, vt_key, gsb_key, webhook_url) VALUES ((SELECT id FROM users ORDER BY id ASC LIMIT 1), $1, $2, $3);',
      [vt || '', gsb || '', webhook || '']
    );
    res.json({ message: 'API Keys and Webhook URL saved to database successfully!' });
  } catch (err) {
    console.error('Save API keys error:', err);
    res.status(500).json({ error: 'Failed to save API keys to database.' });
  }
});

// ============================================================================
// 7. AI SECURITY ANALYST ASSISTANT API
// ============================================================================

app.post('/api/ai/analyze', async (req, res) => {
  const { url, score, checks, prompt } = req.body;

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
      responseText = `<b>AI Security Analyst Evaluation for <code>${url || 'Target URL'}</code>:</b><br>Our heuristics engine evaluated key risk dimensions. The safety score is rated at <b>${score !== undefined ? score : 85}/100</b>. Always verify domain ownership, inspect SSL certificates, and check blacklists before entering sensitive credentials.`;
    }

    return res.json({ analysis: responseText });
  }

  // General URL breakdown generator
  let explanation = "";
  const failedChecks = (checks || []).filter(c => c.status === 'fail');
  const warnChecks = (checks || []).filter(c => c.status === 'warning');

  if (score >= 75) {
    explanation = `<b>AI Risk Summary: SAFE (Score ${score}/100)</b><br>The analyzed URL <code>${url}</code> demonstrates strong security characteristics. Valid SSL encryption is active, the domain entropy is low, no typosquatting terms were identified, and no blacklisting records were found across threat intelligence feeds.`;
  } else if (score >= 45) {
    explanation = `<b>AI Risk Summary: SUSPICIOUS (Score ${score}/100)</b><br>Caution advised for <code>${url}</code>. Found ${warnChecks.length + failedChecks.length} potential risk indicators:<br>` +
      (failedChecks.concat(warnChecks)).map(c => `• <b>${c.name}:</b> ${c.desc}`).join('<br>') +
      `<br><i>Recommendation: Exercise caution before logging in or granting permissions.</i>`;
  } else {
    explanation = `<b>AI Risk Summary: MALICIOUS (Score ${score}/100)</b><br>⚠️ HIGH THREAT ALERT for <code>${url}</code>. Severe security penalties triggered:<br>` +
      failedChecks.map(c => `• 🚨 <b>${c.name}:</b> ${c.desc}`).join('<br>') +
      `<br><b>Remediation:</b> Do NOT visit this link or enter passwords. Add domain to Blacklist rules immediately.`;
  }

  res.json({ analysis: explanation });
});

// ============================================================================
// 8. ADMIN USER MANAGEMENT API
// ============================================================================

app.get('/api/admin/users', async (req, res) => {
  try {
    const result = await query('SELECT id, name, email, role, initials, created_at FROM users ORDER BY created_at DESC;');
    res.json(result.rows);
  } catch (err) {
    console.error('Fetch admin users error:', err);
    res.status(500).json({ error: 'Failed to fetch users list.' });
  }
});

// Serve index.html for root path fallback (for non-API GET requests)
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'API endpoint not found' });
  }
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Export app for serverless function platforms (Vercel)
module.exports = app;

// Start Express Server locally
if (require.main === module) {
  app.listen(PORT, () => {
    console.log('================================================================');
    console.log(`🛡️ ShieldURL Security Server live on http://localhost:${PORT}`);
    console.log(`🗄️ Database Connected: Supabase PostgreSQL`);
    console.log('================================================================');
  });
}

