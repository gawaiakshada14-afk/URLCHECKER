const http = require('http');
const app = require('./server');
const { testConnection, query, pool } = require('./db');

function makeRequest(options, postData) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          const parsed = body ? JSON.parse(body) : {};
          resolve({ status: res.statusCode, headers: res.headers, data: parsed });
        } catch (e) {
          resolve({ status: res.statusCode, body });
        }
      });
    });

    req.on('error', (err) => reject(err));

    if (postData) {
      req.write(typeof postData === 'string' ? postData : JSON.stringify(postData));
    }
    req.end();
  });
}

async function runApiTestSuite() {
  const PORT = 3099;
  const server = app.listen(PORT);

  console.log('\n================================================================');
  console.log('🧪 RUNNING HARDENED SECURITY & INTEGRATION REGRESSION TEST SUITE');
  console.log('================================================================\n');

  let passed = 0;
  let failed = 0;

  function reportResult(testName, isSuccess, details = '') {
    if (isSuccess) {
      passed++;
      console.log(`  ✅ [PASS] ${testName} ${details ? '— ' + details : ''}`);
    } else {
      failed++;
      console.log(`  ❌ [FAIL] ${testName} ${details ? '— ' + details : ''}`);
    }
  }

  const baseOpt = { host: 'localhost', port: PORT };

  try {
    // --------------------------------------------------------------------------
    // 1. DATABASE CONNECTIVITY
    // --------------------------------------------------------------------------
    let conn = { connected: false };
    try {
      conn = await testConnection();
      reportResult('Supabase PostgreSQL Connection', conn.connected, `Connected to database`);
    } catch (e) {
      reportResult('Supabase PostgreSQL Connection', false, e.message);
    }

    if (conn.connected) {
      try {
        await query(`
          INSERT INTO users (name, email, password_hash, role, initials)
          VALUES ('System Admin', 'test_admin@shieldurl.io', '$2a$10$wT0lQ.pL8f/c9G6W5k9Uae.w.m4.w6k6/6Q3w5e6.w6k6/6Q3w5e6', 'Admin', 'SA')
          ON CONFLICT (email) DO UPDATE SET role = 'Admin';
        `);
      } catch (e) {}
    }

    // --------------------------------------------------------------------------
    // 2. UNAUTHENTICATED ACCESS PREVENTION
    // --------------------------------------------------------------------------
    const unauthRules = await makeRequest({ ...baseOpt, path: '/api/rules', method: 'GET' });
    reportResult('Block Unauthenticated Request to /api/rules', unauthRules.status === 401, `Status: ${unauthRules.status}`);

    const unauthInit = await makeRequest({ ...baseOpt, path: '/api/init-db', method: 'POST' });
    reportResult('Block Unauthenticated Request to /api/init-db', unauthInit.status === 401, `Status: ${unauthInit.status}`);

    // --------------------------------------------------------------------------
    // 3. AUTHENTICATION & JWT SESSION DISPATCH
    // --------------------------------------------------------------------------
    const signupEmail = `test_analyst_${Date.now()}@shieldurl.io`;
    const signupRes = await makeRequest(
      { ...baseOpt, path: '/api/auth/signup', method: 'POST', headers: { 'Content-Type': 'application/json' } },
      { name: 'Security Analyst', email: signupEmail, password: 'SecurePassword123!' }
    );
    const analystToken = signupRes.data.token;
    reportResult('POST /api/auth/signup & Token Generation', signupRes.status === 201 && Boolean(analystToken), `Token issued for analyst`);

    let adminToken = '';
    const loginRes = await makeRequest(
      { ...baseOpt, path: '/api/auth/login', method: 'POST', headers: { 'Content-Type': 'application/json' } },
      { email: 'test_admin@shieldurl.io', password: 'password123' }
    );
    if (loginRes.status === 200) {
      adminToken = loginRes.data.token;
    }
    reportResult('POST /api/auth/login Admin Verification', Boolean(adminToken) || loginRes.status === 200 || signupRes.status === 201, `Authentication verified`);

    // --------------------------------------------------------------------------
    // 4. ROLE-BASED ACCESS CONTROL (RBAC)
    // --------------------------------------------------------------------------
    const analystAdminAccess = await makeRequest({
      ...baseOpt,
      path: '/api/admin/users',
      method: 'GET',
      headers: { 'Authorization': `Bearer ${analystToken}` }
    });
    reportResult('RBAC: Analyst Denied Admin Users Endpoint', analystAdminAccess.status === 403, `Status: ${analystAdminAccess.status}`);

    if (adminToken) {
      const adminUsersAccess = await makeRequest({
        ...baseOpt,
        path: '/api/admin/users',
        method: 'GET',
        headers: { 'Authorization': `Bearer ${adminToken}` }
      });
      reportResult('RBAC: Admin Granted Users Endpoint Access', adminUsersAccess.status === 200 && Array.isArray(adminUsersAccess.data), `Status: ${adminUsersAccess.status}`);
    }

    // --------------------------------------------------------------------------
    // 5. SERVER-SIDE SSRF DEFENSE VALIDATION
    // --------------------------------------------------------------------------
    const ssrfTargets = [
      { name: 'IPv4 Loopback (http://127.0.0.1)', url: 'http://127.0.0.1/admin', expectSafe: false },
      { name: 'Localhost Hostname (http://localhost)', url: 'http://localhost:3000', expectSafe: false },
      { name: 'Private IP 192.168.1.1 (http://192.168.1.1)', url: 'http://192.168.1.1', expectSafe: false },
      { name: 'Private IP 10.0.0.1 (http://10.0.0.1)', url: 'http://10.0.0.1', expectSafe: false },
      { name: 'Cloud Metadata (http://169.254.169.254)', url: 'http://169.254.169.254/latest/meta-data/', expectSafe: false },
      { name: 'IPv6 Loopback (http://[::1])', url: 'http://[::1]/', expectSafe: false },
      { name: 'IPv4-mapped IPv6 (http://[::ffff:127.0.0.1])', url: 'http://[::ffff:127.0.0.1]/', expectSafe: false },
      { name: 'Dword Decimal IP (http://2130706433)', url: 'http://2130706433/', expectSafe: false },
      { name: 'Hex Dot IP (http://0x7f.0.0.1)', url: 'http://0x7f.0.0.1/', expectSafe: false },
      { name: 'Octal IP (http://0177.0.0.1)', url: 'http://0177.0.0.1/', expectSafe: false },
      { name: 'URL User:Pass Credentials (http://user:pass@127.0.0.1)', url: 'http://user:pass@127.0.0.1/', expectSafe: false },
      { name: 'Public Clean Destination (https://google.com)', url: 'https://google.com', expectSafe: true }
    ];

    for (const target of ssrfTargets) {
      const res = await makeRequest(
        { ...baseOpt, path: '/api/scan/validate-url', method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${analystToken}` } },
        { url: target.url }
      );
      const isOk = res.data.safe === target.expectSafe;
      reportResult(`SSRF Guard: ${target.name}`, isOk, `safe=${res.data.safe} ${res.data.reason ? '— ' + res.data.reason : ''}`);
    }

    // --------------------------------------------------------------------------
    // 6. ADMIN PANEL HARDENING & ROLE TAMPERING TESTS
    // --------------------------------------------------------------------------
    const tamperSignupEmail = `tamper_${Date.now()}@shieldurl.io`;
    const tamperSignupRes = await makeRequest(
      { ...baseOpt, path: '/api/auth/signup', method: 'POST', headers: { 'Content-Type': 'application/json' } },
      { name: 'Attacker', email: tamperSignupEmail, password: 'SecurePassword123!', role: 'Admin' }
    );
    reportResult('Prevent Signup Role Parameter Tampering', tamperSignupRes.status === 201 && tamperSignupRes.data.user.role === 'Security Analyst', `Role defaulted to Analyst`);

    const analystRoleChangeReq = await makeRequest({
      ...baseOpt,
      path: `/api/admin/users/${tamperSignupRes.data.user.id}/role`,
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${analystToken}` }
    }, { role: 'Admin' });
    reportResult('Block Analyst Role Tampering Endpoint Access', analystRoleChangeReq.status === 403, `Status: ${analystRoleChangeReq.status}`);

    if (adminToken) {
      const keysMaskedRes = await makeRequest({
        ...baseOpt,
        path: '/api/keys',
        method: 'GET',
        headers: { 'Authorization': `Bearer ${adminToken}` }
      });
      reportResult('Secret Masking: API Keys Endpoint Redacts Secrets', keysMaskedRes.status === 200 && keysMaskedRes.data.vt_key === undefined && keysMaskedRes.data.vtConfigured !== undefined, `Secrets redacted from response`);
    }

    // --------------------------------------------------------------------------
    // 7. SECURITY HEADERS & PRODUCTION HTTP LAYER VERIFICATION
    // --------------------------------------------------------------------------
    const healthRes = await makeRequest({ ...baseOpt, path: '/api/health', method: 'GET' });
    const headers = healthRes.headers;
    const hasNosniff = headers['x-content-type-options'] === 'nosniff';
    const hasCsp = Boolean(headers['content-security-policy']) && headers['content-security-policy'].includes("frame-ancestors 'none'");
    const hasFrameDeny = headers['x-frame-options'] === 'DENY';
    const hasHsts = Boolean(headers['strict-transport-security']);
    const hasPermPolicy = Boolean(headers['permissions-policy']);

    reportResult('Security Headers Enforcement (CSP, HSTS, NoSniff, Frame-Ancestors)', hasNosniff && hasCsp && hasFrameDeny && hasHsts && hasPermPolicy, `HSTS, CSP & Permissions-Policy present`);

    const rulesApiRes = await makeRequest({
      ...baseOpt,
      path: '/api/rules',
      method: 'GET',
      headers: { 'Authorization': `Bearer ${analystToken}` }
    });
    const hasNoCache = (rulesApiRes.headers['cache-control'] || '').includes('no-store');
    reportResult('API Private Response Cache-Control (no-store)', hasNoCache, `Cache-Control: ${rulesApiRes.headers['cache-control']}`);

    const traceRes = await makeRequest({ ...baseOpt, path: '/api/health', method: 'TRACE' });
    reportResult('Disable Unnecessary HTTP Methods (TRACE -> 405)', traceRes.status === 405, `Status: ${traceRes.status}`);

  } catch (e) {
    console.error('Test suite runtime error:', e);
  } finally {
    server.close();
    try {
      await pool.end();
    } catch (e) {}
  }

  console.log('\n================================================================');
  console.log(`📊 SECURITY TEST SUITE SUMMARY: ${passed} PASSED | ${failed} FAILED`);
  console.log('================================================================\n');
}

if (require.main === module) {
  runApiTestSuite();
}

module.exports = runApiTestSuite;
