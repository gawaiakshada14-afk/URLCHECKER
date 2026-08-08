const http = require('http');
const { testConnection, query, pool } = require('./db');

// Helper to make HTTP request to local server
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
  console.log('\n================================================================');
  console.log('🧪 RUNNING COMPREHENSIVE SUPABASE POSTGRESQL & API TEST SUITE');
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

  // --------------------------------------------------------------------------
  // TEST 1: Direct Supabase Connection Test
  // --------------------------------------------------------------------------
  try {
    const conn = await testConnection();
    reportResult('Supabase PostgreSQL Direct Connection', conn.connected, `DB: ${conn.database}, Version: ${conn.version?.substring(0, 30)}...`);
  } catch (e) {
    reportResult('Supabase PostgreSQL Direct Connection', false, e.message);
  }

  // --------------------------------------------------------------------------
  // TEST 2: Schema & Seed Data Validation via Direct SQL
  // --------------------------------------------------------------------------
  try {
    const userRes = await query('SELECT COUNT(*) FROM users;');
    const rulesRes = await query('SELECT COUNT(*) FROM domain_rules;');
    const scanRes = await query('SELECT COUNT(*) FROM scan_history;');

    reportResult('Users Table Query', parseInt(userRes.rows[0].count, 10) > 0, `Users count: ${userRes.rows[0].count}`);
    reportResult('Domain Rules Table Query', parseInt(rulesRes.rows[0].count, 10) > 0, `Rules count: ${rulesRes.rows[0].count}`);
    reportResult('Scan History Table Query', parseInt(scanRes.rows[0].count, 10) > 0, `Scans count: ${scanRes.rows[0].count}`);
  } catch (e) {
    reportResult('Database Schema & Tables Verification', false, e.message);
  }

  // HTTP API Tests against running Express Server (Port 3000)
  const port = process.env.PORT || 3000;
  const baseOpt = { host: 'localhost', port };

  // --------------------------------------------------------------------------
  // TEST 3: GET /api/health
  // --------------------------------------------------------------------------
  try {
    const res = await makeRequest({ ...baseOpt, path: '/api/health', method: 'GET' });
    reportResult('GET /api/health', res.status === 200 && res.data.connected === true, `Status: ${res.data.status}, DB: ${res.data.database}`);
  } catch (e) {
    reportResult('GET /api/health', false, e.message + ' (Make sure server is running)');
  }

  // --------------------------------------------------------------------------
  // TEST 4: POST /api/auth/signup
  // --------------------------------------------------------------------------
  const testEmail = `test_analyst_${Date.now()}@shieldurl.io`;
  try {
    const res = await makeRequest(
      { ...baseOpt, path: '/api/auth/signup', method: 'POST', headers: { 'Content-Type': 'application/json' } },
      { name: 'Test Analyst', email: testEmail, password: 'SecurePassword123!' }
    );
    reportResult('POST /api/auth/signup', res.status === 201 && res.data.user?.email === testEmail, `Created analyst: ${res.data.user?.email}`);
  } catch (e) {
    reportResult('POST /api/auth/signup', false, e.message);
  }

  // --------------------------------------------------------------------------
  // TEST 5: POST /api/auth/login
  // --------------------------------------------------------------------------
  try {
    const res = await makeRequest(
      { ...baseOpt, path: '/api/auth/login', method: 'POST', headers: { 'Content-Type': 'application/json' } },
      { email: 'analyst@shieldurl.io', password: 'password123' }
    );
    reportResult('POST /api/auth/login', res.status === 200 && res.data.user?.name !== undefined, `Logged in as: ${res.data.user?.name}`);
  } catch (e) {
    reportResult('POST /api/auth/login', false, e.message);
  }

  // --------------------------------------------------------------------------
  // TEST 6: GET /api/rules
  // --------------------------------------------------------------------------
  try {
    const res = await makeRequest({ ...baseOpt, path: '/api/rules', method: 'GET' });
    reportResult('GET /api/rules', res.status === 200 && Array.isArray(res.data), `Total rules returned: ${res.data.length}`);
  } catch (e) {
    reportResult('GET /api/rules', false, e.message);
  }

  // --------------------------------------------------------------------------
  // TEST 7: POST /api/rules (Add Whitelist / Blacklist Rule)
  // --------------------------------------------------------------------------
  const testDomain = `malicious-domain-test-${Date.now()}.com`;
  try {
    const res = await makeRequest(
      { ...baseOpt, path: '/api/rules', method: 'POST', headers: { 'Content-Type': 'application/json' } },
      { domain: testDomain, type: 'blacklist' }
    );
    reportResult('POST /api/rules', res.status === 201 && res.data.rule?.domain === testDomain, `Added blacklist rule for ${testDomain}`);
  } catch (e) {
    reportResult('POST /api/rules', false, e.message);
  }

  // --------------------------------------------------------------------------
  // TEST 8: DELETE /api/rules/:domain
  // --------------------------------------------------------------------------
  try {
    const res = await makeRequest({ ...baseOpt, path: `/api/rules/${encodeURIComponent(testDomain)}`, method: 'DELETE' });
    reportResult('DELETE /api/rules/:domain', res.status === 200, `Deleted rule for ${testDomain}`);
  } catch (e) {
    reportResult('DELETE /api/rules/:domain', false, e.message);
  }

  // --------------------------------------------------------------------------
  // TEST 9: POST /api/scans (Save Security Audit Record)
  // --------------------------------------------------------------------------
  let createdScanId = null;
  try {
    const res = await makeRequest(
      { ...baseOpt, path: '/api/scans', method: 'POST', headers: { 'Content-Type': 'application/json' } },
      {
        url: 'https://test-supabase-api-scan.org/audit',
        domain: 'test-supabase-api-scan.org',
        score: 95,
        status: '🟢 SAFE',
        risk_level: 'Safe',
        checks_json: [{ name: 'Supabase API Verification', passed: true, details: 'Verified via unit test' }],
        metadata_json: { test: true }
      }
    );
    createdScanId = res.data.scan?.id;
    reportResult('POST /api/scans', res.status === 201 && createdScanId !== undefined, `Saved scan record ID: ${createdScanId}`);
  } catch (e) {
    reportResult('POST /api/scans', false, e.message);
  }

  // --------------------------------------------------------------------------
  // TEST 10: GET /api/scans (Fetch Scan Audit History)
  // --------------------------------------------------------------------------
  try {
    const res = await makeRequest({ ...baseOpt, path: '/api/scans', method: 'GET' });
    reportResult('GET /api/scans', res.status === 200 && Array.isArray(res.data), `Fetched ${res.data.length} scan audits from database`);
  } catch (e) {
    reportResult('GET /api/scans', false, e.message);
  }

  // --------------------------------------------------------------------------
  // TEST 11: GET /api/kpis (Executive KPI Aggregation)
  // --------------------------------------------------------------------------
  try {
    const res = await makeRequest({ ...baseOpt, path: '/api/kpis', method: 'GET' });
    reportResult('GET /api/kpis', res.status === 200 && res.data.totalScans !== undefined, `Total Scans: ${res.data.totalScans}, Safe Ratio: ${res.data.safeRatio}`);
  } catch (e) {
    reportResult('GET /api/kpis', false, e.message);
  }

  // --------------------------------------------------------------------------
  // TEST 12: GET /api/keys & POST /api/keys
  // --------------------------------------------------------------------------
  try {
    const saveRes = await makeRequest(
      { ...baseOpt, path: '/api/keys', method: 'POST', headers: { 'Content-Type': 'application/json' } },
      { vt: 'test_vt_key_123', gsb: 'test_gsb_key_456' }
    );
    const getRes = await makeRequest({ ...baseOpt, path: '/api/keys', method: 'GET' });
    reportResult('GET & POST /api/keys', saveRes.status === 200 && getRes.data.vt === 'test_vt_key_123', `API keys configured and verified`);
  } catch (e) {
    reportResult('GET & POST /api/keys', false, e.message);
  }

  // --------------------------------------------------------------------------
  // TEST 13: DELETE /api/scans/:id
  // --------------------------------------------------------------------------
  if (createdScanId) {
    try {
      const res = await makeRequest({ ...baseOpt, path: `/api/scans/${createdScanId}`, method: 'DELETE' });
      reportResult('DELETE /api/scans/:id', res.status === 200, `Deleted scan record ID: ${createdScanId}`);
    } catch (e) {
      reportResult('DELETE /api/scans/:id', false, e.message);
    }
  }

  console.log('\n================================================================');
  console.log(`📊 TEST SUITE SUMMARY: ${passed} PASSED | ${failed} FAILED`);
  console.log('================================================================\n');

  await pool.end();
}

if (require.main === module) {
  runApiTestSuite();
}

module.exports = runApiTestSuite;
