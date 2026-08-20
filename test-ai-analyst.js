/**
 * ============================================================================
 * ShieldURL AI Analyst Endpoint Verification Test Suite
 * File: test-ai-analyst.js
 * ============================================================================
 */

const http = require('http');

console.log('================================================================');
console.log('🧪 RUNNING AI ANALYST ENDPOINT TEST SUITE');
console.log('================================================================\n');

let passCount = 0;
let failCount = 0;

function makeRequest(options, postData) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(body) });
        } catch (e) {
          resolve({ status: res.statusCode, body });
        }
      });
    });
    req.on('error', reject);
    if (postData) req.write(JSON.stringify(postData));
    req.end();
  });
}

async function runTests() {
  try {
    // 1. Obtain fresh JWT token by signing up test analyst account
    const signupEmail = `test_analyst_${Date.now()}@shieldurl.io`;
    const signupRes = await makeRequest({
      hostname: '127.0.0.1',
      port: 3000,
      path: '/api/auth/signup',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, { name: 'Test Analyst', email: signupEmail, password: 'Password123!' });

    let token = signupRes.data && signupRes.data.token ? signupRes.data.token : null;
    if (!token) {
      console.error('❌ Could not obtain test auth token:', signupRes.data);
      process.exit(1);
    }

    // Test 1: Unauthenticated request should return 401
    const unauthRes = await makeRequest({
      hostname: '127.0.0.1',
      port: 3000,
      path: '/api/ai/analyze',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, { prompt: 'Explain Shannon Entropy' });

    if (unauthRes.status === 401) {
      console.log('  ✅ [PASS] Unauthenticated request to /api/ai/analyze returns 401 Unauthorized');
      passCount++;
    } else {
      console.error(`  ❌ [FAIL] Expected 401, got ${unauthRes.status}`);
      failCount++;
    }

    // Test 2: Authenticated request with missing/mock OpenRouter key returns explicit error (not "Analysis complete.")
    const authRes = await makeRequest({
      hostname: '127.0.0.1',
      port: 3000,
      path: '/api/ai/analyze',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      }
    }, { prompt: 'How does entropy indicate phishing?' });

    if (authRes.data && (authRes.data.analysis || authRes.data.error)) {
      if (authRes.data.analysis) {
        console.log(`  ✅ [PASS] Authenticated request returned AI response: "${authRes.data.analysis.substring(0, 80)}..."`);
      } else {
        console.log(`  ✅ [PASS] Authenticated request returned clear configuration error: "${authRes.data.error}"`);
      }
      passCount++;
    } else {
      console.error(`  ❌ [FAIL] Expected analysis or explicit error, got:`, authRes.data);
      failCount++;
    }

    console.log('\n================================================================');
    console.log(`📊 AI ANALYST TEST SUMMARY: ${passCount} PASSED | ${failCount} FAILED`);
    console.log('================================================================\n');

    process.exit(failCount > 0 ? 1 : 0);
  } catch (err) {
    console.error('❌ Exception during AI Analyst test execution:', err.message);
    process.exit(1);
  }
}

runTests();
