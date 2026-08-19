/**
 * ============================================================================
 * ShieldURL Risk-Scoring Engine Unit Test Suite (13 Specific Scenarios)
 * File: test-scoring.js
 * ============================================================================
 */

const { evaluateHeuristics, evaluateThreatIntel, calculateSecurityScore } = require('./scoring');

console.log('================================================================');
console.log('🧪 RUNNING SHIELDURL RISK-SCORING ENGINE UNIT TEST SUITE');
console.log('================================================================\n');

let passCount = 0;
let failCount = 0;

function runTestCase(name, rawUrl, mockLiveDns, mockRdap, mockUrlhaus, mockVt, mockGsb, mockPhishtank, validatorFn) {
  try {
    let parsedUrl;
    try {
      parsedUrl = new URL(rawUrl);
    } catch (e) {
      parsedUrl = { hostname: 'invalid', protocol: 'invalid:', pathname: '', search: '' };
    }

    const heuristics = evaluateHeuristics(parsedUrl, rawUrl, mockLiveDns, mockRdap);
    const threatIntel = evaluateThreatIntel(parsedUrl, mockLiveDns, mockUrlhaus, mockVt, mockGsb, mockPhishtank);
    const result = calculateSecurityScore(rawUrl, parsedUrl, heuristics, threatIntel);

    const check = validatorFn(result, heuristics, threatIntel);
    if (check.pass) {
      console.log(`  ✅ [PASS] ${name}`);
      console.log(`     -> Score: ${result.score}/100 | Risk: ${result.riskLevel}`);
      console.log(`     -> Summary: ${result.summaryDesc}`);
      if (check.note) console.log(`     -> Note: ${check.note}`);
      passCount++;
    } else {
      console.error(`  ❌ [FAIL] ${name}`);
      console.error(`     -> Expected: ${check.expected}`);
      console.error(`     -> Got Score: ${result.score}/100 | Risk: ${result.riskLevel}`);
      console.error(`     -> Error: ${check.error}`);
      failCount++;
    }
  } catch (err) {
    console.error(`  ❌ [FAIL] ${name} — Exception: ${err.message}`);
    failCount++;
  }
  console.log('');
}

// 1. https://google.com (Clean HTTPS)
runTestCase(
  'Test Case 1: https://google.com (Safe HTTPS)',
  'https://google.com',
  { resolved: true, ip: '142.250.190.46' },
  { found: true, ageDays: 9800, creationDate: '1997-09-15' },
  { found: false, status: 'Clean' },
  { configured: true, flagged: 0, total: 91 },
  { configured: true, status: 'Clean' },
  { found: false, status: 'Unlisted' },
  (res) => {
    const pass = res.score >= 90 && (res.riskLevel.includes('SAFE') || res.riskLevel.includes('LOW RISK'));
    return { pass, expected: 'Score >= 90 and Risk SAFE / LOW RISK', note: `Score = ${res.score}` };
  }
);

// 2. http://google.com (Unencrypted HTTP)
runTestCase(
  'Test Case 2: http://google.com (Unencrypted HTTP)',
  'http://google.com',
  { resolved: true, ip: '142.250.190.46' },
  { found: true, ageDays: 9800, creationDate: '1997-09-15' },
  { found: false, status: 'Clean' },
  { configured: true, flagged: 0, total: 91 },
  { configured: true, status: 'Clean' },
  { found: false, status: 'Unlisted' },
  (res, heuristics) => {
    const sslCheck = heuristics.checks.find(c => c.id === 'ssl');
    const pass = res.score >= 80 && res.score <= 95 && sslCheck && sslCheck.tag === 'UNSECURE';
    return { pass, expected: 'Score 80–95 and HTTP warning tag', note: `Score = ${res.score}` };
  }
);

// 3. Normal HTTPS Website
runTestCase(
  'Test Case 3: Normal HTTPS Website (example.com)',
  'https://example.com',
  { resolved: true, ip: '93.184.216.34' },
  { found: true, ageDays: 4000, creationDate: '2000-01-01' },
  { found: false, status: 'Clean' },
  { configured: true, flagged: 0, total: 91 },
  { configured: true, status: 'Clean' },
  { found: false, status: 'Unlisted' },
  (res) => {
    const pass = res.score >= 85 && (res.riskLevel.includes('SAFE') || res.riskLevel.includes('LOW RISK'));
    return { pass, expected: 'Score >= 85 and Risk SAFE / LOW RISK', note: `Score = ${res.score}` };
  }
);

// 4. Suspicious URL with login/verify keywords
runTestCase(
  'Test Case 4: Suspicious URL (secure-login-example.com/account/verify-password)',
  'https://secure-login-example.com/account/verify-password',
  { resolved: true, ip: '198.51.100.22' },
  { found: true, ageDays: 90, creationDate: '2026-05-15' },
  { found: false, status: 'Clean' },
  { configured: false },
  { configured: false },
  { found: false, status: 'Unlisted' },
  (res) => {
    const pass = res.score >= 50 && res.score <= 79 && res.riskLevel === 'SUSPICIOUS';
    return { pass, expected: 'Score 50–79 and Risk SUSPICIOUS', note: `Score = ${res.score}` };
  }
);

// 5. URL with Raw IP Address
runTestCase(
  'Test Case 5: URL with Raw IP Address (http://93.184.216.34/login)',
  'http://93.184.216.34/login',
  { resolved: true, ip: '93.184.216.34' },
  { found: false },
  { found: false, status: 'Clean' },
  { configured: false },
  { configured: false },
  { found: false, status: 'Unlisted' },
  (res, heuristics) => {
    const ipCheck = heuristics.checks.find(c => c.id === 'ip_host');
    const pass = res.score <= 75 && ipCheck && ipCheck.tag === 'RAW IP';
    return { pass, expected: 'Score <= 75 with RAW IP check flag', note: `Score = ${res.score}` };
  }
);

// 6. High Entropy Domain (6-7 entropy -> -15 deduction)
runTestCase(
  'Test Case 6: High Entropy Domain (https://qzxw791kpz992xaqlm837190zkpmswqa10283.com)',
  'https://qzxw791kpz992xaqlm837190zkpmswqa10283.com',
  { resolved: true, ip: '203.0.113.5' },
  { found: false },
  { found: false, status: 'Clean' },
  { configured: false },
  { configured: false },
  { found: false, status: 'Unlisted' },
  (res, heuristics) => {
    const entCheck = heuristics.checks.find(c => c.id === 'entropy');
    const pass = entCheck && entCheck.tag.includes('ENTROPY') && entCheck.status !== 'pass' && res.score <= 85;
    return { pass, expected: 'Entropy deduction -15 applied (score <= 85)', note: `Score = ${res.score}, Check = ${entCheck.title}` };
  }
);

// 7. 1 VirusTotal Flag
runTestCase(
  'Test Case 7: 1 VirusTotal Vendor Flag (Isolated Warning)',
  'https://example-single-flag.com',
  { resolved: true, ip: '93.184.216.34' },
  { found: true, ageDays: 2000, creationDate: '2018-01-01' },
  { found: false, status: 'Clean' },
  { configured: true, flagged: 1, total: 91 },
  { configured: true, status: 'Clean' },
  { found: false, status: 'Unlisted' },
  (res, heuristics, threatIntel) => {
    const vtStatus = threatIntel.virusTotal.status;
    const pass = res.score >= 80 && res.riskLevel === 'SAFE WITH WARNING' && vtStatus === '1 / 91 Vendor Flags';
    return { pass, expected: 'Score >= 80, Risk SAFE WITH WARNING, Status "1 / 91 Vendor Flags"', note: `VT Status = ${vtStatus}` };
  }
);

// 8. Multiple VirusTotal Flags (25/91 Vendors)
runTestCase(
  'Test Case 8: Multiple VirusTotal Vendor Flags (25/91 Vendors)',
  'https://malicious-multi-vendor.com',
  { resolved: true, ip: '198.51.100.55' },
  { found: true, ageDays: 100 },
  { found: false, status: 'Clean' },
  { configured: true, flagged: 25, total: 91 },
  { configured: true, status: 'Clean' },
  { found: false, status: 'Unlisted' },
  (res) => {
    const pass = res.score <= 50 && res.riskLevel === 'DANGEROUS';
    return { pass, expected: 'Score <= 50 and Risk DANGEROUS', note: `Score = ${res.score}` };
  }
);

// 9. PhishTank Listed URL
runTestCase(
  'Test Case 9: PhishTank Listed Phishing URL',
  'https://phish-victim-bank.com/login',
  { resolved: true, ip: '198.51.100.99' },
  { found: true, ageDays: 3000 },
  { found: false },
  { configured: false },
  { configured: false },
  { found: true, status: 'MALICIOUS LISTED' },
  (res) => {
    const pass = res.score <= 20 && res.riskLevel === 'DANGEROUS' && res.isConfirmedThreat;
    return { pass, expected: 'Score <= 20, Risk DANGEROUS, Confirmed Threat = true', note: `Score = ${res.score}` };
  }
);

// 10. URLhaus Malicious Host
runTestCase(
  'Test Case 10: URLhaus Confirmed Malware Host',
  'https://malware-payload-drop.org/exe.bin',
  { resolved: true, ip: '203.0.113.88' },
  { found: true, ageDays: 2000 },
  { found: true, status: 'MALICIOUS LISTED' },
  { configured: false },
  { configured: false },
  { found: false, status: 'Unlisted' },
  (res) => {
    const pass = res.score <= 20 && res.riskLevel === 'DANGEROUS' && res.isConfirmedThreat;
    return { pass, expected: 'Score <= 20, Risk DANGEROUS, Confirmed Threat = true', note: `Score = ${res.score}` };
  }
);

// 11. Google Safe Browsing NOT CONFIGURED
runTestCase(
  'Test Case 11: Google Safe Browsing Unconfigured (Not Checked)',
  'https://google.com',
  { resolved: true, ip: '142.250.190.46' },
  { found: true, ageDays: 9800 },
  { found: false, status: 'Clean' },
  { configured: false },
  { configured: false }, // Unconfigured GSB
  { found: false, status: 'Unlisted' },
  (res, heuristics, threatIntel) => {
    const gsbStatus = threatIntel.googleSafe.status;
    const pass = gsbStatus === 'Not Checked' && threatIntel.googleSafe.badge === 'badge-neutral' && res.riskLevel.includes('LIMITED CHECK');
    return { pass, expected: 'GSB Status = "Not Checked" and Risk Level includes LIMITED CHECK', note: `Risk Level = ${res.riskLevel}` };
  }
);

// 12. Malformed URL
runTestCase(
  'Test Case 12: Malformed URL Handling',
  'ht!tp://invalid-url-format-999',
  { resolved: false, status: 'Error' },
  { found: false },
  { found: false },
  { configured: false },
  { configured: false },
  { found: false },
  (res) => {
    const pass = res.score < 80 && typeof res.score === 'number' && !isNaN(res.score);
    return { pass, expected: 'Handled without NaN exception and score < 80', note: `Score = ${res.score}` };
  }
);

// 13. HTTPS Cannot Override Confirmed Threat Intelligence
runTestCase(
  'Test Case 13: HTTPS Cannot Override Confirmed Malicious Threat Intelligence',
  'https://malicious-phishing-target.com',
  { resolved: true, ip: '198.51.100.11' },
  { found: true, ageDays: 4000 },
  { found: true, status: 'MALICIOUS LISTED' },
  { configured: true, flagged: 15, total: 91 },
  { configured: true, status: 'THREAT MATCH' },
  { found: true, status: 'MALICIOUS LISTED' },
  (res, heuristics) => {
    const sslCheck = heuristics.checks.find(c => c.id === 'ssl');
    const isHttpsPassed = sslCheck && sslCheck.status === 'pass';
    const pass = isHttpsPassed && res.score <= 20 && res.riskLevel === 'DANGEROUS' && res.isConfirmedThreat;
    return { pass, expected: 'HTTPS passes (0 deduction), but confirmed threat forces score <= 20 and Risk DANGEROUS', note: `HTTPS Pass = ${isHttpsPassed}, Score = ${res.score}, Risk = ${res.riskLevel}` };
  }
);

console.log('================================================================');
console.log(`📊 SCORING UNIT TEST SUMMARY: ${passCount} PASSED | ${failCount} FAILED`);
console.log('================================================================\n');

if (failCount > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
