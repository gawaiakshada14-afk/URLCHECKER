/**
 * ShieldURL Production Bundle & Source Security Audit Tool
 * Comprehensive Credential, Token, and Secret Leak Detection
 */

const fs = require('fs');
const path = require('path');

const IGNORED_DIRS = ['node_modules', '.git', '.vscode'];

const DETAILED_PATTERNS = [
  { name: 'Supabase Service Role Key', severity: 'CRITICAL', regex: /service_role\s*=\s*['"]?[a-zA-Z0-9._-]{20,}/i },
  { name: 'PostgreSQL Password Connection String', severity: 'CRITICAL', regex: /postgresql:\/\/[^:]+:([^@]+)@/i },
  { name: 'Google API Key (AIzaSy...)', severity: 'HIGH', regex: /AIzaSy[a-zA-Z0-9_-]{33}/ },
  { name: 'OpenAI / AI Provider Key (sk-...)', severity: 'HIGH', regex: /sk-[a-zA-Z0-9]{32,}/ },
  { name: 'Slack Webhook URL', severity: 'HIGH', regex: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9\/_-]+/ },
  { name: 'Discord Webhook URL', severity: 'HIGH', regex: /https:\/\/discord\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+/ },
  { name: 'JWT-Shaped Token Literal', severity: 'HIGH', regex: /eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/ },
  { name: 'PEM Private Key Header', severity: 'CRITICAL', regex: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/ },
  { name: 'Embedded URL Credentials', severity: 'HIGH', regex: /https?:\/\/[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@[a-zA-Z0-9.-]+/ },
  { name: 'Hardcoded Password Assignment', severity: 'CRITICAL', regex: /password\s*=\s*['"](?!password123|password|YOUR_|[A-Z_]+['"])[^'"]{8,}['"]/i }
];

let criticalLeaks = 0;
let totalAuditedFiles = 0;
const auditedManifest = [];

function scanPath(targetPath) {
  if (!fs.existsSync(targetPath)) return;

  const stat = fs.statSync(targetPath);

  if (stat.isDirectory()) {
    const items = fs.readdirSync(targetPath);
    for (const item of items) {
      if (IGNORED_DIRS.includes(item)) continue;
      scanPath(path.join(targetPath, item));
    }
  } else if (stat.isFile()) {
    const ext = path.extname(targetPath).toLowerCase();
    const fileName = path.basename(targetPath);

    // Skip root .env file as it is local server configuration
    if (fileName === '.env') return;

    if (['.js', '.map', '.json', '.html', '.css', '.sql', '.example'].includes(ext) || fileName.startsWith('.env.')) {
      auditFile(targetPath);
    }
  }
}

function auditFile(filePath) {
  totalAuditedFiles++;
  const relativePath = path.relative(__dirname, filePath);
  const content = fs.readFileSync(filePath, 'utf8');
  const lines = content.split('\n');

  let fileHasLeak = false;

  lines.forEach((line, index) => {
    for (const pattern of DETAILED_PATTERNS) {
      const match = line.match(pattern.regex);
      if (match) {
        // Exclude safe documentation placeholders
        if (
          line.includes('YOUR_') ||
          line.includes('placeholder') ||
          line.includes('example') ||
          line.includes('YOUR_DB_PASSWORD')
        ) {
          continue;
        }

        // Exclude test file synthetic SSRF payload strings
        if (relativePath === 'test-apis.js' && (line.includes('password123') || line.includes('user:pass@127.0.0.1'))) {
          continue;
        }

        criticalLeaks++;
        fileHasLeak = true;
        console.error(`🚨 [${pattern.severity} LEAK DETECTED] ${pattern.name}`);
        console.error(`   File: ${relativePath}:${index + 1}`);
        console.error(`   Snippet: ${line.trim().substring(0, 90)}...`);
        console.error('----------------------------------------------------------------');
      }
    }
  });

  auditedManifest.push({
    file: relativePath,
    status: fileHasLeak ? 'FAIL' : 'CLEAN'
  });
}

console.log('================================================================');
console.log('🔍 SHIELDURL DEDICATED PRODUCTION BUNDLE & SOURCE SECURITY AUDIT');
console.log('================================================================\n');

scanPath(__dirname);

console.log(`Audited Files Count: ${totalAuditedFiles}`);
console.log('----------------------------------------------------------------');

if (criticalLeaks > 0) {
  console.error(`\n❌ BUILD AUDIT FAILED: ${criticalLeaks} privileged secret(s) found in client-accessible assets!`);
  process.exit(1);
} else {
  console.log('\n✅ AUDIT PASSED: 0 privileged secrets found in production assets.');
  console.log('   All client-side variables are public by design.\n');
  console.log('================================================================\n');
  process.exit(0);
}
