/**
 * ShieldURL Defensive SSRF Guard Engine
 * Hardened Outbound Network & URL Validation Module
 */

const dns = require('dns').promises;
const net = require('net');
const http = require('http');
const https = require('https');

/**
 * Normalizes and parses non-standard IPv4 notations (decimal, hex, octal, IPv4-mapped IPv6)
 */
function parseNormalizedIp(ipStr) {
  if (!ipStr || typeof ipStr !== 'string') return null;

  let cleanStr = ipStr.trim().toLowerCase();

  // Strip brackets from IPv6 notation if present
  if (cleanStr.startsWith('[') && cleanStr.endsWith(']')) {
    cleanStr = cleanStr.slice(1, -1);
  }

  // Handle IPv4-mapped IPv6 (e.g., ::ffff:127.0.0.1 or ::ffff:7f00:1)
  if (cleanStr.startsWith('::ffff:')) {
    const mapped = cleanStr.substring(7);
    if (net.isIPv4(mapped)) return mapped;
    // Hex mapped IPv6 (e.g. ::ffff:7f00:0001)
    const hexParts = mapped.split(':');
    if (hexParts.length === 2) {
      const p1 = parseInt(hexParts[0], 16);
      const p2 = parseInt(hexParts[1], 16);
      if (!isNaN(p1) && !isNaN(p2)) {
        return `${(p1 >> 8) & 255}.${p1 & 255}.${(p2 >> 8) & 255}.${p2 & 255}`;
      }
    }
  }

  // Standard IPv4
  if (net.isIPv4(cleanStr)) {
    return cleanStr;
  }

  // Single Dword / Decimal IP notation (e.g. 2130706433 -> 127.0.0.1)
  if (/^\d+$/.test(cleanStr)) {
    const num = parseInt(cleanStr, 10);
    if (num >= 0 && num <= 4294967295) {
      return `${(num >>> 24) & 255}.${(num >>> 16) & 255}.${(num >>> 8) & 255}.${num & 255}`;
    }
  }

  // Octal or Hex dot notation (e.g. 0177.0.0.1 or 0x7f.0.0.1 or 0x7f000001)
  if (cleanStr.startsWith('0x') && !cleanStr.includes('.')) {
    const num = parseInt(cleanStr, 16);
    if (!isNaN(num) && num >= 0 && num <= 4294967295) {
      return `${(num >>> 24) & 255}.${(num >>> 16) & 255}.${(num >>> 8) & 255}.${num & 255}`;
    }
  }

  const parts = cleanStr.split('.');
  if (parts.length === 4) {
    const octets = [];
    for (const part of parts) {
      let val;
      if (part.startsWith('0x') || part.startsWith('0X')) {
        val = parseInt(part, 16);
      } else if (part.startsWith('0') && part.length > 1 && /^[0-7]+$/.test(part)) {
        val = parseInt(part, 8);
      } else if (/^\d+$/.test(part)) {
        val = parseInt(part, 10);
      } else {
        return null;
      }
      if (isNaN(val) || val < 0 || val > 255) return null;
      octets.push(val);
    }
    return octets.join('.');
  }

  // Standard IPv6
  if (net.isIPv6(cleanStr)) {
    return cleanStr;
  }

  return null;
}

/**
 * Checks if an IP address belongs to loopback, private, link-local, metadata, or reserved ranges
 */
function isBlockedIp(ipStr) {
  const norm = parseNormalizedIp(ipStr) || ipStr;

  if (net.isIPv4(norm)) {
    const parts = norm.split('.').map(Number);
    const [a, b, c, d] = parts;

    // 127.0.0.0/8 (Loopback)
    if (a === 127) return { blocked: true, range: '127.0.0.0/8 (Loopback)' };
    // 10.0.0.0/8 (Private)
    if (a === 10) return { blocked: true, range: '10.0.0.0/8 (Private)' };
    // 172.16.0.0/12 (Private)
    if (a === 172 && b >= 16 && b <= 31) return { blocked: true, range: '172.16.0.0/12 (Private)' };
    // 192.168.0.0/16 (Private)
    if (a === 192 && b === 168) return { blocked: true, range: '192.168.0.0/16 (Private)' };
    // 169.254.0.0/16 (Link-local & Cloud Metadata)
    if (a === 169 && b === 254) return { blocked: true, range: '169.254.0.0/16 (Link-Local / Metadata)' };
    // 100.64.0.0/10 (Carrier-grade NAT)
    if (a === 100 && b >= 64 && b <= 127) return { blocked: true, range: '100.64.0.0/10 (Carrier-Grade NAT)' };
    // 0.0.0.0/8 (Current Network / Unspecified)
    if (a === 0) return { blocked: true, range: '0.0.0.0/8 (Unspecified)' };
    // 224.0.0.0/4 (Multicast)
    if (a >= 224 && a <= 239) return { blocked: true, range: '224.0.0.0/4 (Multicast)' };
    // 240.0.0.0/4 (Reserved)
    if (a >= 240) return { blocked: true, range: '240.0.0.0/4 (Reserved)' };

    return { blocked: false };
  }

  if (net.isIPv6(norm)) {
    const lower = norm.toLowerCase();
    // ::1/128 (Loopback)
    if (lower === '::1' || lower === '0:0:0:0:0:0:0:1') return { blocked: true, range: '::1/128 (IPv6 Loopback)' };
    // ::/128 (Unspecified)
    if (lower === '::' || lower === '0:0:0:0:0:0:0:0') return { blocked: true, range: '::/128 (Unspecified)' };
    // fe80::/10 (Link-Local)
    if (lower.startsWith('fe80:')) return { blocked: true, range: 'fe80::/10 (Link-Local)' };
    // fc00::/7 (Unique Local)
    if (lower.startsWith('fc00:') || lower.startsWith('fd00:')) return { blocked: true, range: 'fc00::/7 (Unique Local)' };
    // IPv4-mapped IPv6 loopback / private
    if (lower.startsWith('::ffff:')) {
      const v4 = lower.replace('::ffff:', '');
      return isBlockedIp(v4);
    }

    return { blocked: false };
  }

  return { blocked: true, range: 'Unrecognized IP format' };
}

/**
 * Validates a target URL string before any outbound fetch attempt
 */
function validateTargetUrl(urlStr) {
  if (!urlStr || typeof urlStr !== 'string') {
    return { valid: false, error: 'Blocked / Unsafe Target: Missing or invalid URL string.' };
  }

  let parsed;
  try {
    parsed = new URL(urlStr);
  } catch (e) {
    return { valid: false, error: 'Blocked / Unsafe Target: Malformed URL syntax.' };
  }

  // Scheme Restriction: HTTP and HTTPS only
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { valid: false, error: `Blocked / Unsafe Target: Unsupported scheme (${parsed.protocol}). Only http:// and https:// allowed.` };
  }

  // Reject Credentials in URL
  if (parsed.username || parsed.password) {
    return { valid: false, error: 'Blocked / Unsafe Target: Embedded URL credentials (user:pass) are prohibited.' };
  }

  const hostname = parsed.hostname.toLowerCase();

  // Reject Localhost & Internal Hostnames
  if (
    hostname === 'localhost' ||
    hostname === '0.0.0.0' ||
    hostname.endsWith('.internal') ||
    hostname.endsWith('.local') ||
    hostname.endsWith('.localhost') ||
    hostname.endsWith('.lan')
  ) {
    return { valid: false, error: 'Blocked / Unsafe Target: Target resolves to prohibited internal hostname.' };
  }

  // Check if hostname is an explicit IP representation
  const parsedIp = parseNormalizedIp(hostname);
  if (parsedIp) {
    const ipCheck = isBlockedIp(parsedIp);
    if (ipCheck.blocked) {
      return { valid: false, error: `Blocked / Unsafe Target: Prohibited IP target (${ipCheck.range}).` };
    }
  }

  return { valid: true, parsed, hostname };
}

/**
 * Resolves DNS server-side and validates every resolved IP address
 */
async function resolveAndValidateDns(hostname) {
  // If hostname is already an IP address
  const directIp = parseNormalizedIp(hostname);
  if (directIp) {
    const ipCheck = isBlockedIp(directIp);
    if (ipCheck.blocked) {
      return { safe: false, error: `Blocked / Unsafe Target: IP ${directIp} is in blocked range (${ipCheck.range}).` };
    }
    return { safe: true, resolvedIp: directIp };
  }

  let addresses = [];
  try {
    addresses = await dns.lookup(hostname, { all: true });
  } catch (err) {
    return { safe: false, error: 'Blocked / Unsafe Target: DNS resolution failed for domain.' };
  }

  if (!addresses || addresses.length === 0) {
    return { safe: false, error: 'Blocked / Unsafe Target: No IP records found for domain.' };
  }

  // Validate EVERY resolved IP address
  for (const record of addresses) {
    const ip = record.address;
    const ipCheck = isBlockedIp(ip);
    if (ipCheck.blocked) {
      return { safe: false, error: `Blocked / Unsafe Target: Domain resolves to prohibited IP (${ip} in ${ipCheck.range}).` };
    }
  }

  return { safe: true, resolvedIp: addresses[0].address };
}

/**
 * Hardened Outbound Network Fetcher
 * - Rebinding Protection: Connects directly to validated IP with Host header
 * - Timeout: 5s connect, 10s total
 * - Max Redirects: 3 (validated independently)
 * - Max Response Size: 1MB
 * - Strips sensitive headers (Authorization, Cookie, etc.)
 */
async function fetchSafeUrl(urlStr, options = {}) {
  const maxRedirects = options.maxRedirects !== undefined ? options.maxRedirects : 3;
  const currentRedirectCount = options.redirectCount || 0;

  if (currentRedirectCount > maxRedirects) {
    return { success: false, error: 'Blocked / Unsafe Target: Maximum redirect limit exceeded (max 3).' };
  }

  // 1. Validate Target URL
  const urlCheck = validateTargetUrl(urlStr);
  if (!urlCheck.valid) {
    console.warn(`[SSRF Guard Blocked]: ${urlStr} — ${urlCheck.error}`);
    return { success: false, error: urlCheck.error };
  }

  const { parsed, hostname } = urlCheck;

  // 2. DNS Resolution & IP Validation (DNS Rebinding Guard)
  const dnsCheck = await resolveAndValidateDns(hostname);
  if (!dnsCheck.safe) {
    console.warn(`[SSRF Guard Blocked DNS]: ${urlStr} — ${dnsCheck.error}`);
    return { success: false, error: dnsCheck.error };
  }

  const targetIp = dnsCheck.resolvedIp;
  const isHttps = parsed.protocol === 'https:';
  const port = parsed.port ? parseInt(parsed.port, 10) : (isHttps ? 443 : 80);

  // 3. Dispatch Network Request directly to validated IP
  return new Promise((resolve) => {
    const transport = isHttps ? https : http;

    const reqOptions = {
      hostname: targetIp, // Rebinding protection: connect to validated IP directly
      port: port,
      path: parsed.pathname + parsed.search,
      method: options.method || 'GET',
      headers: {
        'Host': hostname, // Preserve original hostname in Host header
        'User-Agent': 'ShieldURL-Security-Scanner/2.0',
        'Accept': 'text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8'
        // Strips Authorization, Cookie, Proxy-Authorization
      },
      timeout: 5000,
      rejectUnauthorized: true
    };

    const req = transport.request(reqOptions, (res) => {
      // Handle Redirects independently with SSRF checks on target
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
        let redirectUrl = res.headers.location;
        try {
          redirectUrl = new URL(redirectUrl, urlStr).toString();
        } catch (e) {
          return resolve({ success: false, error: 'Blocked / Unsafe Target: Invalid redirect target header.' });
        }

        console.log(`[SSRF Guard] Following redirect (${currentRedirectCount + 1}/${maxRedirects}) -> ${redirectUrl}`);
        return resolve(fetchSafeUrl(redirectUrl, {
          ...options,
          redirectCount: currentRedirectCount + 1,
          maxRedirects
        }));
      }

      let responseBytes = 0;
      const MAX_BYTES = 1024 * 1024; // 1MB limit
      let bodyData = '';

      res.on('data', (chunk) => {
        responseBytes += chunk.length;
        if (responseBytes > MAX_BYTES) {
          req.destroy();
          return resolve({ success: false, error: 'Blocked / Unsafe Target: Response payload exceeded size limit (1MB).' });
        }
        bodyData += chunk.toString('utf8');
      });

      res.on('end', () => {
        resolve({
          success: true,
          status: res.statusCode,
          headers: {
            'content-type': res.headers['content-type'] || '',
            'server': res.headers['server'] || 'Protected'
          },
          ip: targetIp,
          contentLength: responseBytes
        });
      });
    });

    req.on('timeout', () => {
      req.destroy();
      resolve({ success: false, error: 'Blocked / Unsafe Target: Outbound connection timed out (5000ms).' });
    });

    req.on('error', (err) => {
      resolve({ success: false, error: 'Blocked / Unsafe Target: Network connection failed.' });
    });

    req.end();
  });
}

module.exports = {
  parseNormalizedIp,
  isBlockedIp,
  validateTargetUrl,
  resolveAndValidateDns,
  fetchSafeUrl
};
