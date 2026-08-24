/**
 * ============================================================================
 * ShieldURL Unified Risk-Scoring & Threat Classification Engine
 * File: scoring.js
 * ============================================================================
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.ShieldURLScoring = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {

  const HIGH_RISK_TLDS = new Set([
    'xyz', 'top', 'tk', 'ml', 'cf', 'gq', 'buzz', 'club', 'site',
    'work', 'click', 'monster', 'icu', 'cam', 'rest', 'online'
  ]);

  const SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'verification', 'account', 'password',
    'signin', 'secure', 'bank', 'wallet', 'payment', 'update'
  ];

  /**
   * Calculates Shannon Entropy normalized to an 8.0-bit scale for UI rendering
   */
  function calculateShannonEntropy(str) {
    if (!str || str.length === 0) return 0;
    const nameOnly = str.includes('.') ? str.split('.')[0] : str;
    const target = nameOnly.length >= 3 ? nameOnly : str;
    const len = target.length;
    const freq = {};
    for (const c of target) freq[c] = (freq[c] || 0) + 1;
    let charEnt = 0;
    for (const c in freq) {
      const p = freq[c] / len;
      charEnt -= p * Math.log2(p);
    }
    // Scale Shannon character entropy (0 to ~5.17) to 8.0 bit scale
    const byteEnt = (charEnt / 5.17) * 8.0;
    return parseFloat(Math.min(8.0, byteEnt).toFixed(2));
  }

  function getBaseDomain(hostname) {
    if (!hostname) return '';
    const parts = hostname.toLowerCase().split('.');
    if (parts.length <= 2) return hostname.toLowerCase();
    return parts.slice(-2).join('.');
  }

  /**
   * Evaluates heuristics dynamically and returns check objects + total deduction score
   */
  function evaluateHeuristics(parsedUrl, rawUrl, liveDns, rdap) {
    const hostname = (parsedUrl && parsedUrl.hostname ? parsedUrl.hostname : '').toLowerCase();
    const protocol = (parsedUrl && parsedUrl.protocol ? parsedUrl.protocol : '').toLowerCase();
    const fullPath = (parsedUrl ? (parsedUrl.pathname + parsedUrl.search) : '').toLowerCase();
    const queryStr = (parsedUrl && parsedUrl.search ? parsedUrl.search : '');
    const baseDomain = getBaseDomain(hostname);
    
    const checks = [];
    let totalDeduction = 0;

    // 0. SSRF / Restricted IP Check
    const isIpHost = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
    const isPrivateIp = (ip) => {
      if (!ip) return false;
      return /^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|169\.254\.|::1|0\.)/.test(ip);
    };

    if (isPrivateIp(hostname) || (liveDns && isPrivateIp(liveDns.ip))) {
      totalDeduction += 100;
      checks.push({
        id: 'ssrf',
        title: 'INTERNAL / RESTRICTED TARGET (SSRF ALERT)',
        desc: `Target resolves to a restricted internal IP or loopback address. Accessing local network resources is blocked.`,
        status: 'fail',
        tag: 'BLOCKED / UNSAFE'
      });
    }

    // 1. Protocol / HTTPS
    if (protocol === 'https:') {
      checks.push({
        id: 'ssl',
        title: 'HTTPS Protocol Encrypted',
        desc: 'Connection uses modern SSL/TLS encryption.',
        status: 'pass',
        tag: 'ENCRYPTED'
      });
    } else if (protocol === 'http:') {
      totalDeduction += 10;
      checks.push({
        id: 'ssl',
        title: 'Unencrypted HTTP Connection',
        desc: 'Data transmitted in plain text without SSL encryption.',
        status: 'warning',
        tag: 'UNSECURE'
      });
    } else {
      totalDeduction += 20;
      checks.push({
        id: 'ssl',
        title: 'Invalid / Malformed Protocol',
        desc: 'URL protocol is not standard HTTP or HTTPS.',
        status: 'fail',
        tag: 'MALFORMED'
      });
    }

    // 2. DNS
    if (!liveDns || !liveDns.resolved) {
      if (liveDns && liveDns.status === 'NXDOMAIN') {
        totalDeduction += 30;
        checks.push({
          id: 'dns',
          title: 'Domain Does Not Exist (NXDOMAIN)',
          desc: 'DNS resolution confirmed domain has no active A-records.',
          status: 'fail',
          tag: 'NXDOMAIN'
        });
      } else {
        totalDeduction += 15;
        checks.push({
          id: 'dns',
          title: 'DNS Resolution Failed',
          desc: `DNS resolution failed or timed out (${liveDns ? liveDns.status : 'Error'}).`,
          status: 'warning',
          tag: 'DNS FAIL'
        });
      }
    } else {
      const isSimulated = liveDns.isSimulated || liveDns.provider === 'SIMULATED';
      checks.push({
        id: 'dns',
        title: 'Live DNS Resolution Verified',
        desc: `Resolves to ${liveDns.ip}${isSimulated ? ' [Simulated Test IP]' : ''}.`,
        status: 'pass',
        tag: isSimulated ? 'SIMULATED DNS' : 'DNS OK'
      });
    }

    // 3. Domain Age (RDAP / WHOIS)
    if (rdap && rdap.found && rdap.ageDays !== null && rdap.ageDays !== undefined) {
      const ageDays = rdap.ageDays;
      if (ageDays > 1825) { // > 5 years
        checks.push({
          id: 'age',
          title: 'Domain Age > 5 Years Verified',
          desc: `Registered ${rdap.creationDate || ''} (${Math.floor(ageDays / 365)}+ years old).`,
          status: 'pass',
          tag: 'VERIFIED (>5 yrs)'
        });
      } else if (ageDays > 365) { // 1–5 years
        totalDeduction += 2;
        checks.push({
          id: 'age',
          title: 'Domain Age 1–5 Years',
          desc: `Registered ${rdap.creationDate || ''} (${Math.floor(ageDays / 365)} years old).`,
          status: 'pass',
          tag: 'VERIFIED (1-5 yrs)'
        });
      } else if (ageDays > 180) { // 6–12 months
        totalDeduction += 5;
        checks.push({
          id: 'age',
          title: 'Domain Age 6–12 Months',
          desc: `Registered ${rdap.creationDate || ''} (${ageDays} days old).`,
          status: 'warning',
          tag: 'MODERATE (6-12 mo)'
        });
      } else if (ageDays > 30) { // 1–6 months
        totalDeduction += 10;
        checks.push({
          id: 'age',
          title: 'Domain Age 1–6 Months',
          desc: `Registered ${rdap.creationDate || ''} (${ageDays} days old).`,
          status: 'warning',
          tag: 'RECENT (1-6 mo)'
        });
      } else { // < 30 days
        totalDeduction += 15;
        checks.push({
          id: 'age',
          title: 'Newly Registered Domain (<30 Days)',
          desc: `Registered ${rdap.creationDate || ''} (${ageDays} days old). High risk for phishing.`,
          status: 'fail',
          tag: 'NEW (<30 days)'
        });
      }
    } else {
      checks.push({
        id: 'age',
        title: 'Domain Age Information Unlisted',
        desc: 'RDAP creation record unlisted or private. Unknown age does not indicate maliciousness.',
        status: 'neutral',
        tag: 'UNKNOWN AGE'
      });
    }

    // 4. URL Entropy (Refined deductions: 6-7 = -15, >7 = -20)
    const entropy = calculateShannonEntropy(hostname);

    if (entropy > 7.0) {
      totalDeduction += 20;
      checks.push({
        id: 'entropy',
        title: `Very High String Entropy (${entropy.toFixed(2)})`,
        desc: 'Random character patterns suggest automated domain generation (DGA).',
        status: 'fail',
        tag: 'VERY HIGH ENTROPY'
      });
    } else if (entropy >= 6.0) {
      totalDeduction += 15;
      checks.push({
        id: 'entropy',
        title: `High String Entropy (${entropy.toFixed(2)})`,
        desc: 'High randomness detected in hostname characters.',
        status: 'warning',
        tag: 'HIGH ENTROPY'
      });
    } else if (entropy >= 5.0) {
      totalDeduction += 7;
      checks.push({
        id: 'entropy',
        title: `Elevated String Entropy (${entropy.toFixed(2)})`,
        desc: 'Slightly random character patterns detected.',
        status: 'warning',
        tag: 'ELEVATED ENTROPY'
      });
    } else if (entropy >= 4.0) {
      totalDeduction += 3;
      checks.push({
        id: 'entropy',
        title: `Slightly Elevated Entropy (${entropy.toFixed(2)})`,
        desc: 'Character distribution shows minor randomness.',
        status: 'warning',
        tag: 'MINOR ENTROPY'
      });
    } else {
      checks.push({
        id: 'entropy',
        title: `Normal String Entropy (${entropy.toFixed(2)})`,
        desc: 'Character distribution matches natural language words.',
        status: 'pass',
        tag: 'NORMAL ENTROPY'
      });
    }

    // 5. Suspicious Keywords
    const matchedKw = SUSPICIOUS_KEYWORDS.filter(kw => hostname.includes(kw) || fullPath.includes(kw));
    
    if (matchedKw.length >= 3) {
      totalDeduction += 15;
      checks.push({
        id: 'kw',
        title: `Multiple Phishing Keywords Found (${matchedKw.length})`,
        desc: `Detected sensitive terms: [${matchedKw.join(', ')}]. Legitimate sites may use keywords, exercise caution.`,
        status: 'fail',
        tag: 'SUSPICIOUS KW'
      });
    } else if (matchedKw.length === 2) {
      totalDeduction += 6;
      checks.push({
        id: 'kw',
        title: `2 Security Keywords Found`,
        desc: `Detected keywords: [${matchedKw.join(', ')}].`,
        status: 'warning',
        tag: 'CAUTION KW'
      });
    } else if (matchedKw.length === 1) {
      totalDeduction += 3;
      checks.push({
        id: 'kw',
        title: `1 Security Keyword Found`,
        desc: `Detected keyword: [${matchedKw.join(', ')}].`,
        status: 'warning',
        tag: 'CAUTION KW'
      });
    } else {
      checks.push({
        id: 'kw',
        title: 'Clean Keyword Inspection',
        desc: 'No credential-harvesting keywords found in URL structure.',
        status: 'pass',
        tag: 'CLEAN KW'
      });
    }

    // 6. URL Structure Heuristics
    if (isIpHost && !isPrivateIp(hostname)) {
      totalDeduction += 15;
      checks.push({
        id: 'ip_host',
        title: 'Raw IP Address Hostname',
        desc: 'URL specifies a raw IP address instead of a domain name.',
        status: 'fail',
        tag: 'RAW IP'
      });
    }

    if (rawUrl && rawUrl.includes('@')) {
      totalDeduction += 15;
      checks.push({
        id: 'at_symbol',
        title: '@ Symbol in URL Path/Authority',
        desc: '@ symbol detected in URL structure, which can obscure real destination.',
        status: 'fail',
        tag: '@ SYMBOL'
      });
    }

    if (hostname.includes('xn--')) {
      totalDeduction += 12;
      checks.push({
        id: 'punycode',
        title: 'Punycode Internationalized Domain (xn--)',
        desc: 'Domain uses Punycode encoding, often used in IDN homograph attacks.',
        status: 'warning',
        tag: 'PUNYCODE'
      });
    }

    const subdomainDepth = hostname.split('.').length - 2;
    if (subdomainDepth >= 3) {
      totalDeduction += 8;
      checks.push({
        id: 'subdomains',
        title: `Excessive Subdomain Depth (${subdomainDepth} levels)`,
        desc: 'Deep subdomain nesting is frequently used in phishing campaigns.',
        status: 'warning',
        tag: 'DEEP SUBDOMAINS'
      });
    }

    if (queryStr.length > 100) {
      totalDeduction += 5;
      checks.push({
        id: 'long_query',
        title: `Very Long Query String (${queryStr.length} chars)`,
        desc: 'Excessively long query parameters can hide tracking or payload data.',
        status: 'warning',
        tag: 'LONG QUERY'
      });
    }

    if (rawUrl && rawUrl.length > 300) {
      totalDeduction += 10;
      checks.push({
        id: 'url_len',
        title: `Extremely Long URL (${rawUrl.length} chars)`,
        desc: 'URL total length exceeds 300 characters.',
        status: 'warning',
        tag: 'LONG URL (>300)'
      });
    } else if (rawUrl && rawUrl.length >= 200) {
      totalDeduction += 6;
      checks.push({
        id: 'url_len',
        title: `Very Long URL (${rawUrl.length} chars)`,
        desc: 'URL total length is between 200 and 300 characters.',
        status: 'warning',
        tag: 'LONG URL (200-300)'
      });
    } else if (rawUrl && rawUrl.length >= 100) {
      totalDeduction += 3;
      checks.push({
        id: 'url_len',
        title: `Long URL (${rawUrl.length} chars)`,
        desc: 'URL total length is between 100 and 200 characters.',
        status: 'warning',
        tag: 'LONG URL (100-200)'
      });
    }

    // 7. TLD Assessment
    const tld = hostname.split('.').pop();
    if (tld && HIGH_RISK_TLDS.has(tld.toLowerCase())) {
      totalDeduction += 5;
      checks.push({
        id: 'tld',
        title: `Elevated Risk TLD Extension (.${tld})`,
        desc: `The .${tld} top-level domain is frequently seen in spam/phishing campaigns.`,
        status: 'warning',
        tag: `.${tld.toUpperCase()}`
      });
    }

    return {
      checks,
      totalDeduction,
      entropy: entropy.toFixed(2),
      tld: '.' + tld,
      isIpHost
    };
  }

  /**
   * Evaluates Threat Intelligence results & returns deductions and updated card metadata
   */
  function evaluateThreatIntel(parsedUrl, liveDns, urlhaus, vt, gsb, phishTank) {
    let threatDeduction = 0;
    let isConfirmedThreat = false;
    let vtDeduction = 0;
    let vtStatusText = '';

    // VirusTotal Vendor Deduction Logic
    let vtResult = vt || { configured: false, status: 'Not Checked', badge: 'badge-neutral', desc: 'VirusTotal API unconfigured. Threat status not checked.' };
    
    if (vtResult.configured && typeof vtResult.flagged === 'number') {
      const flagged = vtResult.flagged;
      const total = vtResult.total || 91;

      if (flagged === 0) {
        vtDeduction = 0;
        vtStatusText = `0 / ${total} Vendor Flags`;
        vtResult.badge = 'badge-safe';
        vtResult.desc = `Verified clean across ${total} threat intelligence vendors on VirusTotal.`;
      } else if (flagged === 1) {
        vtDeduction = 10;
        vtStatusText = `1 / ${total} Vendor Flags`;
        vtResult.badge = 'badge-warning';
        vtResult.desc = `1 / ${total} security vendors flagged this URL.`;
      } else if (flagged <= 5) {
        vtDeduction = 25;
        vtStatusText = `${flagged} / ${total} Vendor Flags`;
        vtResult.badge = 'badge-warning';
        vtResult.desc = `${flagged} / ${total} security vendors flagged this URL.`;
      } else if (flagged <= 15) {
        vtDeduction = 45;
        vtStatusText = `${flagged} / ${total} Vendor Flags`;
        vtResult.badge = 'badge-danger';
        vtResult.desc = `${flagged} / ${total} security vendors flagged this URL.`;
      } else if (flagged <= 30) {
        vtDeduction = 65;
        vtStatusText = `${flagged} / ${total} Vendor Flags`;
        vtResult.badge = 'badge-danger';
        vtResult.desc = `${flagged} / ${total} security vendors flagged this URL.`;
      } else {
        vtDeduction = 80;
        vtStatusText = `${flagged} / ${total} Vendor Flags`;
        vtResult.badge = 'badge-danger';
        vtResult.desc = `${flagged} / ${total} security vendors flagged this URL.`;
      }

      vtResult.status = vtStatusText;
      vtResult.deduction = vtDeduction;
      vtResult.flagged = flagged;
      vtResult.total = total;
    } else {
      vtResult.status = 'Not Checked';
      vtResult.badge = 'badge-neutral';
      vtResult.desc = 'VirusTotal API unconfigured. Threat status not checked.';
      vtResult.deduction = 0;
      vtResult.configured = false;
    }

    threatDeduction += vtResult.deduction;

    // Google Safe Browsing
    let gsbResult = gsb || { configured: false, status: 'Not Checked', badge: 'badge-neutral', desc: 'Google Safe Browsing API unconfigured. Threat status not checked.' };
    if (gsbResult.configured) {
      if (gsbResult.status === 'THREAT MATCH' || (gsbResult.found === true && gsbResult.status !== 'Clean')) {
        isConfirmedThreat = true;
        gsbResult.status = 'THREAT MATCH';
        gsbResult.badge = 'badge-danger';
        gsbResult.desc = gsbResult.desc || 'Google Safe Browsing flagged this URL as malicious.';
      } else if (gsbResult.status === 'Clean' || gsbResult.found === false) {
        gsbResult.status = 'Clean';
        gsbResult.badge = 'badge-safe';
        gsbResult.desc = gsbResult.desc || 'Google Safe Browsing verified no threat matches for this URL.';
      }
    } else {
      gsbResult.status = 'Not Checked';
      gsbResult.badge = 'badge-neutral';
      gsbResult.desc = 'Google Safe Browsing API unconfigured. Threat status not checked.';
      gsbResult.configured = false;
    }

    // PhishTank
    let phishResult = phishTank || { configured: false, status: 'Not Checked', badge: 'badge-neutral', desc: 'PhishTank database unconfigured or unavailable.' };
    if (phishResult.found || phishResult.status === 'MALICIOUS LISTED' || phishResult.status === 'Likely Phish') {
      if (phishResult.found || phishResult.status === 'MALICIOUS LISTED') {
        isConfirmedThreat = true;
        phishResult.status = 'MALICIOUS LISTED';
        phishResult.badge = 'badge-danger';
        phishResult.desc = 'Listed as confirmed phishing in PhishTank database.';
      } else {
        phishResult.badge = 'badge-warning';
      }
    } else if (phishResult.status === 'Unlisted' || phishResult.found === false) {
      phishResult.status = 'Unlisted';
      phishResult.badge = 'badge-safe';
      phishResult.desc = 'URL is unlisted in active PhishTank community database.';
    } else {
      phishResult.status = 'Not Checked';
      phishResult.badge = 'badge-neutral';
      phishResult.desc = 'PhishTank database unconfigured or unavailable.';
    }

    // URLhaus
    let urlhausResult = urlhaus || { configured: false, status: 'Not Checked', badge: 'badge-neutral', desc: 'URLhaus malware database unconfigured or unavailable.' };
    if (urlhausResult.found || urlhausResult.status === 'MALICIOUS LISTED') {
      isConfirmedThreat = true;
      urlhausResult.status = 'MALICIOUS LISTED';
      urlhausResult.badge = 'badge-danger';
      urlhausResult.desc = 'Domain listed as malware host in URLhaus database.';
    } else if (urlhausResult.status === 'Clean' || (urlhausResult.found === false && urlhausResult.isReal)) {
      urlhausResult.status = 'Clean';
      urlhausResult.badge = 'badge-safe';
      urlhausResult.desc = 'No malware payload hosting found on URLhaus database.';
    } else {
      urlhausResult.status = 'Not Checked';
      urlhausResult.badge = 'badge-neutral';
      urlhausResult.desc = 'URLhaus malware database unconfigured or unavailable.';
    }

    return {
      virusTotal: vtResult,
      googleSafe: gsbResult,
      phishTank: phishResult,
      urlHaus: urlhausResult,
      threatDeduction,
      isConfirmedThreat
    };
  }

  /**
   * Master function: Assembles security score, applies overrides, and calculates classification
   */
  function calculateSecurityScore(rawUrl, parsedUrl, heuristics, threatIntel) {
    let score = 100; // Start from 100

    // Subtract heuristic deductions
    score -= heuristics.totalDeduction;

    // Subtract threat intelligence deductions
    score -= threatIntel.threatDeduction;

    // Check for explicit confirmed threat
    const isConfirmedThreat = threatIntel.isConfirmedThreat || 
      heuristics.checks.some(c => c.tag === 'BLOCKED / UNSAFE' || c.tag === 'SPOOFED' || c.tag === 'BLACKLISTED');

    // Threat Intelligence Override Rules:
    // Rule 1: Confirmed Threat (GSB, PhishTank, URLhaus, SSRF, Blacklist) -> score = min(score, 20), classification = DANGEROUS
    if (isConfirmedThreat) {
      score = Math.min(score, 20);
    } else if (threatIntel.virusTotal && threatIntel.virusTotal.configured && threatIntel.virusTotal.flagged >= 6) {
      // Rule 2: VT >= 6 vendor flags -> score = min(score, 35)
      score = Math.min(score, 35);
    }

    // Clamp score strictly to [0, 100]
    score = Math.max(0, Math.min(100, Math.round(score)));

    // Check if any major threat intelligence provider is unconfigured / Not Checked
    const hasUncheckedFeeds = !threatIntel.googleSafe.configured || !threatIntel.virusTotal.configured;

    let riskLevel = 'SAFE';
    let riskBadgeClass = 'safe';
    let riskBadgeIcon = 'fa-shield-check';
    let summaryDesc = '';

    const hasWarnings = heuristics.checks.some(c => c.status === 'warning') ||
      (threatIntel.virusTotal && threatIntel.virusTotal.flagged === 1);

    if (isConfirmedThreat || score < 50) {
      riskLevel = 'DANGEROUS';
      riskBadgeClass = 'danger';
      riskBadgeIcon = 'fa-triangle-exclamation';
      summaryDesc = 'DANGER: Confirmed security threat or multiple malicious indicators detected. Do NOT interact with this URL.';
    } else if (score < 80) {
      riskLevel = 'SUSPICIOUS';
      riskBadgeClass = 'warning';
      riskBadgeIcon = 'fa-triangle-exclamation';
      summaryDesc = 'SUSPICIOUS: Risk indicators or security warnings detected — exercise caution before proceeding.';
    } else {
      if (hasWarnings) {
        riskLevel = 'SAFE WITH WARNING';
        riskBadgeClass = 'warning';
        summaryDesc = 'Passed primary checks with minor risk warnings detected — review details below.';
      } else if (hasUncheckedFeeds) {
        // Prevent unconfigured APIs from presenting a false "fully verified safe" label
        riskLevel = 'LOW RISK / LIMITED CHECK';
        riskBadgeClass = 'warning';
        riskBadgeIcon = 'fa-circle-info';
        summaryDesc = 'Heuristics passed (100/100), but one or more threat-intelligence feeds were NOT CHECKED (unconfigured API keys).';
      } else {
        riskLevel = 'SAFE';
        riskBadgeClass = 'safe';
        riskBadgeIcon = 'fa-shield-check';
        summaryDesc = 'This website passed security checks with no active threat matches found across global feeds.';
      }
    }

    return {
      score,
      riskLevel,
      riskBadgeClass,
      riskBadgeIcon,
      summaryDesc,
      isConfirmedThreat
    };
  }

  return {
    HIGH_RISK_TLDS,
    SUSPICIOUS_KEYWORDS,
    calculateShannonEntropy,
    getBaseDomain,
    evaluateHeuristics,
    evaluateThreatIntel,
    calculateSecurityScore
  };

}));
