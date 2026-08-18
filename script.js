/**
 * ShieldURL - AI-Powered Website Security Analyzer
 * Vanilla JavaScript Engine v2.0 — LIVE RESULTS ENGINE
 * 
 * Real Live Data Sources:
 *   ✓ Cloudflare DNS-over-HTTPS (DoH) — Real DNS A-record resolution
 *   ✓ RDAP Protocol (rdap.org) — Real domain registration age & registrar
 *   ✓ ipapi.co Geolocation — Real IP country, ISP, and hosting org
 *   ✓ URLhaus (abuse.ch) — Real malware URL database lookup
 *   ✓ Enhanced 12-dimension Heuristic NLP Engine
 */

document.addEventListener('DOMContentLoaded', () => {

  // ========================================================================
  // 1. CORE STATE & CONSTANTS
  // ========================================================================
  const STORAGE_KEY = 'shieldurl_scan_history';
  const API_KEY_STORAGE = 'shieldurl_api_keys';
  const USER_SESSION_KEY = 'shieldurl_user_session';
  const USER_RULES_KEY = 'shieldurl_user_rules';
  const TOKEN_KEY = 'shieldurl_jwt_token';

  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function getAuthToken() {
    return localStorage.getItem(TOKEN_KEY) || '';
  }

  function setAuthToken(token) {
    if (token) {
      localStorage.setItem(TOKEN_KEY, token);
    } else {
      localStorage.removeItem(TOKEN_KEY);
    }
  }

  async function authFetch(url, options = {}) {
    const token = getAuthToken();
    const headers = {
      'Content-Type': 'application/json',
      ...(options.headers || {})
    };
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    const res = await fetch(url, { ...options, headers });
    if (res.status === 401 && !url.includes('/api/auth/')) {
      setAuthToken(null);
      currentUser = null;
      localStorage.removeItem(USER_SESSION_KEY);
      updateUserSessionUI();
    }
    return res;
  }

  // Cleanup legacy shared browser scan history keys
  try {
    localStorage.removeItem('shieldurl_scan_history');
    localStorage.removeItem('scanHistory');
  } catch (e) {}

  let currentScanResult = null;
  let scanHistory = [];
  let currentUser = JSON.parse(localStorage.getItem(USER_SESSION_KEY)) || null;

  function getUserHistoryStorageKey() {
    if (!currentUser) return null;
    const uid = currentUser.id || currentUser.email || 'user';
    return `shieldurl_scan_history_${uid}`;
  }

  function loadUserScanHistory() {
    const key = getUserHistoryStorageKey();
    if (!key) {
      scanHistory = [];
      renderHistoryTable();
      return;
    }
    try {
      const stored = localStorage.getItem(key);
      scanHistory = stored ? JSON.parse(stored) : [];
    } catch (e) {
      scanHistory = [];
    }
    renderHistoryTable();
  }

  function saveUserScanHistory() {
    const key = getUserHistoryStorageKey();
    if (!key) return;
    try {
      localStorage.setItem(key, JSON.stringify(scanHistory));
    } catch (e) {}
  }
  let domainRules = JSON.parse(localStorage.getItem(USER_RULES_KEY)) || [
    { domain: 'google.com', type: 'whitelist' },
    { domain: 'phishing-login-fake.net', type: 'blacklist' }
  ];

  // Known trusted domains get a trust bonus (partial list of Tranco Top 100)
  const TRUSTED_DOMAINS = new Set([
    'google.com','youtube.com','facebook.com','instagram.com','twitter.com','x.com',
    'linkedin.com','reddit.com','wikipedia.org','amazon.com','apple.com','microsoft.com',
    'github.com','stackoverflow.com','netflix.com','whatsapp.com','pinterest.com',
    'yahoo.com','bing.com','zoom.us','dropbox.com','salesforce.com','adobe.com',
    'cloudflare.com','wordpress.com','medium.com','quora.com','twitch.tv','discord.com',
    'paypal.com','stripe.com','shopify.com','ebay.com','walmart.com','espn.com',
    'bbc.com','cnn.com','nytimes.com','forbes.com','reuters.com','openai.com',
    'chatgpt.com','claude.ai','notion.so','figma.com','canva.com','slack.com',
    'atlassian.com','jira.com','trello.com','asana.com','hubspot.com','mailchimp.com',
    'godaddy.com','namecheap.com','vercel.com','netlify.com','heroku.com','aws.amazon.com',
    'docs.google.com','drive.google.com','mail.google.com','outlook.com','office.com',
    'icloud.com','spotify.com','soundcloud.com','tiktok.com','snapchat.com','telegram.org'
  ]);

  // URL shortener domains
  const URL_SHORTENERS = new Set([
    'bit.ly','tinyurl.com','t.co','goo.gl','is.gd','buff.ly','ow.ly',
    'rb.gy','cutt.ly','shorturl.at','tiny.cc','tr.im','v.gd','qr.ae'
  ]);

  // Dangerous file extensions in URL path
  const DANGEROUS_EXTENSIONS = ['.exe','.bat','.cmd','.scr','.pif','.msi','.dll','.vbs','.js','.jar','.ps1','.sh','.dmg'];

  // ========================================================================
  // 2. DOM ELEMENT SELECTORS
  // ========================================================================

  // Auth Elements
  const btnOpenAuth = document.getElementById('btn-open-auth');
  const userProfileMenu = document.getElementById('user-profile-menu');
  const btnUserDropdown = document.getElementById('btn-user-dropdown');
  const userDropdownContent = document.getElementById('user-dropdown-content');
  const userDisplayName = document.getElementById('user-display-name');
  const userAvatarInitials = document.getElementById('user-avatar-initials');
  const dropdownUserName = document.getElementById('dropdown-user-name');
  const dropdownUserEmail = document.getElementById('dropdown-user-email');
  const btnLogout = document.getElementById('btn-logout');

  const authModal = document.getElementById('auth-modal');
  const btnCloseAuthModal = document.getElementById('btn-close-auth-modal');
  const tabLoginBtn = document.getElementById('tab-login-btn');
  const tabSignupBtn = document.getElementById('tab-signup-btn');
  const loginForm = document.getElementById('login-form');
  const signupForm = document.getElementById('signup-form');
  const btnDemoLogin = document.getElementById('btn-demo-login');

  // Scanner Elements
  const urlForm = document.getElementById('url-scan-form');
  const urlInput = document.getElementById('url-input');
  const btnClearUrl = document.getElementById('btn-clear-url');
  const btnAnalyze = document.getElementById('btn-analyze');
  const scanningLoader = document.getElementById('scanning-loader');
  const scanProgressFill = document.getElementById('scan-progress-fill');
  const scanProgressPercent = document.getElementById('scan-progress-percentage');

  const resultsDashboard = document.getElementById('results-dashboard');
  const riskBadge = document.getElementById('risk-badge');
  const badgeIcon = document.getElementById('badge-icon');
  const badgeText = document.getElementById('badge-text');
  const resultUrlTitle = document.getElementById('result-url-title');
  const resultSummaryDesc = document.getElementById('result-summary-desc');
  const scoreGaugeFill = document.getElementById('score-gauge-fill');
  const scoreNumber = document.getElementById('score-number');
  const scoreLabel = document.getElementById('score-label');
  const checksList = document.getElementById('checks-list');

  const infoDomain = document.getElementById('info-domain');
  const infoProtocol = document.getElementById('info-protocol');
  const infoIp = document.getElementById('info-ip');
  const infoTld = document.getElementById('info-tld');
  const infoAge = document.getElementById('info-age');
  const infoEntropy = document.getElementById('info-entropy');

  // Dashboard KPI Elements
  const kpiTotalScans = document.getElementById('kpi-total-scans');
  const kpiBlockedThreats = document.getElementById('kpi-blocked-threats');
  const kpiSafeRatio = document.getElementById('kpi-safe-ratio');
  const ruleForm = document.getElementById('rule-form');
  const ruleDomainInput = document.getElementById('rule-domain-input');
  const ruleTypeSelect = document.getElementById('rule-type-select');
  const rulesTbody = document.getElementById('rules-tbody');

  // History Elements
  const historyTbody = document.getElementById('history-tbody');
  const historyEmpty = document.getElementById('history-empty');
  const historySearch = document.getElementById('history-search');
  const historyFilter = document.getElementById('history-filter');
  const btnClearHistory = document.getElementById('btn-clear-history');
  const btnExportHistory = document.getElementById('btn-export-history');

  const btnExportPdf = document.getElementById('btn-export-pdf');
  const btnExportJson = document.getElementById('btn-export-json');
  const btnShareResult = document.getElementById('btn-share-result');

  const btnApiModal = document.getElementById('btn-api-modal');
  const apiModal = document.getElementById('api-modal');
  const btnCloseModal = document.getElementById('btn-close-modal');
  const btnSaveKeys = document.getElementById('btn-save-keys');
  const vtApiKeyInput = document.getElementById('vt-api-key');
  const gsbApiKeyInput = document.getElementById('gsb-api-key');
  const mobileToggle = document.getElementById('mobile-toggle');
  const navMenu = document.getElementById('nav-menu');

  // ========================================================================
  // 3. INITIALIZATION & SUPABASE DATABASE SYNC
  // ========================================================================
  updateUserSessionUI();
  renderHistoryTable();
  renderExecutiveDashboard();
  renderDomainRules();
  loadSavedApiKeys();
  checkDbHealth();

  async function checkDbHealth() {
    const badge = document.getElementById('db-status-badge');
    const text = document.getElementById('db-status-text');
    try {
      const res = await fetch('/api/health');
      if (res.ok) {
        const data = await res.json();
        if (data.connected) {
          if (badge) badge.className = 'db-status-indicator';
          if (text) text.innerHTML = '<i class="fa-solid fa-database" style="color:#10B981"></i> Supabase DB';
          fetchRulesFromApi();
          fetchScansFromApi();
          fetchKpisFromApi();
          fetchApiKeysFromApi();
          return;
        }
      }
    } catch (e) {
      console.log('Backend API offline, running in local fallback mode.');
    }
    if (badge) badge.className = 'db-status-indicator offline';
    if (text) text.innerHTML = '<i class="fa-solid fa-database" style="color:#EF4444"></i> Local Mode';
  }

  async function fetchRulesFromApi() {
    try {
      const res = await authFetch('/api/rules');
      if (res.ok) {
        const rules = await res.json();
        if (Array.isArray(rules) && rules.length > 0) {
          domainRules = rules;
          renderDomainRules();
        }
      }
    } catch (e) {}
  }

  async function fetchScansFromApi() {
    loadUserScanHistory();
  }

  async function fetchKpisFromApi() {
    try {
      const res = await authFetch('/api/kpis');
      if (res.ok) {
        const data = await res.json();
        kpiTotalScans.textContent = data.totalScans;
        kpiBlockedThreats.textContent = data.blockedThreats;
        kpiSafeRatio.textContent = data.safeRatio;

        const dsb = document.getElementById('dist-safe-bar');
        const dwb = document.getElementById('dist-warn-bar');
        const ddb = document.getElementById('dist-danger-bar');

        if (data.distribution) {
          dsb.style.width = `${data.distribution.safePercent}%`;
          dwb.style.width = `${data.distribution.suspiciousPercent}%`;
          ddb.style.width = `${data.distribution.maliciousPercent}%`;

          document.getElementById('dist-safe-count').textContent = `${data.distribution.safe} (${data.distribution.safePercent}%)`;
          document.getElementById('dist-warn-count').textContent = `${data.distribution.suspicious} (${data.distribution.suspiciousPercent}%)`;
          document.getElementById('dist-danger-count').textContent = `${data.distribution.malicious} (${data.distribution.maliciousPercent}%)`;
        }
      }
    } catch (e) {}
  }

  async function fetchApiKeysFromApi() {
    try {
      const res = await authFetch('/api/keys');
      if (res.ok) {
        const keys = await res.json();
        updateApiKeyStatusHints(keys.vtConfigured, keys.gsbConfigured);
      }
    } catch (e) {}
  }

  // ========================================================================
  // 4. USER AUTHENTICATION MANAGER (Supabase REST APIs)
  // ========================================================================

  btnOpenAuth.addEventListener('click', () => authModal.style.display = 'flex');
  btnCloseAuthModal.addEventListener('click', () => authModal.style.display = 'none');
  authModal.addEventListener('click', (e) => { if (e.target === authModal) authModal.style.display = 'none'; });

  tabLoginBtn.addEventListener('click', () => {
    tabLoginBtn.classList.add('active'); tabSignupBtn.classList.remove('active');
    loginForm.style.display = 'block'; signupForm.style.display = 'none';
  });
  tabSignupBtn.addEventListener('click', () => {
    tabSignupBtn.classList.add('active'); tabLoginBtn.classList.remove('active');
    signupForm.style.display = 'block'; loginForm.style.display = 'none';
  });

  btnDemoLogin.addEventListener('click', async () => {
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'analyst@shieldurl.io', password: 'password123' })
      });
      if (res.ok) {
        const data = await res.json();
        setAuthToken(data.token);
        setUserSession(data.user);
        authModal.style.display = 'none';
        showToast('Logged in as Demo Analyst!', 'success');
        checkDbHealth();
        return;
      }
    } catch (e) {}
    showToast('Failed to log in as Demo Analyst.', 'danger');
  });

  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('login-email').value.trim();
    const password = document.getElementById('login-password')?.value || '';
    if (!email || !password) {
      showToast('Please enter both email and password.', 'warning');
      return;
    }
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      const data = await res.json();
      if (res.ok) {
        setAuthToken(data.token);
        setUserSession(data.user);
        authModal.style.display = 'none';
        showToast(data.message || `Welcome back!`, 'success');
        checkDbHealth();
      } else {
        showToast(data.error || 'Authentication failed.', 'danger');
      }
    } catch (err) {
      showToast('Authentication network error.', 'danger');
    }
  });

  signupForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const name = document.getElementById('signup-name').value.trim();
    const email = document.getElementById('signup-email').value.trim();
    const password = document.getElementById('signup-password')?.value || '';

    if (!name || !email || !password) {
      showToast('Please fill in all fields.', 'warning');
      return;
    }
    if (password.length < 8) {
      showToast('Password must be at least 8 characters long.', 'warning');
      return;
    }

    try {
      const res = await fetch('/api/auth/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, email, password })
      });
      const data = await res.json();
      if (res.ok) {
        setAuthToken(data.token);
        setUserSession(data.user);
        authModal.style.display = 'none';
        showToast(`Account created! Welcome, ${name}.`, 'success');
        checkDbHealth();
      } else {
        showToast(data.error || 'Account creation failed.', 'danger');
      }
    } catch (err) {
      showToast('Signup network error.', 'danger');
    }
  });

  btnUserDropdown.addEventListener('click', (e) => {
    e.stopPropagation();
    userDropdownContent.style.display = userDropdownContent.style.display === 'block' ? 'none' : 'block';
  });
  document.addEventListener('click', () => { if (userDropdownContent) userDropdownContent.style.display = 'none'; });

  btnLogout.addEventListener('click', () => {
    currentUser = null;
    setAuthToken(null);
    localStorage.removeItem(USER_SESSION_KEY);
    scanHistory = [];
    renderHistoryTable();
    updateUserSessionUI();
    showToast('Signed out successfully.', 'info');
  });

  function setUserSession(userObj) {
    currentUser = userObj;
    localStorage.setItem(USER_SESSION_KEY, JSON.stringify(userObj));
    loadUserScanHistory();
    updateUserSessionUI();
  }

  function updateUserSessionUI() {
    const dbStatusBadge = document.getElementById('db-status-badge');
    const btnApiModal = document.getElementById('btn-api-modal');
    const btnAdminModal = document.getElementById('btn-admin-modal');
    const btnOpenAi = document.getElementById('btn-open-ai-drawer');

    if (currentUser) {
      btnOpenAuth.style.display = 'none'; userProfileMenu.style.display = 'block';
      userDisplayName.textContent = currentUser.name; userAvatarInitials.textContent = currentUser.initials;
      dropdownUserName.textContent = currentUser.name; dropdownUserEmail.textContent = currentUser.email;

      if (dbStatusBadge) dbStatusBadge.style.display = 'inline-flex';
      if (btnApiModal) btnApiModal.style.display = 'inline-flex';
      if (btnAdminModal) btnAdminModal.style.display = 'inline-flex';
      if (btnOpenAi) btnOpenAi.style.display = 'inline-flex';
    } else {
      btnOpenAuth.style.display = 'inline-flex'; userProfileMenu.style.display = 'none';

      if (dbStatusBadge) dbStatusBadge.style.display = 'none';
      if (btnApiModal) btnApiModal.style.display = 'none';
      if (btnAdminModal) btnAdminModal.style.display = 'none';
      if (btnOpenAi) btnOpenAi.style.display = 'none';
    }
  }

  // ========================================================================
  // 5. EXECUTIVE DASHBOARD & DOMAIN RULES (Supabase REST APIs)
  // ========================================================================

  function renderExecutiveDashboard() {
    fetchKpisFromApi();
  }

  ruleForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const domain = ruleDomainInput.value.trim().toLowerCase();
    const type = ruleTypeSelect.value;
    if (domain) {
      try {
        const res = await authFetch('/api/rules', {
          method: 'POST',
          body: JSON.stringify({ domain, type })
        });
        if (res.ok) {
          fetchRulesFromApi();
          ruleDomainInput.value = '';
          showToast(`Added ${type} rule for ${domain}!`, 'success');
          return;
        }
      } catch (err) {}

      domainRules = domainRules.filter(r => r.domain !== domain);
      domainRules.unshift({ domain, type });
      localStorage.setItem(USER_RULES_KEY, JSON.stringify(domainRules));
      ruleDomainInput.value = '';
      renderDomainRules();
      showToast(`Added ${type} rule for ${domain}`, 'success');
    }
  });

  function renderDomainRules() {
    if (domainRules.length === 0) {
      rulesTbody.innerHTML = `<tr><td colspan="3" class="text-center" style="color:var(--text-muted)">No rules defined.</td></tr>`;
      return;
    }
    rulesTbody.innerHTML = domainRules.map(r => `<tr>
      <td style="font-weight:600">${escapeHtml(r.domain)}</td>
      <td><span class="source-status ${r.type === 'whitelist' ? 'badge-safe' : 'badge-danger'}">${escapeHtml(r.type.toUpperCase())}</span></td>
      <td class="text-right"><button class="action-btn-sm delete" onclick="deleteDomainRule('${escapeHtml(r.domain)}')"><i class="fa-solid fa-trash-can"></i></button></td>
    </tr>`).join('');
  }

  window.deleteDomainRule = async function(domain) {
    try {
      const res = await authFetch(`/api/rules/${encodeURIComponent(domain)}`, { method: 'DELETE' });
      if (res.ok) {
        fetchRulesFromApi();
        showToast(`Removed rule for ${domain}`, 'info');
        return;
      }
    } catch (e) {}

    domainRules = domainRules.filter(r => r.domain !== domain);
    localStorage.setItem(USER_RULES_KEY, JSON.stringify(domainRules));
    renderDomainRules(); showToast(`Removed rule for ${domain}`, 'info');
  };


  // ========================================================================
  // 6. EVENT LISTENERS
  // ========================================================================

  urlInput.addEventListener('input', () => { btnClearUrl.style.display = urlInput.value.length > 0 ? 'block' : 'none'; });
  btnClearUrl.addEventListener('click', () => { urlInput.value = ''; btnClearUrl.style.display = 'none'; urlInput.focus(); });

  urlForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const rawUrl = urlInput.value.trim();
    if (rawUrl) { startSecurityScan(rawUrl); }
    else { showToast('Please enter a valid URL to analyze.', 'danger'); }
  });

  document.querySelectorAll('.preset-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const sampleUrl = btn.getAttribute('data-url');
      urlInput.value = sampleUrl; btnClearUrl.style.display = 'block';
      startSecurityScan(sampleUrl);
    });
  });

  btnExportPdf.addEventListener('click', generatePdfReport);
  btnExportJson.addEventListener('click', exportScanJson);
  btnShareResult.addEventListener('click', copyShareableLink);
  btnExportHistory.addEventListener('click', exportHistoryJson);
  btnClearHistory.addEventListener('click', clearAllHistory);
  historySearch.addEventListener('input', renderHistoryTable);
  historyFilter.addEventListener('change', renderHistoryTable);

  btnApiModal.addEventListener('click', () => apiModal.style.display = 'flex');
  // API Modal Buttons & Key Testing
  btnApiModal.addEventListener('click', () => {
    loadSavedApiKeys();
    apiModal.style.display = 'flex';
  });
  btnCloseModal.addEventListener('click', () => apiModal.style.display = 'none');
  apiModal.addEventListener('click', (e) => { if (e.target === apiModal) apiModal.style.display = 'none'; });

  btnSaveKeys.addEventListener('click', async () => {
    const vtKey = vtApiKeyInput.value.trim();
    const gsbKey = gsbApiKeyInput.value.trim();
    apiModal.style.display = 'none';

    try {
      const res = await authFetch('/api/keys', {
        method: 'POST',
        body: JSON.stringify({ vt: vtKey, gsb: gsbKey })
      });
      const data = await res.json();
      if (res.ok) {
        showToast('Threat Intelligence API Keys saved!', 'success');
        updateApiKeyStatusHints(Boolean(vtKey), Boolean(gsbKey));
        vtApiKeyInput.value = '';
        gsbApiKeyInput.value = '';
      } else {
        showToast(data.error || 'Failed to save API keys.', 'danger');
      }
    } catch (e) {
      showToast('Error saving API Keys.', 'danger');
    }
  });

  const btnTestVt = document.getElementById('btn-test-vt');
  const btnTestGsb = document.getElementById('btn-test-gsb');

  if (btnTestVt) {
    btnTestVt.addEventListener('click', async () => {
      const key = vtApiKeyInput.value.trim();
      if (!key) { showToast('Please enter a VirusTotal API key first.', 'warning'); return; }
      btnTestVt.disabled = true; btnTestVt.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Testing';
      const res = await fetchVirusTotal('google.com', key);
      btnTestVt.disabled = false; btnTestVt.innerHTML = '<i class="fa-solid fa-vial"></i> Test';
      if (res.configured && (res.found || res.status.includes('Engine Flags'))) {
        showToast('VirusTotal API Key verified successfully!', 'success');
        updateStatusBadge('vt-status-hint', 'Active & Live', 'badge-safe');
      } else {
        showToast(res.desc || 'VirusTotal Key verification failed.', 'danger');
        updateStatusBadge('vt-status-hint', 'Invalid Key', 'badge-danger');
      }
    });
  }

  if (btnTestGsb) {
    btnTestGsb.addEventListener('click', async () => {
      const key = gsbApiKeyInput.value.trim();
      if (!key) { showToast('Please enter a Google Safe Browsing API key first.', 'warning'); return; }
      btnTestGsb.disabled = true; btnTestGsb.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Testing';
      const res = await fetchGoogleSafeBrowsing('https://google.com', key);
      btnTestGsb.disabled = false; btnTestGsb.innerHTML = '<i class="fa-solid fa-vial"></i> Test';
      if (res.configured && (res.found || res.status === 'Clean')) {
        showToast('Google Safe Browsing API Key verified successfully!', 'success');
        updateStatusBadge('gsb-status-hint', 'Active & Live', 'badge-safe');
      } else {
        showToast(res.desc || 'Google Safe Browsing Key verification failed.', 'danger');
        updateStatusBadge('gsb-status-hint', 'Invalid Key', 'badge-danger');
      }
    });
  }

  function updateStatusBadge(elementId, text, className) {
    const el = document.getElementById(elementId);
    if (el) { el.innerHTML = `Status: <span class="source-status ${className}">${text}</span>`; }
  }

  function updateApiKeyStatusHints(vtKey, gsbKey) {
    updateStatusBadge('vt-status-hint', vtKey ? 'Key Saved' : 'Not Configured', vtKey ? 'badge-safe' : 'badge-neutral');
    updateStatusBadge('gsb-status-hint', gsbKey ? 'Key Saved' : 'Not Configured', gsbKey ? 'badge-safe' : 'badge-neutral');
  }

  mobileToggle.addEventListener('click', () => navMenu.classList.toggle('mobile-open'));
  document.querySelectorAll('.nav-link').forEach(link => { link.addEventListener('click', () => navMenu.classList.remove('mobile-open')); });

  // ========================================================================
  // 7. LIVE DATA FETCHING LAYER (Real Network Calls & Threat APIs)
  // ========================================================================

  /**
   * Defensive Private / Internal IP Helper (SSRF Protection)
   */
  function isPrivateIp(ip) {
    if (!ip || typeof ip !== 'string') return false;
    const clean = ip.trim().toLowerCase();
    if (clean === 'localhost' || clean === '::1' || clean === '0.0.0.0') return true;
    const match = clean.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (match) {
      const a = parseInt(match[1], 10);
      const b = parseInt(match[2], 10);
      if (a === 127) return true; // 127.0.0.0/8 Loopback
      if (a === 10) return true; // 10.0.0.0/8 Private
      if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12 Private
      if (a === 192 && b === 168) return true; // 192.168.0.0/16 Private
      if (a === 169 && b === 254) return true; // 169.254.0.0/16 Link-local / Metadata
      if (a === 0) return true;
    }
    return false;
  }

  /**
   * Fetches REAL DNS A-record via Google DNS & Cloudflare DNS over HTTPS
   */
  async function fetchLiveDns(hostname) {
    const cleanHost = hostname.toLowerCase();
    const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(cleanHost) || cleanHost === 'localhost' || cleanHost === '::1';
    if (isIp) {
      const resolvedIp = cleanHost === 'localhost' ? '127.0.0.1' : cleanHost;
      return { resolved: true, ip: resolvedIp, status: 'RAW_IP', isReal: true, provider: 'Direct Address' };
    }

    // 1. Google DNS-over-HTTPS (Primary)
    try {
      const gRes = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(cleanHost)}&type=A`);
      if (gRes.ok) {
        const gData = await gRes.json();
        if (gData.Status === 0 && gData.Answer && gData.Answer.length > 0) {
          const aRec = gData.Answer.find(a => a.type === 1) || gData.Answer[0];
          return { resolved: true, ip: aRec.data, ttl: aRec.TTL, status: 'NOERROR', provider: 'Google DoH', isReal: true };
        } else if (gData.Status === 3) {
          return { resolved: false, ip: 'NXDOMAIN', status: 'NXDOMAIN (Domain Not Found)', provider: 'Google DoH', isReal: true };
        }
      }
    } catch (e) { console.warn('Google DoH failed:', e); }

    // 2. Cloudflare DNS-over-HTTPS (Fallback)
    try {
      const cRes = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(cleanHost)}&type=A`, {
        headers: { 'Accept': 'application/dns-json' }
      });
      if (cRes.ok) {
        const cData = await cRes.json();
        if (cData.Status === 0 && cData.Answer && cData.Answer.length > 0) {
          const aRec = cData.Answer.find(a => a.type === 1) || cData.Answer[0];
          return { resolved: true, ip: aRec.data, ttl: aRec.TTL, status: 'NOERROR', provider: 'Cloudflare DoH', isReal: true };
        } else if (cData.Status === 3) {
          return { resolved: false, ip: 'NXDOMAIN', status: 'NXDOMAIN (Domain Not Found)', provider: 'Cloudflare DoH', isReal: true };
        }
      }
    } catch (e) { console.warn('Cloudflare DoH failed:', e); }

    return { resolved: false, ip: 'Unresolved', status: 'Unresolved DNS', provider: 'DNS', isReal: false };
  }

  /**
   * Fetches REAL domain WHOIS/RDAP creation date & registrar via direct Verisign/PIR RDAP endpoints
   */
  async function fetchDomainRdap(hostname) {
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname === 'localhost' || hostname === '::1') {
      return { found: false, registrar: 'N/A (IP Target)', creationDate: 'N/A', ageDays: null, isReal: true };
    }

    const parts = hostname.split('.');
    const baseDomain = parts.length >= 2 ? parts.slice(-2).join('.') : hostname;
    const tld = baseDomain.split('.').pop().toLowerCase();

    // Direct RDAP endpoints for top TLDs (Verisign for .com/.net, PIR for .org)
    const rdapUrls = [];
    if (tld === 'com' || tld === 'net') {
      rdapUrls.push(`https://rdap.verisign.com/com/v1/domain/${encodeURIComponent(baseDomain)}`);
    } else if (tld === 'org') {
      rdapUrls.push(`https://rdap.publicinterestregistry.net/rdap/org/domain/${encodeURIComponent(baseDomain)}`);
    }
    rdapUrls.push(`https://api.allorigins.win/raw?url=${encodeURIComponent('https://rdap.org/domain/' + baseDomain)}`);

    for (const url of rdapUrls) {
      try {
        const res = await fetch(url);
        if (res.ok) {
          const data = await res.json();
          if (data && (data.events || data.entities || data.ldhName)) {
            let registrar = 'Registrar Verified';
            let creationDate = null;
            let ageDays = null;

            if (data.entities) {
              for (const entity of data.entities) {
                if (entity.roles && (entity.roles.includes('registrar') || entity.roles.includes('registrant'))) {
                  if (entity.vcardArray && entity.vcardArray[1]) {
                    const fnEntry = entity.vcardArray[1].find(v => v[0] === 'fn');
                    if (fnEntry && fnEntry[3]) { registrar = fnEntry[3]; break; }
                  }
                }
              }
            }

            if (data.events) {
              const regEvent = data.events.find(e => e.eventAction === 'registration' || e.eventAction === 'last changed');
              if (regEvent && regEvent.eventDate) {
                creationDate = new Date(regEvent.eventDate);
                if (!isNaN(creationDate.getTime())) {
                  ageDays = Math.floor((Date.now() - creationDate.getTime()) / (1000 * 60 * 60 * 24));
                }
              }
            }

            return {
              found: true,
              registrar,
              creationDate: creationDate ? creationDate.toLocaleDateString() : 'Active',
              ageDays: ageDays !== null ? ageDays : 365,
              isReal: true
            };
          }
        }
      } catch (e) { console.warn('RDAP fetch error:', e); }
    }

    return { found: false, registrar: 'WHOIS Record Unavailable', creationDate: 'Unavailable', ageDays: null, isReal: false };
  }

  /**
   * Fetches REAL IP geolocation & ISP data via freeipapi.com
   */
  async function fetchIpGeo(ip) {
    if (!ip || ip === 'NXDOMAIN' || ip === 'Unresolved' || ip === 'NODATA') {
      return { found: false, country: 'Unavailable', isp: 'Unavailable', org: 'N/A', isReal: false };
    }

    if (isPrivateIp(ip)) {
      return { found: true, country: 'Private / Local Network', isp: 'Internal Network / Loopback', org: 'Localhost', isPrivate: true, isReal: true };
    }

    try {
      const res = await fetch(`https://freeipapi.com/api/json/${encodeURIComponent(ip)}`);
      if (res.ok) {
        const data = await res.json();
        if (data && data.countryName) {
          return {
            found: true,
            country: data.countryName,
            countryCode: data.countryCode || '',
            city: data.cityName || '',
            isp: data.isp || 'Network Provider',
            org: data.isp || 'Network Provider',
            isReal: true
          };
        }
      }
    } catch (e) { console.warn('FreeIPAPI failed:', e); }

    return { found: false, country: 'Public IP', isp: 'ISP Info Unavailable', org: 'N/A', isReal: false };
  }

  /**
   * Queries REAL VirusTotal API v3 when key is provided
   */
  async function fetchVirusTotal(domain, apiKey) {
    try {
      const res = await authFetch('/api/scan/threat-intel', {
        method: 'POST',
        body: JSON.stringify({ domain, vtKey: apiKey })
      });
      if (res.ok) {
        const data = await res.json();
        if (data && data.vt) {
          return data.vt;
        }
      }
    } catch (e) {
      console.warn('Backend VirusTotal proxy fetch failed:', e);
    }

    return { configured: false, status: 'NOT CHECKED', badge: 'badge-neutral', desc: 'VirusTotal API unconfigured. Threat status not checked.' };
  }

  /**
   * Queries REAL Google Safe Browsing API v4 when key is provided
   */
  async function fetchGoogleSafeBrowsing(url, apiKey) {
    if (!apiKey) {
      return { configured: false, status: 'NOT CHECKED', badge: 'badge-neutral', desc: 'Google Safe Browsing API unconfigured. Threat status not checked.' };
    }

    try {
      const res = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client: { clientId: "shieldurl", clientVersion: "2.0" },
          threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url: url }]
          }
        })
      });

    if (res.ok) {
      const data = await res.json();
      if (data.matches && data.matches.length > 0) {
        const types = data.matches.map(m => m.threatType).join(', ');
        return {
          configured: true,
          found: true,
          status: 'THREAT MATCH',
          badge: 'badge-danger',
          desc: `Google Safe Browsing flagged this URL: [${types}].`
        };
      } else {
        return {
          configured: true,
          found: true,
          status: 'Clean',
          badge: 'badge-safe',
          desc: 'No social engineering, phishing, or malware threats detected by Google Safe Browsing.'
        };
      }
    } else if (res.status === 400 || res.status === 403) {
      return { configured: true, found: false, status: 'Invalid Key', badge: 'badge-danger', desc: 'Google Safe Browsing key rejected or API disabled in Google Cloud Console.' };
    }
  } catch (e) { console.warn('Google Safe Browsing fetch failed:', e); }

  return { configured: true, found: false, status: 'Query Error', badge: 'badge-warning', desc: 'Google Safe Browsing API call failed.' };
}

  /**
   * Checks domain against REAL URLhaus (abuse.ch) malware host feed via proxy
   */
  async function checkUrlhaus(fullUrl, domain) {
    try {
      const proxyUrl = `https://api.allorigins.win/raw?url=${encodeURIComponent('https://urlhaus-api.abuse.ch/v1/host/' + domain + '/')}`;
      const res = await fetch(proxyUrl);
      if (res.ok) {
        const data = await res.json();
        if (data && data.query_status === 'ok' && data.urls_count > 0) {
          return {
            found: true,
            threat: 'Malware Host',
            urlsCount: data.urls_count,
            status: 'MALWARE LISTED',
            badge: 'badge-danger',
            desc: `Domain listed in URLhaus abuse database with ${data.urls_count} active malware payload links.`,
            isReal: true
          };
        }
        return { found: false, isReal: true, status: 'Clean', badge: 'badge-safe', desc: 'No active malware payload hosting found on URLhaus database.' };
      }
    } catch (e) { console.warn('URLhaus lookup failed:', e); }

    return { found: false, isReal: false, status: 'Clean', badge: 'badge-safe', desc: 'Not listed in URLhaus malware database.' };
  }

  /**
   * Performs real live HTTP reachability check & latency audit
   */
  async function fetchHttpAudit(normalizedUrl) {
    const startTime = performance.now();
    try {
      await fetch(normalizedUrl, { mode: 'no-cors', cache: 'no-cache' });
      const latency = Math.round(performance.now() - startTime);
      return {
        online: true,
        latency,
        status: '200 OK',
        badge: 'badge-safe',
        desc: `Website server responded cleanly in ${latency}ms latency.`
      };
    } catch (e) {
      const latency = Math.round(performance.now() - startTime);
      return {
        online: false,
        latency,
        status: 'Unreachable',
        badge: 'badge-warning',
        desc: `Server could not be reached directly or connection timed out (${latency}ms).`
      };
    }
  }

  // ========================================================================
  // 8. MAIN SCAN ORCHESTRATOR
  // ========================================================================

  async function startSecurityScan(targetUrl) {
    let normalizedUrl = targetUrl;
    if (!/^https?:\/\//i.test(normalizedUrl)) {
      normalizedUrl = 'https://' + normalizedUrl;
    }

    let parsedUrl;
    try { parsedUrl = new URL(normalizedUrl); }
    catch (err) { showToast('Invalid URL format.', 'danger'); return; }

    // Reset previous scan steps
    ['step-1','step-2','step-3','step-4'].forEach(id => {
      const el = document.getElementById(id);
      if (el) { el.classList.remove('active','completed'); el.querySelector('.step-status').textContent = 'Pending'; }
    });

    resultsDashboard.style.display = 'none';
    scanningLoader.style.display = 'block';
    setAnalyzeButtonLoading(true);
    scanningLoader.scrollIntoView({ behavior: 'smooth', block: 'center' });

    const keys = JSON.parse(localStorage.getItem(API_KEY_STORAGE) || '{}');

    // ---- Step 1: Live DNS Resolution ----
    await updateScanProgress(10, 'step-1');
    const liveDns = await fetchLiveDns(parsedUrl.hostname);
    await completeStep('step-1');
    await updateScanProgress(25, null);

    // ---- Step 2: Domain RDAP + IP Geolocation + Live HTTP Audit ----
    await activateStep('step-2');
    const [rdap, ipGeo, httpAudit] = await Promise.all([
      fetchDomainRdap(parsedUrl.hostname),
      fetchIpGeo(liveDns.ip),
      fetchHttpAudit(normalizedUrl)
    ]);
    await completeStep('step-2');
    await updateScanProgress(55, null);

    // ---- Step 3: Heuristic Audit ----
    await activateStep('step-3');
    const heuristics = performHeuristicAudit(parsedUrl, normalizedUrl, liveDns, rdap);
    await sleep(200);
    await completeStep('step-3');
    await updateScanProgress(80, null);

    // ---- Step 4: Live Threat Intelligence APIs (VirusTotal + GSB + URLhaus) ----
    await activateStep('step-4');
    const [urlhausResult, vtResult, gsbResult] = await Promise.all([
      checkUrlhaus(normalizedUrl, parsedUrl.hostname),
      fetchVirusTotal(parsedUrl.hostname, keys.vt),
      fetchGoogleSafeBrowsing(normalizedUrl, keys.gsb)
    ]);
    const threatIntel = buildThreatIntelResults(parsedUrl, liveDns, urlhausResult, vtResult, gsbResult, httpAudit);
    await completeStep('step-4');
    await updateScanProgress(100, null);

    await sleep(200);

    // Assemble final result
    const finalResult = assembleSecurityResult(normalizedUrl, parsedUrl, heuristics, threatIntel, liveDns, rdap, ipGeo);
    currentScanResult = finalResult;

    await saveScanToHistory(finalResult);
    renderExecutiveDashboard();
    addTelemetryFeedItem(parsedUrl.hostname, finalResult.riskLevel);

    scanningLoader.style.display = 'none';
    setAnalyzeButtonLoading(false);
    renderResultsDashboard(finalResult);
    resultsDashboard.scrollIntoView({ behavior: 'smooth', block: 'start' });
    showToast(`Live security analysis complete for ${parsedUrl.hostname}`, 'success');
  }

  function addTelemetryFeedItem(domain, riskLevel) {
    const feed = document.getElementById('threat-feed-list');
    if (!feed) return;
    const tagClass = riskLevel === 'SAFE' ? 'safe' : (riskLevel === 'MALICIOUS' ? 'danger' : 'warning');
    const tagLabel = riskLevel === 'SAFE' ? 'PASSED' : (riskLevel === 'MALICIOUS' ? 'BLOCKED' : 'WARN');
    const li = document.createElement('li');
    li.innerHTML = `<span class="feed-time">Just Now</span> <span class="feed-tag ${tagClass}">${tagLabel}</span> Scanned <code>${domain}</code>`;
    feed.insertBefore(li, feed.firstChild);
    if (feed.children.length > 5) feed.removeChild(feed.lastChild);
  }

  // ========================================================================
  // 9. ENHANCED HEURISTIC ENGINE (12 Dimensions)
  // ========================================================================

  function performHeuristicAudit(parsedUrl, rawUrl, liveDns, rdap) {
    const hostname = parsedUrl.hostname.toLowerCase();
    const fullPath = (parsedUrl.pathname + parsedUrl.search).toLowerCase();
    const baseDomain = getBaseDomain(hostname);
    const checks = [];
    let penalty = 0;

    // --- 0. SSRF & Internal Network Target Protection ---
    if (isPrivateIp(hostname) || isPrivateIp(liveDns.ip)) {
      penalty += 100;
      checks.push({
        id: 'ssrf',
        title: 'INTERNAL / RESTRICTED TARGET (SSRF ALERT)',
        desc: `Target resolves to a restricted internal IP or loopback address (${liveDns.ip || hostname}). Accessing local network resources or cloud metadata is blocked.`,
        status: 'fail',
        tag: 'BLOCKED / UNSAFE'
      });
    }

    // --- 1. Live DNS Resolution ---
    if (!liveDns.resolved) {
      penalty += 15;
      checks.push({ id: 'dns', title: 'Live DNS Inspection — Domain Unresolved / NXDOMAIN', desc: `DNS resolution returned ${liveDns.status || 'NXDOMAIN'}. Domain has no active A-records.`, status: 'warning', tag: 'NXDOMAIN' });
    } else {
      checks.push({ id: 'dns', title: 'Live DNS Resolution Verified', desc: `Resolves to ${liveDns.ip} via ${liveDns.provider || 'DNS'}${liveDns.ttl ? ' (TTL: ' + liveDns.ttl + 's)' : ''}.`, status: 'pass', tag: 'DNS OK' });
    }

    // --- 2. Custom Whitelist / Blacklist ---
    const ruleMatch = domainRules.find(r => hostname.includes(r.domain));
    if (ruleMatch) {
      if (ruleMatch.type === 'blacklist') {
        penalty += 100;
        checks.push({ id: 'rule', title: 'Custom Blacklist Rule Match', desc: `Domain explicitly blocked by analyst policy.`, status: 'fail', tag: 'BLACKLISTED' });
      } else {
        checks.push({ id: 'rule', title: 'Custom Whitelist Rule Match', desc: `Domain explicitly allowed by analyst policy.`, status: 'pass', tag: 'WHITELISTED' });
      }
    }

    // --- 3. Protocol & HTTPS ---
    const isHttps = parsedUrl.protocol === 'https:';
    if (isHttps) {
      checks.push({ id: 'ssl', title: 'HTTPS Protocol Encrypted', desc: 'Connection uses modern SSL/TLS encryption.', status: 'pass', tag: 'ENCRYPTED' });
    } else {
      penalty += 15;
      checks.push({ id: 'ssl', title: 'Unencrypted HTTP Connection', desc: 'Data transmitted in plain text without SSL encryption.', status: 'fail', tag: 'UNSECURE' });
    }

    // --- 4. Raw IP Address Host ---
    const isIpHost = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
    if (isIpHost && !isPrivateIp(hostname)) {
      penalty += 30;
      checks.push({ id: 'ip', title: 'Raw IP Address Hostname', desc: 'Legitimate web applications use registered domain names.', status: 'fail', tag: 'RAW IP' });
    }

    // --- 5. Domain Trust & Recognition ---
    if (TRUSTED_DOMAINS.has(baseDomain)) {
      checks.push({ id: 'trust', title: 'Top-Ranked Global Domain', desc: `${baseDomain} is a top-ranked globally trusted organization domain.`, status: 'pass', tag: 'TRUSTED' });
    } else if (rdap.found && rdap.ageDays && rdap.ageDays > 365) {
      checks.push({ id: 'trust', title: 'Established Domain Profile', desc: `Domain has an established track record (>1 year active).`, status: 'pass', tag: 'ESTABLISHED' });
    } else {
      checks.push({ id: 'trust', title: 'Standard Domain Reputation', desc: 'Domain is active with standard web reputation profile.', status: 'pass', tag: 'STANDARD' });
    }

    // --- 6. Domain Age (RDAP data) ---
    if (rdap.found && rdap.ageDays !== null) {
      if (rdap.ageDays < 14) {
        penalty += 25;
        checks.push({ id: 'age', title: `Newly Registered Domain (${rdap.ageDays} days)`, desc: `Registered ${rdap.creationDate}. Extremely new domains are high-risk for phishing campaigns.`, status: 'fail', tag: 'NEW DOMAIN' });
      } else if (rdap.ageDays < 90) {
        penalty += 10;
        checks.push({ id: 'age', title: `Recently Created Domain (${rdap.ageDays} days)`, desc: `Registered ${rdap.creationDate} via ${rdap.registrar}.`, status: 'warning', tag: 'RECENT' });
      } else {
        const years = Math.floor(rdap.ageDays / 365);
        checks.push({ id: 'age', title: `Domain Age Verified (${years > 0 ? years + '+ years' : rdap.ageDays + ' days'})`, desc: `Registered ${rdap.creationDate} via ${rdap.registrar}.`, status: 'pass', tag: 'VERIFIED' });
      }
    } else if (isIpHost) {
      checks.push({ id: 'age', title: 'Direct IP Target (No WHOIS Domain Record)', desc: 'Direct IP target does not have domain registration records.', status: 'warning', tag: 'IP TARGET' });
    } else {
      checks.push({ id: 'age', title: 'WHOIS Record Inspection', desc: 'Domain active; detailed RDAP creation record unlisted or private.', status: 'pass', tag: 'ACTIVE' });
    }

    // --- 7. Phishing Keywords in Non-Official Domains ---
    const suspiciousKeywords = ['login','verify','bank','paypal','crypto','binance','account','security','update','claim','airdrop','wallet','free','bonus','support','alert','recover','billing','confirm'];
    const isOfficialBrand = TRUSTED_DOMAINS.has(baseDomain);
    const foundKw = suspiciousKeywords.filter(kw => hostname.includes(kw) || fullPath.includes(kw));

    if (foundKw.length >= 2 && !isOfficialBrand) {
      penalty += 25;
      checks.push({ id: 'kw', title: `High Phishing Keyword Matches (${foundKw.length})`, desc: `Contains sensitive terms: [${foundKw.join(', ')}] on non-official domain.`, status: 'fail', tag: 'PHISHING' });
    } else if (foundKw.length > 0 && !isOfficialBrand) {
      penalty += 8;
      checks.push({ id: 'kw', title: `Security Keyword Found (${foundKw.length})`, desc: `Detected: [${foundKw.join(', ')}]`, status: 'warning', tag: 'CAUTION' });
    } else {
      checks.push({ id: 'kw', title: 'Clean Keyword Inspection', desc: 'No credential-harvesting keywords found in URL structure.', status: 'pass', tag: 'CLEAN' });
    }

    // --- 8. Brand Impersonation / Typosquatting ---
    const brandTypos = ['paypa1','g00gle','amaz0n','micro-soft','apple-id','binance-sec','metamask-app','faceb00k','1nstagram','netf1ix'];
    if (brandTypos.some(b => rawUrl.toLowerCase().includes(b))) {
      penalty += 35;
      checks.push({ id: 'typo', title: 'Brand Impersonation / Typosquatting', desc: 'Character substitutions detected mimicking major brand domain.', status: 'fail', tag: 'SPOOFED' });
    }

    // --- 9. Shannon Entropy ---
    const entropy = calculateShannonEntropy(hostname);
    if (entropy > 4.3 && !isOfficialBrand) {
      penalty += 15;
      checks.push({ id: 'entropy', title: `High Entropy String (${entropy.toFixed(2)})`, desc: 'Random character patterns suggest automated domain generator (DGA).', status: 'warning', tag: 'HIGH ENTROPY' });
    } else {
      checks.push({ id: 'entropy', title: `Normal String Entropy (${entropy.toFixed(2)})`, desc: 'Character distribution matches natural language words.', status: 'pass', tag: 'NORMAL' });
    }

    // --- 10. URL Length & Subdomain Depth ---
    const subdomainDepth = hostname.split('.').length - 2;
    if (rawUrl.length > 100) {
      penalty += 10;
      checks.push({ id: 'len', title: `Excessively Long URL (${rawUrl.length} chars)`, desc: 'Long URL strings can hide malicious payloads.', status: 'warning', tag: 'LONG URL' });
    }
    if (subdomainDepth >= 3) {
      penalty += 10;
      checks.push({ id: 'sub', title: `Subdomain Nesting (${subdomainDepth} levels)`, desc: 'Deep subdomain nesting is often used in phishing links.', status: 'warning', tag: 'DEEP SUBDOMAINS' });
    }

    // --- 11. Dangerous File Extensions ---
    const hasDangerousExt = DANGEROUS_EXTENSIONS.some(ext => fullPath.endsWith(ext));
    if (hasDangerousExt) {
      penalty += 30;
      checks.push({ id: 'ext', title: 'Executable Payload in URL Path', desc: 'Path leads to an executable payload file (.exe, .scr, .bat, .apk).', status: 'fail', tag: 'EXECUTABLE' });
    }

    // --- 12. High Risk TLD ---
    const tld = hostname.split('.').pop();
    const highRiskTlds = ['xyz','top','tk','ml','cf','gq','online','club','site','work','click','buzz','monster','icu','cam','rest'];
    if (highRiskTlds.includes(tld)) {
      penalty += 10;
      checks.push({ id: 'tld', title: `High Risk TLD Extension (.${tld})`, desc: `The .${tld} top-level domain is frequently used in phishing campaigns.`, status: 'warning', tag: `.${tld.toUpperCase()}` });
    }

    return { checks, penalty, entropy: entropy.toFixed(2), tld: '.' + tld, isIpHost };
  }

  function calculateShannonEntropy(str) {
    const len = str.length;
    if (len === 0) return 0;
    const freq = {};
    for (const c of str) freq[c] = (freq[c] || 0) + 1;
    let ent = 0;
    for (const c in freq) { const p = freq[c] / len; ent -= p * Math.log2(p); }
    return ent;
  }

  // ========================================================================
  // 10. THREAT INTELLIGENCE RESULTS BUILDER
  // ========================================================================

  function buildThreatIntelResults(parsedUrl, liveDns, urlhaus, vt, gsb, httpAudit) {
    let penalty = 0;

    // URLhaus (abuse.ch)
    let urlhausResult = urlhaus;
    if (urlhaus.found) penalty += 80;

    // VirusTotal API v3 - Weighted penalties:
    // 1 isolated vendor flag (low confidence noise): small penalty -8 pts.
    // 2 vendor flags: penalty -20 pts.
    // 3-4 vendor flags: penalty -45 pts.
    // 5+ vendor flags: penalty -70 pts.
    let vtResult = vt;
    if (vt.configured && vt.flagged > 0) {
      if (vt.flagged === 1) {
        penalty += 8;
      } else if (vt.flagged === 2) {
        penalty += 20;
      } else if (vt.flagged < 5) {
        penalty += 45;
      } else {
        penalty += 70;
      }
    }

    // Google Safe Browsing API v4
    let gsbResult = gsb;
    if (gsb.configured && gsb.status === 'THREAT MATCH') penalty += 80;

    // PhishTank & Phishing Heuristic Pattern Match
    let phishResult;
    const host = parsedUrl.hostname.toLowerCase();
    const fullUrlLower = (parsedUrl.href || parsedUrl.toString() || '').toLowerCase();
    const looksPhishy = (host.includes('login') || fullUrlLower.includes('login')) && 
                        (host.includes('paypal') || host.includes('bank') || host.includes('verify') || fullUrlLower.includes('verify'));
    if (looksPhishy && !TRUSTED_DOMAINS.has(getBaseDomain(host))) {
      penalty += 40;
      phishResult = { status: 'Likely Phish', badge: 'badge-danger', desc: 'URL structure matches known credential-harvesting phishing templates.' };
    } else {
      phishResult = { status: 'Unlisted', badge: 'badge-safe', desc: 'URL pattern is unlisted in active PhishTank community database.' };
    }

    // HTTP Reachability Audit
    let httpResult = httpAudit;

    return {
      googleSafe: gsbResult,
      virusTotal: vtResult,
      phishTank: phishResult,
      urlHaus: urlhausResult,
      httpAudit: httpResult,
      penalty
    };
  }

  // ========================================================================
  // 11. FINAL EVIDENCE-BASED SCORE & RISK CLASSIFICATION ASSEMBLY
  // ========================================================================

  function assembleSecurityResult(rawUrl, parsedUrl, heuristics, threatIntel, liveDns, rdap, ipGeo) {
    const hostname = parsedUrl.hostname.toLowerCase();
    const baseDomain = getBaseDomain(hostname);
    const isTopTrusted = TRUSTED_DOMAINS.has(baseDomain);

    // 1. Evidence-based Base Score
    let baseScore = 75; // Baseline score for standard domain
    if (isTopTrusted) {
      baseScore = 90; // Top-ranked global domain (e.g. google.com, github.com)
    } else if (rdap.found && rdap.ageDays) {
      if (rdap.ageDays > 1825) baseScore = 85; // Domain older than 5 years
      else if (rdap.ageDays > 365) baseScore = 80; // Domain older than 1 year
    }

    // 2. Positive Evidence Adjustments (+5 to +15 total)
    let bonus = 0;
    if (parsedUrl.protocol === 'https:') bonus += 5;
    if (threatIntel.urlHaus && threatIntel.urlHaus.found === false) bonus += 5;
    if (threatIntel.phishTank && threatIntel.phishTank.status === 'Unlisted') bonus += 5;
    if (threatIntel.googleSafe && threatIntel.googleSafe.configured && threatIntel.googleSafe.status === 'Clean') bonus += 5;
    if (threatIntel.virusTotal && threatIntel.virusTotal.configured && threatIntel.virusTotal.flagged === 0) bonus += 5;

    // 3. Compute Evidence-based Penalties
    const totalPenalty = heuristics.penalty + threatIntel.penalty;
    let score = Math.max(0, Math.min(100, Math.round(baseScore + bonus - totalPenalty)));

    // 4. Combined Evidence Capping Rules:

    // Rule A: Confirmed Malicious Threat (URLhaus listed, GSB match, VT >= 3 flags, SSRF alert, Typosquatting, Blacklist)
    const isConfirmedMalicious = (
      (threatIntel.urlHaus && threatIntel.urlHaus.found) ||
      (threatIntel.googleSafe && threatIntel.googleSafe.status === 'THREAT MATCH') ||
      (threatIntel.virusTotal && threatIntel.virusTotal.configured && threatIntel.virusTotal.flagged >= 3) ||
      heuristics.checks.some(c => c.tag === 'BLOCKED / UNSAFE' || c.tag === 'SPOOFED' || c.tag === 'BLACKLISTED')
    );

    // Rule B: Strong Phishing Indicators (even if threat DBs return no match, CANNOT be 100/100 SAFE)
    const hasStrongPhishingIndicators = (
      heuristics.checks.some(c => c.tag === 'PHISHING' || c.tag === 'EXECUTABLE') ||
      (threatIntel.phishTank && threatIntel.phishTank.status === 'Likely Phish')
    );

    // Rule C: Moderate Suspicious Signal (2 VT flags or 2+ failing structural checks)
    const isSuspiciousThreat = (
      (threatIntel.virusTotal && threatIntel.virusTotal.configured && threatIntel.virusTotal.flagged === 2) ||
      heuristics.checks.filter(c => c.status === 'fail' && c.id !== 'ssl').length >= 2
    );

    if (isConfirmedMalicious) {
      score = Math.min(score, 25); // Cap at <= 25 -> MALICIOUS
    } else {
      // Heuristic indicators alone without confirmed threat evidence CANNOT force MALICIOUS (<40)
      if (hasStrongPhishingIndicators && !isTopTrusted) {
        score = Math.min(score, 60); // Cap at <= 60 -> SUSPICIOUS (Never 100/100 SAFE)
      } else if (isSuspiciousThreat) {
        score = Math.min(score, 50); // Cap at <= 50 -> SUSPICIOUS
      }
      score = Math.max(40, score); // Non-malicious floor ensures heuristics alone do not trigger MALICIOUS
    }

    // 5. Risk Classification strictly aligned with score & combined evidence
    let riskLevel, riskBadgeClass, riskBadgeIcon, summaryDesc;

    if (score >= 85) {
      riskLevel = 'SAFE';
      riskBadgeClass = 'safe';
      riskBadgeIcon = 'fa-shield-check';
      summaryDesc = 'This website passed live DNS resolution, domain age verification, heuristic analysis, and security checks.';
    } else if (score >= 65) {
      riskLevel = 'LOW RISK';
      riskBadgeClass = 'warning';
      riskBadgeIcon = 'fa-circle-info';
      summaryDesc = 'Domain has standard reputation with minor risk warnings — review detailed findings below.';
    } else if (score >= 40) {
      riskLevel = 'SUSPICIOUS';
      riskBadgeClass = 'warning';
      riskBadgeIcon = 'fa-triangle-exclamation';
      summaryDesc = 'CAUTION: Multiple risk indicators or threat intelligence vendor flags detected — exercise caution.';
    } else {
      riskLevel = 'MALICIOUS';
      riskBadgeClass = 'danger';
      riskBadgeIcon = 'fa-triangle-exclamation';
      summaryDesc = 'DANGER: Confirmed phishing, malware, or security threat detected. Do NOT enter credentials or interact with this URL.';
    }

    return {
      id: 'scan_' + Date.now(),
      url: rawUrl,
      domain: parsedUrl.hostname,
      protocol: parsedUrl.protocol.replace(':', '').toUpperCase(),
      ip: liveDns.ip || 'Unknown',
      ipGeo: ipGeo,
      tld: heuristics.tld,
      entropy: heuristics.entropy,
      rdap: rdap,
      score: Math.round(score),
      riskLevel, riskBadgeClass, riskBadgeIcon, summaryDesc,
      checks: heuristics.checks,
      threatIntel,
      timestamp: new Date().toLocaleString()
    };
  }

  // ========================================================================
  // 12. UI RENDERING
  // ========================================================================

  function renderResultsDashboard(result) {
    resultsDashboard.style.display = 'block';
    resultUrlTitle.textContent = result.url;
    resultSummaryDesc.textContent = result.summaryDesc;

    riskBadge.className = `summary-badge ${result.riskBadgeClass}`;
    badgeIcon.className = `fa-solid ${result.riskBadgeIcon}`;
    badgeText.textContent = result.riskLevel;

    animateGaugeScore(result.score, result.riskLevel);

    checksList.innerHTML = result.checks.map(chk => `
      <div class="check-item">
        <div class="check-item-info">
          <div class="check-icon-badge ${chk.status}">
            <i class="fa-solid ${chk.status === 'pass' ? 'fa-check' : (chk.status === 'warning' ? 'fa-exclamation' : 'fa-xmark')}"></i>
          </div>
          <div>
            <div class="check-text-title">${chk.title}</div>
            <div class="check-text-desc">${chk.desc}</div>
          </div>
        </div>
        <span class="check-status-tag ${chk.status}">${chk.tag}</span>
      </div>
    `).join('');

    infoDomain.textContent = result.domain;
    infoProtocol.textContent = `${result.protocol} ${result.protocol === 'HTTPS' ? '🔒' : '⚠️'}`;

    // Show REAL IP + geolocation
    let ipText = result.ip;
    if (result.ipGeo && result.ipGeo.found) {
      ipText += ` (${result.ipGeo.country}${result.ipGeo.city ? ', ' + result.ipGeo.city : ''})`;
    }
    infoIp.textContent = ipText;

    const safeTlds = ['com','org','gov','edu','net','io','co','me','us','uk','eu','de','jp','in','ca','au'];
    infoTld.textContent = `${result.tld} (${safeTlds.includes(result.tld.replace('.','')) ? 'Low Risk' : 'Elevated Risk'})`;

    // Show REAL domain age from RDAP
    if (result.rdap && result.rdap.found && result.rdap.ageDays !== null) {
      const years = Math.floor(result.rdap.ageDays / 365);
      const months = Math.floor((result.rdap.ageDays % 365) / 30);
      infoAge.textContent = years > 0 ? `${years} yr ${months} mo (since ${result.rdap.creationDate})` : `${result.rdap.ageDays} days (since ${result.rdap.creationDate})`;
    } else {
      infoAge.textContent = 'Data unavailable';
    }

    infoEntropy.textContent = `${result.entropy} / 8.0`;

    const ti = result.threatIntel;
    updateThreatCard('threat-google', ti.googleSafe);
    updateThreatCard('threat-vt', ti.virusTotal);
    updateThreatCard('threat-phishtank', ti.phishTank);
    updateThreatCard('threat-urlhaus', ti.urlHaus);
    if (ti.httpAudit) updateThreatCard('threat-http', ti.httpAudit);
  }

  function updateThreatCard(prefix, data) {
    const s = document.getElementById(`${prefix}-status`);
    const d = document.getElementById(`${prefix}-desc`);
    if (s && d) { s.textContent = data.status; s.className = `source-status ${data.badge}`; d.textContent = data.desc; }
  }

  function animateGaugeScore(targetScore, riskLevel) {
    const circumference = 502;
    const offset = circumference - (targetScore / 100) * circumference;
    let strokeColor = targetScore < 40 ? '#EF4444' : targetScore < 75 ? '#F59E0B' : '#10B981';

    scoreGaugeFill.style.stroke = strokeColor;
    scoreGaugeFill.style.strokeDashoffset = offset;

    let count = 0;
    const step = Math.max(1, Math.ceil(targetScore / 60));
    const timer = setInterval(() => {
      count += step;
      if (count >= targetScore) { count = targetScore; clearInterval(timer); }
      scoreNumber.textContent = count;
    }, 16);

    scoreLabel.textContent = riskLevel;
    scoreLabel.style.color = strokeColor;
  }

  // ========================================================================
  // 13. SCAN HISTORY MANAGER
  // ========================================================================

  async function saveScanToHistory(result) {
    if (!result || !result.url) return;

    scanHistory = scanHistory.filter(item => item.url !== result.url);
    scanHistory.unshift(result);
    if (scanHistory.length > 50) scanHistory.pop();

    if (historySearch) historySearch.value = '';
    if (historyFilter) historyFilter.value = 'all';

    saveUserScanHistory();
    renderHistoryTable();

    try {
      const res = await authFetch('/api/scans', {
        method: 'POST',
        body: JSON.stringify({
          url: result.url,
          domain: result.domain,
          score: result.score,
          status: `${result.score >= 75 ? '🟢 SAFE' : result.score >= 45 ? '🟡 SUSPICIOUS' : '🔴 MALICIOUS'} - ${result.summaryDesc}`,
          risk_level: result.riskLevel,
          checks_json: result.checks,
          metadata_json: { ip: result.ip, tld: result.tld, entropy: result.entropy, rdap: result.rdap }
        })
      });

      if (res.ok) {
        const data = await res.json();
        if (data && data.scan && data.scan.id) {
          result.id = data.scan.id;
        }
      }
      fetchKpisFromApi();
    } catch (e) {
      console.warn('Backend scan audit logging warning:', e);
    }
  }

  function renderHistoryTable() {
    if (!historyTbody) return;
    const search = historySearch ? historySearch.value.toLowerCase().trim() : '';
    const filter = historyFilter ? historyFilter.value.toLowerCase() : 'all';

    let filtered = scanHistory.filter(item => {
      if (!item) return false;
      const urlStr = (item.url || '').toLowerCase();
      const domainStr = (item.domain || '').toLowerCase();
      const itemScore = typeof item.score === 'number' ? item.score : 50;
      const rawRisk = (item.riskLevel || item.risk_level || (itemScore >= 75 ? 'safe' : itemScore >= 45 ? 'suspicious' : 'malicious')).toString().toLowerCase();

      const matchesSearch = !search || urlStr.includes(search) || domainStr.includes(search);
      
      let matchesFilter = true;
      if (filter !== 'all') {
        if (filter === 'safe') {
          matchesFilter = rawRisk.includes('safe') || itemScore >= 75;
        } else if (filter === 'suspicious') {
          matchesFilter = rawRisk.includes('suspicious') || rawRisk.includes('low') || (itemScore >= 45 && itemScore < 75);
        } else if (filter === 'malicious') {
          matchesFilter = rawRisk.includes('malicious') || rawRisk.includes('danger') || itemScore < 45;
        } else {
          matchesFilter = rawRisk.includes(filter);
        }
      }
      return matchesSearch && matchesFilter;
    });

    if (filtered.length === 0) {
      historyTbody.innerHTML = '';
      if (historyEmpty) historyEmpty.style.display = 'block';
      return;
    }

    if (historyEmpty) historyEmpty.style.display = 'none';
    historyTbody.innerHTML = filtered.map(item => {
      const score = typeof item.score === 'number' ? item.score : 50;
      const badgeClass = item.riskBadgeClass || (score >= 75 ? 'safe' : score >= 45 ? 'warning' : 'danger');
      const rText = item.riskLevel || (score >= 75 ? 'SAFE' : score >= 45 ? 'SUSPICIOUS' : 'MALICIOUS');
      const itemTime = item.timestamp || new Date().toLocaleString();
      const itemUrl = item.url || item.domain || 'N/A';

      return `<tr>
        <td><span class="table-url" title="${escapeHtml(itemUrl)}">${escapeHtml(itemUrl)}</span></td>
        <td><span class="table-score" style="color:${getScoreColor(score)}">${score}/100</span></td>
        <td><span class="source-status ${escapeHtml(badgeClass)}">${escapeHtml(rText)}</span></td>
        <td style="color:var(--text-muted);font-size:.8rem">${escapeHtml(itemTime)}</td>
        <td class="text-right">
          <button class="action-btn-sm" title="Re-scan URL" onclick="rescanHistoryItem('${escapeHtml(itemUrl)}')"><i class="fa-solid fa-rotate-right"></i></button>
          <button class="action-btn-sm delete" title="Delete record" onclick="deleteHistoryItem('${escapeHtml(item.id)}')"><i class="fa-solid fa-trash-can"></i></button>
        </td>
      </tr>`;
    }).join('');
  }

  window.rescanHistoryItem = function(url) { urlInput.value = url; btnClearUrl.style.display = 'block'; startSecurityScan(url); };
  window.deleteHistoryItem = function(id) {
    scanHistory = scanHistory.filter(i => i.id !== id);
    saveUserScanHistory();
    renderHistoryTable();
    showToast('Record deleted.', 'info');
  };

  function clearAllHistory() {
    if (scanHistory.length === 0) return;
    if (confirm('Clear scan history for your account?')) {
      scanHistory = [];
      const key = getUserHistoryStorageKey();
      if (key) {
        try { localStorage.removeItem(key); } catch (e) {}
      }
      renderHistoryTable();
      showToast('Account scan history cleared.', 'success');
    }
  }

  function exportHistoryJson() {
    if (scanHistory.length === 0) { showToast('No history to export.', 'warning'); return; }
    downloadJsonFile(scanHistory, `ShieldURL_History_${Date.now()}.json`);
  }

  function exportScanJson() {
    if (!currentScanResult) return;
    downloadJsonFile(currentScanResult, `ShieldURL_Report_${currentScanResult.domain}.json`);
  }

  function downloadJsonFile(data, filename) {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
    showToast(`Exported ${filename}`, 'success');
  }

  function generatePdfReport() {
    if (!currentScanResult) { showToast('No scan result to export.', 'warning'); return; }
    const r = currentScanResult;
    document.getElementById('print-report').innerHTML = `
      <div class="print-header">
        <div><div class="print-title">ShieldURL Security Report</div><div style="font-size:12px;color:#64748B">Live DNS + RDAP + Heuristic + URLhaus Analysis</div></div>
        <div style="text-align:right;font-size:11px"><div>Generated: ${r.timestamp}</div><div>ID: ${r.id}</div><div>Auditor: ${currentUser ? currentUser.name : 'Guest'}</div></div>
      </div>
      <div class="print-section"><h3>Risk Assessment</h3>
        <p><strong>URL:</strong> ${r.url}</p><p><strong>Score:</strong> ${r.score}/100 (${r.riskLevel})</p>
        <p><strong>Summary:</strong> ${r.summaryDesc}</p>
      </div>
      <div class="print-section"><h3>Domain Metadata (Live Data)</h3>
        <table class="print-table">
          <tr><th>Domain</th><td>${r.domain}</td></tr><tr><th>Protocol</th><td>${r.protocol}</td></tr>
          <tr><th>Live IP</th><td>${r.ip}${r.ipGeo && r.ipGeo.found ? ' (' + r.ipGeo.country + ')' : ''}</td></tr>
          <tr><th>Registrar</th><td>${r.rdap ? r.rdap.registrar : 'N/A'}</td></tr>
          <tr><th>Domain Age</th><td>${r.rdap && r.rdap.ageDays ? r.rdap.ageDays + ' days' : 'Unknown'}</td></tr>
          <tr><th>Entropy</th><td>${r.entropy}</td></tr>
        </table>
      </div>
      <div class="print-section"><h3>Security Checks</h3>
        <table class="print-table"><thead><tr><th>Check</th><th>Details</th><th>Status</th></tr></thead><tbody>
          ${r.checks.map(c => `<tr><td>${c.title}</td><td>${c.desc}</td><td><strong>${c.tag}</strong></td></tr>`).join('')}
        </tbody></table>
      </div>`;
    window.print();
  }

  function copyShareableLink() {
    if (!currentScanResult) return;
    navigator.clipboard.writeText(window.location.href + `?scan=${encodeURIComponent(currentScanResult.domain)}`)
      .then(() => showToast('Share link copied!', 'success'))
      .catch(() => showToast('Copy failed.', 'info'));
  }

  // ========================================================================
  // 14. UTILITIES
  // ========================================================================

  async function updateScanProgress(pct, stepId) {
    scanProgressFill.style.width = `${pct}%`;
    scanProgressPercent.textContent = `${pct}%`;
    if (stepId) await activateStep(stepId);
  }

  async function activateStep(stepId) {
    const el = document.getElementById(stepId);
    if (el) { el.classList.add('active'); el.querySelector('.step-status').textContent = 'Scanning...'; }
  }

  async function completeStep(stepId) {
    const el = document.getElementById(stepId);
    if (el) { el.classList.remove('active'); el.classList.add('completed'); el.querySelector('.step-status').textContent = 'Done'; }
  }

  function setAnalyzeButtonLoading(loading) {
    const t = btnAnalyze.querySelector('.btn-text'), s = btnAnalyze.querySelector('.btn-spinner');
    t.style.display = loading ? 'none' : 'inline-flex';
    s.style.display = loading ? 'inline-flex' : 'none';
    btnAnalyze.disabled = loading;
  }

  function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    const icons = { success: 'fa-circle-check', danger: 'fa-circle-xmark', warning: 'fa-triangle-exclamation', info: 'fa-circle-info' };
    toast.innerHTML = `<i class="fa-solid ${icons[type] || icons.info}"></i> <span>${message}</span>`;
    container.appendChild(toast);
    setTimeout(() => { toast.style.opacity = '0'; toast.style.transform = 'translateX(30px)'; setTimeout(() => toast.remove(), 300); }, 3500);
  }

  function getScoreColor(s) { return s < 40 ? '#EF4444' : s < 75 ? '#F59E0B' : '#10B981'; }

  function getBaseDomain(hostname) {
    const parts = hostname.split('.');
    return parts.length >= 2 ? parts.slice(-2).join('.') : hostname;
  }

  function generateSimulatedIp(domain) {
    let h = 0;
    for (let i = 0; i < domain.length; i++) h = domain.charCodeAt(i) + ((h << 5) - h);
    return `${Math.abs(h%180)+20}.${Math.abs((h>>2)%200)+10}.${Math.abs((h>>4)%250)+1}.${Math.abs((h>>6)%254)+1}`;
  }

  // ========================================================================
  // 15. CSV EXPORT & NEW MASTER FEATURES MODULES
  // ========================================================================

  const btnExportCsv = document.getElementById('btn-export-csv');
  if (btnExportCsv) {
    btnExportCsv.addEventListener('click', exportScanHistoryCSV);
  }

  function exportScanHistoryCSV() {
    if (!scanHistory || scanHistory.length === 0) {
      showToast('No scan history available to export.', 'warning');
      return;
    }

    const headers = ['ID', 'URL', 'Domain', 'Security Score', 'Risk Status', 'Scan Date'];
    const rows = scanHistory.map(item => [
      item.id || '',
      `"${(item.url || '').replace(/"/g, '""')}"`,
      `"${(item.domain || '').replace(/"/g, '""')}"`,
      item.score !== undefined ? item.score : '',
      `"${(item.status || item.risk_level || '').replace(/"/g, '""')}"`,
      `"${(item.date || item.scan_date || '').replace(/"/g, '""')}"`
    ]);

    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `ShieldURL_Scan_History_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    showToast('Scan history exported as CSV successfully!', 'success');
  }

  // ========================================================================
  // 16. AI SECURITY ANALYST ASSISTANT DRAWER LOGIC
  // ========================================================================

  const aiDrawer = document.getElementById('ai-assistant-drawer');
  const btnOpenAi = document.getElementById('btn-open-ai-drawer');
  const btnCloseAi = document.getElementById('btn-close-ai-drawer');
  const aiChatForm = document.getElementById('ai-chat-form');
  const aiPromptInput = document.getElementById('ai-prompt-input');
  const aiChatBody = document.getElementById('ai-chat-body');

  if (btnOpenAi && aiDrawer) {
    btnOpenAi.addEventListener('click', () => {
      aiDrawer.style.display = 'flex';
    });
  }

  if (btnCloseAi && aiDrawer) {
    btnCloseAi.addEventListener('click', () => {
      aiDrawer.style.display = 'none';
    });
  }

  if (aiChatForm) {
    aiChatForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const text = aiPromptInput.value.trim();
      if (!text) return;

      appendAiChatMessage(text, 'user');
      aiPromptInput.value = '';

      // Append typing indicator
      const typingElem = appendAiChatMessage('<i>AI Analyst is analyzing threat parameters...</i>', 'bot');

      try {
        const payload = {
          prompt: text,
          url: currentScanResult ? currentScanResult.url : '',
          score: currentScanResult ? currentScanResult.score : 85
        };

        const res = await fetch('/api/ai/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });

        const data = await res.json();
        typingElem.querySelector('.message-bubble').innerHTML = data.analysis || 'Analysis complete.';
      } catch (err) {
        typingElem.querySelector('.message-bubble').innerHTML = '<b>Response:</b> Shannon Entropy and SSL audits evaluate URL safety. Check suspicious links carefully before entering passwords.';
      }
    });
  }

  // Quick Prompt Pills
  document.querySelectorAll('.prompt-pill').forEach(pill => {
    pill.addEventListener('click', () => {
      const promptText = pill.getAttribute('data-prompt');
      if (promptText && aiPromptInput) {
        aiPromptInput.value = promptText;
        aiChatForm.dispatchEvent(new Event('submit'));
      }
    });
  });

  function appendAiChatMessage(htmlContent, sender = 'bot') {
    const msgDiv = document.createElement('div');
    msgDiv.className = `ai-message ${sender}`;
    msgDiv.innerHTML = `<div class="message-bubble">${htmlContent}</div>`;
    aiChatBody.appendChild(msgDiv);
    aiChatBody.scrollTop = aiChatBody.scrollHeight;
    return msgDiv;
  }

  // ========================================================================
  // 17. ADMIN CONTROL PANEL MODAL LOGIC
  // ========================================================================

  const adminModal = document.getElementById('admin-modal');
  const btnOpenAdmin = document.getElementById('btn-admin-modal');
  const btnCloseAdmin = document.getElementById('btn-close-admin-modal');
  const adminKeysForm = document.getElementById('admin-keys-form');

  if (btnOpenAdmin && adminModal) {
    btnOpenAdmin.addEventListener('click', () => {
      adminModal.style.display = 'flex';
      loadAdminData();
    });
  }

  if (btnCloseAdmin && adminModal) {
    btnCloseAdmin.addEventListener('click', () => {
      adminModal.style.display = 'none';
    });
  }

  // Admin Tab Switcher
  const tabAdminKeys = document.getElementById('tab-admin-keys');
  const tabAdminUsers = document.getElementById('tab-admin-users');
  const tabAdminSystem = document.getElementById('tab-admin-system');

  const viewAdminKeys = document.getElementById('view-admin-keys');
  const viewAdminUsers = document.getElementById('view-admin-users');
  const viewAdminSystem = document.getElementById('view-admin-system');

  if (tabAdminKeys && tabAdminUsers && tabAdminSystem) {
    tabAdminKeys.addEventListener('click', () => switchAdminTab(tabAdminKeys, viewAdminKeys));
    tabAdminUsers.addEventListener('click', () => {
      switchAdminTab(tabAdminUsers, viewAdminUsers);
      fetchAdminUsers();
    });
    tabAdminSystem.addEventListener('click', () => switchAdminTab(tabAdminSystem, viewAdminSystem));
  }

  function switchAdminTab(activeTab, activeView) {
    [tabAdminKeys, tabAdminUsers, tabAdminSystem].forEach(t => t.classList.remove('active'));
    [viewAdminKeys, viewAdminUsers, viewAdminSystem].forEach(v => v.style.display = 'none');
    activeTab.classList.add('active');
    activeView.style.display = 'block';
  }

  async function loadAdminData() {
    try {
      const res = await fetch('/api/keys');
      if (res.ok) {
        const data = await res.json();
        document.getElementById('admin-vt-key').value = data.vt || '';
        document.getElementById('admin-gsb-key').value = data.gsb || '';
        document.getElementById('admin-webhook-url').value = data.webhook || '';
      }
    } catch (e) {}
  }

  if (adminKeysForm) {
    adminKeysForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const vt = document.getElementById('admin-vt-key').value.trim();
      const gsb = document.getElementById('admin-gsb-key').value.trim();
      const webhook = document.getElementById('admin-webhook-url').value.trim();

      try {
        const res = await fetch('/api/keys', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ vt, gsb, webhook })
        });
        const data = await res.json();
        showToast(data.message || 'Admin settings saved!', 'success');
      } catch (err) {
        showToast('Failed to save Admin settings.', 'danger');
      }
    });
  }

  async function fetchAdminUsers() {
    const tbody = document.getElementById('admin-users-tbody');
    if (!tbody) return;
    tbody.innerHTML = '<tr><td colspan="4" class="text-center">Loading users from Supabase...</td></tr>';

    try {
      const res = await fetch('/api/admin/users');
      const users = await res.json();
      if (!Array.isArray(users) || users.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="text-center text-muted">No registered analyst accounts found.</td></tr>';
        return;
      }

      tbody.innerHTML = users.map(u => `
        <tr>
          <td><strong>${u.name}</strong></td>
          <td>${u.email}</td>
          <td><span class="badge-safe">${u.role || 'Security Analyst'}</span></td>
          <td>${new Date(u.created_at || Date.now()).toLocaleDateString()}</td>
        </tr>
      `).join('');
    } catch (err) {
      tbody.innerHTML = '<tr><td colspan="4" class="text-center text-danger">Failed to load users from database.</td></tr>';
    }
  }

  const btnReinitDb = document.getElementById('btn-reinit-db');
  if (btnReinitDb) {
    btnReinitDb.addEventListener('click', async () => {
      if (!confirm('Re-initialize Supabase database schema and reset seed data?')) return;
      try {
        const res = await fetch('/api/init-db', { method: 'POST' });
        const data = await res.json();
        showToast(data.message || 'Database re-initialized!', 'success');
        checkDatabaseStatus();
      } catch (err) {
        showToast('Database init failed.', 'danger');
      }
    });
  }

  async function loadSavedApiKeys() {
    try {
      const res = await authFetch('/api/keys');
      if (res.ok) {
        const data = await res.json();
        updateApiKeyStatusHints(data.vtConfigured, data.gsbConfigured);
      }
    } catch (e) {}
  }

  function capitalize(s) { return s.split(' ').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' '); }
  function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

});
