-- ============================================================================
-- ShieldURL Supabase PostgreSQL Seed Data
-- Database Initial Seeding Script
-- ============================================================================

-- Insert Default Analyst Users
INSERT INTO users (name, email, password_hash, role, initials) VALUES
('Alex Security Analyst', 'analyst@shieldurl.io', '$2a$10$wT0lQ.pL8f/c9G6W5k9Uae.w.m4.w6k6/6Q3w5e6.w6k6/6Q3w5e6', 'Senior Cybersec Specialist', 'AS'),
('Sarah Jenkins', 's.jenkins@cyberdefense.org', '$2a$10$wT0lQ.pL8f/c9G6W5k9Uae.w.m4.w6k6/6Q3w5e6.w6k6/6Q3w5e6', 'Lead Threat Analyst', 'SJ'),
('Demo User', 'demo@shieldurl.io', '$2a$10$wT0lQ.pL8f/c9G6W5k9Uae.w.m4.w6k6/6Q3w5e6.w6k6/6Q3w5e6', 'Security Analyst', 'DU');

-- Insert Initial Custom Domain Rules (Whitelist / Blacklist)
INSERT INTO domain_rules (user_id, domain, type) VALUES
(1, 'google.com', 'whitelist'),
(1, 'github.com', 'whitelist'),
(1, 'microsoft.com', 'whitelist'),
(1, 'phishing-login-fake.net', 'blacklist'),
(1, 'secure-bank-update-verify.com', 'blacklist');

-- Insert Sample Threat Audit Scan History (Safe, Suspicious, Malicious)
INSERT INTO scan_history (user_id, url, domain, score, status, risk_level, checks_json, metadata_json, scan_date) VALUES
(
    1,
    'https://github.com/security/advisories',
    'github.com',
    98,
    '🟢 SAFE',
    'Safe',
    '[{"name": "Custom Domain Rule Check", "passed": true, "details": "Explicitly Whitelisted domain override."},{"name": "SSL Protocol Enforcement", "passed": true, "details": "Valid HTTPS secure connection."},{"name": "Shannon Entropy Analysis", "passed": true, "details": "Entropy 3.42 (Normal)."}]'::jsonb,
    '{"ip": "140.82.121.4", "tld": "com", "protocol": "https:", "age": "Established (2007)", "entropy": 3.42}'::jsonb,
    CURRENT_TIMESTAMP - INTERVAL '2 hours'
),
(
    1,
    'https://google.com',
    'google.com',
    100,
    '🟢 SAFE',
    'Safe',
    '[{"name": "Custom Domain Rule Check", "passed": true, "details": "Explicitly Whitelisted domain override."},{"name": "Google Safe Browsing", "passed": true, "details": "No threats reported by GSB engine."}]'::jsonb,
    '{"ip": "142.250.190.46", "tld": "com", "protocol": "https:", "age": "Established (1997)", "entropy": 2.85}'::jsonb,
    CURRENT_TIMESTAMP - INTERVAL '1 hour'
),
(
    1,
    'http://192.168.1.100/login-verify-account.php',
    '192.168.1.100',
    25,
    '🔴 MALICIOUS',
    'Malicious',
    '[{"name": "Raw IP Hostname Detected", "passed": false, "details": "Suspicious raw IPv4 address used in URL."},{"name": "SSL Protocol Audit", "passed": false, "details": "Unencrypted HTTP connection."},{"name": "Phishing Keyword Scan", "passed": false, "details": "Triggered terms: login, verify, account."}]'::jsonb,
    '{"ip": "192.168.1.100", "tld": "IP", "protocol": "http:", "age": "Raw IP", "entropy": 4.88}'::jsonb,
    CURRENT_TIMESTAMP - INTERVAL '30 minutes'
),
(
    1,
    'http://paypa1-secure-account-login.xyz/auth',
    'paypa1-secure-account-login.xyz',
    15,
    '🔴 MALICIOUS',
    'Malicious',
    '[{"name": "Brand Typosquatting", "passed": false, "details": "Impersonates PayPal with paypa1."},{"name": "High-Risk TLD", "passed": false, "details": "Suspicious .xyz TLD extension."},{"name": "High Shannon Entropy", "passed": false, "details": "Randomized domain name entropy 4.95."}]'::jsonb,
    '{"ip": "185.220.101.5", "tld": "xyz", "protocol": "http:", "age": "New Domain (2 days)", "entropy": 4.95}'::jsonb,
    CURRENT_TIMESTAMP - INTERVAL '10 minutes'
),
(
    1,
    'http://free-crypto-giveaway-2026.click/claim',
    'free-crypto-giveaway-2026.click',
    52,
    '🟡 SUSPICIOUS',
    'Suspicious',
    '[{"name": "High Risk Keywords", "passed": false, "details": "Triggered terms: crypto, giveaway, claim."},{"name": "SSL Audit", "passed": false, "details": "Missing SSL certificate."}]'::jsonb,
    '{"ip": "104.21.55.12", "tld": "click", "protocol": "http:", "age": "15 days", "entropy": 3.92}'::jsonb,
    CURRENT_TIMESTAMP - INTERVAL '5 minutes'
);

-- Insert Default API Keys Entry
INSERT INTO api_keys (user_id, vt_key, gsb_key) VALUES
(1, '', '');
