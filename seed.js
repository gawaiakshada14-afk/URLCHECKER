const fs = require('fs');
const path = require('path');
const { query, testConnection, pool } = require('./db');

async function runSeed() {
  console.log('================================================================');
  console.log('🚀 INITIALIZING SUPABASE POSTGRESQL DATABASE (SCHEMA & SEED)');
  console.log('================================================================');

  // 1. Test database connection
  const connStatus = await testConnection();
  if (!connStatus.connected) {
    console.error('❌ Database Connection Failed:', connStatus.error);
    process.exit(1);
  }

  console.log(`✅ Connected to Supabase Database: ${connStatus.database}`);
  console.log(`⏱️ Server Time: ${connStatus.timestamp}`);

  try {
    // 2. Read and execute schema.sql
    const schemaPath = path.join(__dirname, 'schema.sql');
    const schemaSql = fs.readFileSync(schemaPath, 'utf8');
    console.log('\n📦 Applying Database Schema from schema.sql...');
    await query(schemaSql);
    console.log('✅ Database Schema created successfully!');

    // 3. Read and execute seed.sql
    const seedPath = path.join(__dirname, 'seed.sql');
    const seedSql = fs.readFileSync(seedPath, 'utf8');
    console.log('\n🌱 Populating Seed Data from seed.sql...');
    await query(seedSql);
    console.log('✅ Seed data inserted successfully!');

    // 4. Verify table row counts
    const usersCount = await query('SELECT COUNT(*) FROM users;');
    const rulesCount = await query('SELECT COUNT(*) FROM domain_rules;');
    const scansCount = await query('SELECT COUNT(*) FROM scan_history;');
    const keysCount = await query('SELECT COUNT(*) FROM api_keys;');

    console.log('\n================================================================');
    console.log('📊 SUPABASE DATABASE INITIALIZATION SUMMARY');
    console.log('================================================================');
    console.log(`👤 Users:        ${usersCount.rows[0].count} records`);
    console.log(`🛡️ Domain Rules: ${rulesCount.rows[0].count} rules`);
    console.log(`🔍 Scan Audits:  ${scansCount.rows[0].count} scans`);
    console.log(`🔑 API Key Config: ${keysCount.rows[0].count} configs`);
    console.log('================================================================\n');

  } catch (error) {
    console.error('❌ Database Seeding Failed:', error);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

if (require.main === module) {
  runSeed();
}

module.exports = runSeed;
