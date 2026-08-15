const { Pool } = require('pg');
require('dotenv').config();

const connectionString = process.env.DATABASE_URL;

if (!connectionString) {
  console.error('[Database Error] CRITICAL: DATABASE_URL environment variable is not defined.');
}

console.log('[Database] Connecting to Supabase PostgreSQL...');

const pool = new Pool({
  connectionString,
  ssl: {
    rejectUnauthorized: false // Required for Supabase cloud PostgreSQL connections
  },
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 30000,
  max: 20
});

pool.on('error', (err) => {
  console.error('[Database] Unexpected error on idle Supabase PostgreSQL client:', err);
});

/**
 * Executes a query with logging and error reporting
 */
async function query(text, params) {
  const start = Date.now();
  try {
    const res = await pool.query(text, params);
    const duration = Date.now() - start;
    // Log query execution time for optimization tracking
    if (process.env.NODE_ENV !== 'test') {
      console.log(`[Database Query] executed in ${duration}ms | rows: ${res.rowCount}`);
    }
    return res;
  } catch (error) {
    console.error('[Database Error] Query failed:', { text, error: error.message });
    throw error;
  }
}

/**
 * Tests direct connectivity to Supabase PostgreSQL
 */
async function testConnection() {
  try {
    const res = await pool.query('SELECT NOW() as current_time, current_database() as db_name, version() as pg_version;');
    return {
      connected: true,
      timestamp: res.rows[0].current_time,
      database: res.rows[0].db_name,
      version: res.rows[0].pg_version
    };
  } catch (error) {
    return {
      connected: false,
      error: error.message
    };
  }
}

module.exports = {
  pool,
  query,
  testConnection
};
