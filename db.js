const path = require('path');
const fs = require('fs');
const sqlite3 = require('sqlite3');
const { open } = require('sqlite');

const dataDir = path.join(__dirname, 'data');
const dbPath = path.join(dataDir, 'auth.sqlite');

let db;

async function getDb() {
  if (!db) {
    fs.mkdirSync(dataDir, { recursive: true });

    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });

    await db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
    `);
  }

  return db;
}

module.exports = { getDb };
