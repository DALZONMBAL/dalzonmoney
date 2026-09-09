const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const db = new Database(
  process.env.DB_PATH || "./dalzon.db"
);

db.pragma("journal_mode = WAL");

// ===============================
// CONFIGURATION ADMIN
// ===============================

const ADMIN_EMAIL =
  process.env.ADMIN_EMAIL || "admin@dalzon.local";

const ADMIN_PASSWORD =
  process.env.ADMIN_PASSWORD || "DalzonAdmin2026!";

// ===============================
// CRÉATION DES TABLES
// ===============================

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS wallets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER UNIQUE NOT NULL,
    cdf INTEGER NOT NULL DEFAULT 0,
    usd_cents INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS cards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER UNIQUE NOT NULL,
    card_number TEXT UNIQUE NOT NULL,
    expiry TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    currency TEXT NOT NULL,
    amount_cdf INTEGER DEFAULT 0,
    amount_usd_cents INTEGER DEFAULT 0,
    description TEXT,
    reference TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

// ===============================
// GÉNÉRATEUR ACCOUNT ID
// ===============================

function generateAccountId() {
  let accountId;

  do {
    const year = new Date().getFullYear();

    accountId =
      `DLZ-${year}-` +
      crypto.randomInt(100000, 1000000);

  } while (
    db.prepare(
      "SELECT id FROM users WHERE account_id = ?"
    ).get(accountId)
  );

  return accountId;
}

// ===============================
// GÉNÉRATEUR CARTE
// ===============================

function generateCardNumber() {
  let cardNumber;

  do {
    const part1 = crypto.randomInt(1000, 10000);
    const part2 = crypto.randomInt(1000, 10000);
    const part3 = crypto.randomInt(1000, 10000);
    const part4 = crypto.randomInt(1000, 10000);

    cardNumber =
      `${part1} ${part2} ${part3} ${part4}`;

  } while (
    db.prepare(
      "SELECT id FROM cards WHERE card_number = ?"
    ).get(cardNumber)
  );

  return cardNumber;
}

// ===============================
// DATE D'EXPIRATION
// ===============================

function generateExpiry() {
  const date = new Date();

  date.setFullYear(
    date.getFullYear() + 4
  );

  const month =
    String(date.getMonth() + 1).padStart(2, "0");

  const year =
    String(date.getFullYear()).slice(-2);

  return `${month}/${year}`;
}

// ===============================
// VÉRIFICATION ADMIN EXISTANT
// ===============================

const existingAdmin = db.prepare(`
  SELECT id, account_id, email
  FROM users
  WHERE email = ?
     OR role = 'admin'
  LIMIT 1
`).get(ADMIN_EMAIL);

if (existingAdmin) {
  console.log("");
  console.log("======================================");
  console.log("   ADMIN DALZON EXISTE DÉJÀ");
  console.log("======================================");
  console.log("Account ID :", existingAdmin.account_id);
  console.log("Email      :", existingAdmin.email);
  console.log("======================================");
  console.log("");

  db.close();
  process.exit(0);
}

// ===============================
// HASH MOT DE PASSE
// ===============================

const passwordHash =
  bcrypt.hashSync(
    ADMIN_PASSWORD,
    12
  );

// ===============================
// CRÉATION ADMIN + WALLET + CARTE
// ===============================

const createAdmin = db.transaction(() => {

  const accountId =
    generateAccountId();

  const result = db.prepare(`
    INSERT INTO users (
      account_id,
      name,
      email,
      password_hash,
      role,
      status
    )
    VALUES (?, ?, ?, ?, 'admin', 'active')
  `).run(
    accountId,
    "Administrateur DALZON",
    ADMIN_EMAIL,
    passwordHash
  );

  const userId =
    result.lastInsertRowid;

  // Portefeuille
  db.prepare(`
    INSERT INTO wallets (
      user_id,
      cdf,
      usd_cents
    )
    VALUES (?, 0, 0)
  `).run(userId);

  // Carte virtuelle de simulation
  db.prepare(`
    INSERT INTO cards (
      user_id,
      card_number,
      expiry,
      status
    )
    VALUES (?, ?, ?, 'active')
  `).run(
    userId,
    generateCardNumber(),
    generateExpiry()
  );

  return {
    userId,
    accountId
  };
});

const admin =
  createAdmin();

// ===============================
// RÉSULTAT
// ===============================

console.log("");
console.log("======================================");
console.log("      DALZON WALLET v2.2");
console.log("      ADMIN CRÉÉ AVEC SUCCÈS");
console.log("======================================");
console.log("");
console.log("Nom        : Administrateur DALZON");
console.log("Account ID :", admin.accountId);
console.log("Email      :", ADMIN_EMAIL);
console.log("Rôle       : ADMIN");
console.log("Statut     : ACTIVE");
console.log("");
console.log("Portefeuille : Créé");
console.log("Carte        : Créée");
console.log("");
console.log("======================================");
console.log("⚠️  CONSERVEZ VOS IDENTIFIANTS");
console.log("======================================");
console.log("");

db.close();