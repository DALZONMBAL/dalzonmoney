const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const db = new Database("./dalzon.db");

db.pragma("journal_mode = WAL");

const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "admin@dalzon.local";
const ADMIN_PASSWORD =
    process.env.ADMIN_PASSWORD || "DalzonAdmin2026!";

function generateAccountId() {
    let id;

    do {
        id =
            "DLZ-ADMIN-" +
            crypto.randomInt(1000, 9999);
    } while (
        db.prepare(
            "SELECT id FROM users WHERE account_id = ?"
        ).get(id)
    );

    return id;
}

const existing = db.prepare(`
    SELECT id
    FROM users
    WHERE email = ?
`).get(ADMIN_EMAIL);

if (existing) {
    console.log("Le compte administrateur existe déjà.");
    process.exit(0);
}

const passwordHash =
    bcrypt.hashSync(ADMIN_PASSWORD, 12);

const accountId =
    generateAccountId();

const createAdmin = db.transaction(() => {

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

    db.prepare(`
        INSERT INTO wallets (
            user_id,
            cdf,
            usd_cents
        )
        VALUES (?, 0, 0)
    `).run(userId);

    return userId;
});

createAdmin();

console.log("");
console.log("=================================");
console.log("   ADMIN DALZON CRÉÉ");
console.log("=================================");
console.log("Identifiant :", accountId);
console.log("Email       :", ADMIN_EMAIL);
console.log("=================================");
console.log("");