"use strict";

const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

/* =========================================================
   DALZON WALLET
   SERVER v3.0
   Création du premier administrateur depuis l'application
   ========================================================= */

const app = express();

const PORT = process.env.PORT || 3000;

const JWT_SECRET =
  process.env.JWT_SECRET ||
  "CHANGE-ME-DALZON-WALLET-JWT-SECRET";

const DB_PATH =
  process.env.DB_PATH || "./dalzon.db";

/* =========================================================
   MIDDLEWARE
   ========================================================= */

app.use(express.json({ limit: "1mb" }));

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept, Authorization"
  );
  res.header(
    "Access-Control-Allow-Methods",
    "GET, POST, PUT, PATCH, DELETE, OPTIONS"
  );

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

/* =========================================================
   DATABASE
   ========================================================= */

const db = new Database(DB_PATH);

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

/* =========================================================
   TABLES
   ========================================================= */

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
    FOREIGN KEY (user_id)
      REFERENCES users(id)
      ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS cards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER UNIQUE NOT NULL,
    card_number TEXT UNIQUE NOT NULL,
    expiry TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    FOREIGN KEY (user_id)
      REFERENCES users(id)
      ON DELETE CASCADE
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
    FOREIGN KEY (user_id)
      REFERENCES users(id)
      ON DELETE CASCADE
  );
`);

/* =========================================================
   HELPERS
   ========================================================= */

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

function generateCardNumber() {
  let cardNumber;

  do {
    const p1 = crypto.randomInt(1000, 10000);
    const p2 = crypto.randomInt(1000, 10000);
    const p3 = crypto.randomInt(1000, 10000);
    const p4 = crypto.randomInt(1000, 10000);

    cardNumber =
      `${p1} ${p2} ${p3} ${p4}`;

  } while (
    db.prepare(
      "SELECT id FROM cards WHERE card_number = ?"
    ).get(cardNumber)
  );

  return cardNumber;
}

function generateExpiry() {
  const date = new Date();

  date.setFullYear(
    date.getFullYear() + 4
  );

  const month =
    String(date.getMonth() + 1)
      .padStart(2, "0");

  const year =
    String(date.getFullYear())
      .slice(-2);

  return `${month}/${year}`;
}

function generateReference(prefix = "DLZ") {
  return (
    `${prefix}-` +
    Date.now() +
    "-" +
    crypto.randomBytes(4)
      .toString("hex")
      .toUpperCase()
  );
}

function normalizeEmail(email) {
  return String(email || "")
    .trim()
    .toLowerCase();
}

function cleanName(name) {
  return String(name || "")
    .trim()
    .replace(/\s+/g, " ");
}

function isPositiveInteger(value) {
  return (
    Number.isInteger(value) &&
    value > 0
  );
}

function isValidMoney(value) {
  return (
    Number.isInteger(value) &&
    value > 0
  );
}

function publicUser(user) {
  if (!user) return null;

  return {
    id: user.id,
    account_id: user.account_id,
    name: user.name,
    email: user.email,
    role: user.role,
    status: user.status,
    created_at: user.created_at
  };
}

function getUserById(id) {
  return db.prepare(`
    SELECT *
    FROM users
    WHERE id = ?
  `).get(id);
}

function getWallet(userId) {
  return db.prepare(`
    SELECT *
    FROM wallets
    WHERE user_id = ?
  `).get(userId);
}

function getCard(userId) {
  return db.prepare(`
    SELECT *
    FROM cards
    WHERE user_id = ?
  `).get(userId);
}

function getAccountData(userId) {
  const user = getUserById(userId);

  if (!user) {
    return null;
  }

  const wallet = getWallet(userId);
  const card = getCard(userId);

  return {
    id: user.id,
    account_id: user.account_id,
    name: user.name,
    email: user.email,
    role: user.role,
    status: user.status,
    created_at: user.created_at,

    wallet: {
      CDF: wallet ? wallet.cdf : 0,
      USD: wallet
        ? wallet.usd_cents / 100
        : 0
    },

    card: card
      ? {
          id: card.id,
          number: card.card_number,
          expiry: card.expiry,
          status: card.status
        }
      : null
  };
}

/* =========================================================
   AUTHENTICATION
   ========================================================= */

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      role: user.role,
      account_id: user.account_id
    },
    JWT_SECRET,
    {
      expiresIn: "30d"
    }
  );
}

function authenticateToken(req, res, next) {
  const header =
    req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({
      ok: false,
      message: "Authentification requise."
    });
  }

  const token =
    header.substring(7);

  try {
    const decoded =
      jwt.verify(token, JWT_SECRET);

    const user =
      getUserById(decoded.id);

    if (!user) {
      return res.status(401).json({
        ok: false,
        message: "Compte introuvable."
      });
    }

    if (user.status !== "active") {
      return res.status(403).json({
        ok: false,
        message: "Ce compte est bloqué."
      });
    }

    req.user = user;

    next();

  } catch (error) {
    return res.status(401).json({
      ok: false,
      message: "Session invalide ou expirée."
    });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user) {
    return res.status(401).json({
      ok: false,
      message: "Authentification requise."
    });
  }

  if (req.user.role !== "admin") {
    return res.status(403).json({
      ok: false,
      message: "Accès administrateur refusé."
    });
  }

  next();
}

/* =========================================================
   ROOT / HEALTH
   ========================================================= */

app.get("/", (req, res) => {
  res.json({
    ok: true,
    name: "DALZON Wallet",
    version: "3.0.0",
    mode: "educational-simulation",
    message: "DALZON Wallet API opérationnelle."
  });
});

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    service: "DALZON Wallet",
    version: "3.0.0",
    database: "connected",
    time: new Date().toISOString()
  });
});

/* =========================================================
   ADMIN SETUP
   ========================================================= */

/*
  Vérifie si le premier administrateur existe déjà.

  Cette route est publique afin que l'application puisse
  savoir si elle doit afficher l'écran de configuration.
*/

app.get("/api/setup/status", (req, res) => {
  const admin =
    db.prepare(`
      SELECT id
      FROM users
      WHERE role = 'admin'
      LIMIT 1
    `).get();

  res.json({
    ok: true,
    adminExists: !!admin,
    setupRequired: !admin
  });
});

/*
  CRÉATION DU PREMIER ADMINISTRATEUR.

  Important :
  - fonctionne uniquement s'il n'existe AUCUN admin ;
  - la vérification + création se fait dans une transaction ;
  - après création, cette route refuse toute nouvelle création.
*/

const createFirstAdmin = db.transaction(
  ({
    name,
    email,
    password
  }) => {

    const existingAdmin =
      db.prepare(`
        SELECT id
        FROM users
        WHERE role = 'admin'
        LIMIT 1
      `).get();

    if (existingAdmin) {
      throw new Error(
        "ADMIN_ALREADY_EXISTS"
      );
    }

    const accountId =
      generateAccountId();

    const passwordHash =
      bcrypt.hashSync(password, 12);

    const result =
      db.prepare(`
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
        name,
        email,
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

    return getUserById(userId);
  }
);

app.post("/api/setup/admin", (req, res) => {
  const name =
    cleanName(req.body.name);

  const email =
    normalizeEmail(req.body.email);

  const password =
    String(req.body.password || "");

  if (name.length < 2) {
    return res.status(400).json({
      ok: false,
      message: "Le nom est invalide."
    });
  }

  if (
    !email ||
    !email.includes("@") ||
    email.length < 5
  ) {
    return res.status(400).json({
      ok: false,
      message: "Adresse e-mail invalide."
    });
  }

  if (password.length < 8) {
    return res.status(400).json({
      ok: false,
      message:
        "Le mot de passe doit contenir au moins 8 caractères."
    });
  }

  try {
    const admin =
      createFirstAdmin({
        name,
        email,
        password
      });

    const token =
      createToken(admin);

    return res.status(201).json({
      ok: true,
      message:
        "Administrateur créé avec succès.",
      token,
      user: getAccountData(admin.id)
    });

  } catch (error) {

    if (
      error.message ===
      "ADMIN_ALREADY_EXISTS"
    ) {
      return res.status(409).json({
        ok: false,
        message:
          "Un administrateur existe déjà. La création d'un autre administrateur est désactivée."
      });
    }

    if (
      String(error.message)
        .includes("UNIQUE")
    ) {
      return res.status(409).json({
        ok: false,
        message:
          "Cette adresse e-mail est déjà utilisée."
      });
    }

    console.error(
      "Erreur création admin :",
      error
    );

    return res.status(500).json({
      ok: false,
      message:
        "Impossible de créer l'administrateur."
    });
  }
});

/* =========================================================
   LOGIN
   ========================================================= */

app.post("/api/auth/login", (req, res) => {
  const identifier =
    String(
      req.body.identifier ||
      req.body.email ||
      req.body.account_id ||
      ""
    )
      .trim()
      .toLowerCase();

  const password =
    String(req.body.password || "");

  if (!identifier || !password) {
    return res.status(400).json({
      ok: false,
      message:
        "Identifiant et mot de passe requis."
    });
  }

  const user =
    db.prepare(`
      SELECT *
      FROM users
      WHERE LOWER(email) = ?
         OR LOWER(account_id) = ?
      LIMIT 1
    `).get(
      identifier,
      identifier
    );

  if (!user) {
    return res.status(401).json({
      ok: false,
      message:
        "Identifiants incorrects."
    });
  }

  const valid =
    bcrypt.compareSync(
      password,
      user.password_hash
    );

  if (!valid) {
    return res.status(401).json({
      ok: false,
      message:
        "Identifiants incorrects."
    });
  }

  if (user.status !== "active") {
    return res.status(403).json({
      ok: false,
      message:
        "Ce compte est bloqué."
    });
  }

  const token =
    createToken(user);

  res.json({
    ok: true,
    token,
    user: getAccountData(user.id)
  });
});

/* =========================================================
   REGISTER USER
   ========================================================= */

app.post("/api/auth/register", (req, res) => {
  const name =
    cleanName(req.body.name);

  const email =
    normalizeEmail(req.body.email);

  const password =
    String(req.body.password || "");

  if (name.length < 2) {
    return res.status(400).json({
      ok: false,
      message:
        "Le nom est invalide."
    });
  }

  if (
    !email ||
    !email.includes("@")
  ) {
    return res.status(400).json({
      ok: false,
      message:
        "Adresse e-mail invalide."
    });
  }

  if (password.length < 8) {
    return res.status(400).json({
      ok: false,
      message:
        "Le mot de passe doit contenir au moins 8 caractères."
    });
  }

  const existing =
    db.prepare(`
      SELECT id
      FROM users
      WHERE email = ?
      LIMIT 1
    `).get(email);

  if (existing) {
    return res.status(409).json({
      ok: false,
      message:
        "Cette adresse e-mail est déjà utilisée."
    });
  }

  try {
    const createUser =
      db.transaction(() => {

        const accountId =
          generateAccountId();

        const passwordHash =
          bcrypt.hashSync(
            password,
            12
          );

        const result =
          db.prepare(`
            INSERT INTO users (
              account_id,
              name,
              email,
              password_hash,
              role,
              status
            )
            VALUES (?, ?, ?, ?, 'user', 'active')
          `).run(
            accountId,
            name,
            email,
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

        return getUserById(userId);
      });

    const user =
      createUser();

    const token =
      createToken(user);

    res.status(201).json({
      ok: true,
      message:
        "Compte créé avec succès.",
      token,
      user: getAccountData(user.id)
    });

  } catch (error) {
    console.error(
      "Erreur inscription :",
      error
    );

    res.status(500).json({
      ok: false,
      message:
        "Impossible de créer le compte."
    });
  }
});

/* =========================================================
   CURRENT ACCOUNT
   ========================================================= */

app.get(
  "/api/account",
  authenticateToken,
  (req, res) => {

    const data =
      getAccountData(req.user.id);

    if (!data) {
      return res.status(404).json({
        ok: false,
        message:
          "Compte introuvable."
      });
    }

    res.json({
      ok: true,
      user: data,

      // Compatibilité avec certaines
      // anciennes versions du frontend.
      account: data
    });
  }
);

/* =========================================================
   TRANSACTIONS
   ========================================================= */

app.get(
  "/api/transactions",
  authenticateToken,
  (req, res) => {

    const limit =
      Math.min(
        Math.max(
          Number(req.query.limit) || 50,
          1
        ),
        100
      );

    const transactions =
      db.prepare(`
        SELECT
          id,
          type,
          currency,
          amount_cdf,
          amount_usd_cents,
          description,
          reference,
          created_at
        FROM transactions
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT ?
      `).all(
        req.user.id,
        limit
      );

    res.json({
      ok: true,
      transactions
    });
  }
);

/* =========================================================
   TRANSFER
   ========================================================= */

app.post(
  "/api/transfer",
  authenticateToken,
  (req, res) => {

    const recipientIdentifier =
      String(
        req.body.recipient ||
        req.body.account_id ||
        req.body.accountId ||
        ""
      )
        .trim()
        .toLowerCase();

    const currency =
      String(
        req.body.currency ||
        "CDF"
      ).toUpperCase();

    const amount =
      Number(req.body.amount);

    const description =
      String(
        req.body.description ||
        "Transfert DALZON Wallet"
      )
        .trim()
        .slice(0, 200);

    if (!recipientIdentifier) {
      return res.status(400).json({
        ok: false,
        message:
          "Destinataire requis."
      });
    }

    if (!["CDF", "USD"].includes(currency)) {
      return res.status(400).json({
        ok: false,
        message:
          "Devise invalide."
      });
    }

    if (
      !Number.isFinite(amount) ||
      amount <= 0
    ) {
      return res.status(400).json({
        ok: false,
        message:
          "Montant invalide."
      });
    }

    const recipient =
      db.prepare(`
        SELECT *
        FROM users
        WHERE LOWER(email) = ?
           OR LOWER(account_id) = ?
        LIMIT 1
      `).get(
        recipientIdentifier,
        recipientIdentifier
      );

    if (!recipient) {
      return res.status(404).json({
        ok: false,
        message:
          "Destinataire introuvable."
      });
    }

    if (
      recipient.id ===
      req.user.id
    ) {
      return res.status(400).json({
        ok: false,
        message:
          "Vous ne pouvez pas vous transférer de l'argent à vous-même."
      });
    }

    if (recipient.status !== "active") {
      return res.status(403).json({
        ok: false,
        message:
          "Le compte destinataire est bloqué."
      });
    }

    let amountCdf = 0;
    let amountUsdCents = 0;

    if (currency === "CDF") {
      amountCdf =
        Math.round(amount);
    } else {
      amountUsdCents =
        Math.round(amount * 100);
    }

    if (
      currency === "CDF" &&
      amountCdf <= 0
    ) {
      return res.status(400).json({
        ok: false,
        message:
          "Montant CDF invalide."
      });
    }

    if (
      currency === "USD" &&
      amountUsdCents <= 0
    ) {
      return res.status(400).json({
        ok: false,
        message:
          "Montant USD invalide."
      });
    }

    try {

      const transfer =
        db.transaction(() => {

          const senderWallet =
            getWallet(
              req.user.id
            );

          const recipientWallet =
            getWallet(
              recipient.id
            );

          if (
            !senderWallet ||
            !recipientWallet
          ) {
            throw new Error(
              "WALLET_NOT_FOUND"
            );
          }

          if (
            currency === "CDF"
          ) {
            if (
              senderWallet.cdf <
              amountCdf
            ) {
              throw new Error(
                "INSUFFICIENT_FUNDS"
              );
            }

            db.prepare(`
              UPDATE wallets
              SET cdf = cdf - ?
              WHERE user_id = ?
            `).run(
              amountCdf,
              req.user.id
            );

            db.prepare(`
              UPDATE wallets
              SET cdf = cdf + ?
              WHERE user_id = ?
            `).run(
              amountCdf,
              recipient.id
            );

          } else {

            if (
              senderWallet.usd_cents <
              amountUsdCents
            ) {
              throw new Error(
                "INSUFFICIENT_FUNDS"
              );
            }

            db.prepare(`
              UPDATE wallets
              SET usd_cents =
                usd_cents - ?
              WHERE user_id = ?
            `).run(
              amountUsdCents,
              req.user.id
            );

            db.prepare(`
              UPDATE wallets
              SET usd_cents =
                usd_cents + ?
              WHERE user_id = ?
            `).run(
              amountUsdCents,
              recipient.id
            );
          }

          const reference =
            generateReference(
              "TRF"
            );

          db.prepare(`
            INSERT INTO transactions (
              user_id,
              type,
              currency,
              amount_cdf,
              amount_usd_cents,
              description,
              reference
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
          `).run(
            req.user.id,
            "transfer",
            currency,
            amountCdf,
            amountUsdCents,
            description ||
              `Transfert vers ${recipient.account_id}`,
            reference
          );

          db.prepare(`
            INSERT INTO transactions (
              user_id,
              type,
              currency,
              amount_cdf,
              amount_usd_cents,
              description,
              reference
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
          `).run(
            recipient.id,
            "receive",
            currency,
            amountCdf,
            amountUsdCents,
            description ||
              `Réception de ${req.user.account_id}`,
            reference
          );

          return reference;
        });

      const reference =
        transfer();

      res.json({
        ok: true,
        message:
          "Transfert effectué.",
        reference
      });

    } catch (error) {

      if (
        error.message ===
        "INSUFFICIENT_FUNDS"
      ) {
        return res.status(400).json({
          ok: false,
          message:
            "Solde insuffisant."
        });
      }

      console.error(
        "Erreur transfert :",
        error
      );

      res.status(500).json({
        ok: false,
        message:
          "Impossible d'effectuer le transfert."
      });
    }
  }
);

/* =========================================================
   SIMULATED PAYMENT
   ========================================================= */

app.post(
  "/api/payment",
  authenticateToken,
  (req, res) => {

    const currency =
      String(
        req.body.currency ||
        "CDF"
      ).toUpperCase();

    const amount =
      Number(req.body.amount);

    const merchant =
      String(
        req.body.merchant ||
        req.body.description ||
        "Paiement simulé"
      )
        .trim()
        .slice(0, 200);

    if (!["CDF", "USD"].includes(currency)) {
      return res.status(400).json({
        ok: false,
        message:
          "Devise invalide."
      });
    }

    if (
      !Number.isFinite(amount) ||
      amount <= 0
    ) {
      return res.status(400).json({
        ok: false,
        message:
          "Montant invalide."
      });
    }

    let amountCdf = 0;
    let amountUsdCents = 0;

    if (currency === "CDF") {
      amountCdf =
        Math.round(amount);
    } else {
      amountUsdCents =
        Math.round(amount * 100);
    }

    try {

      const payment =
        db.transaction(() => {

          const wallet =
            getWallet(
              req.user.id
            );

          if (!wallet) {
            throw new Error(
              "WALLET_NOT_FOUND"
            );
          }

          if (
            currency === "CDF"
          ) {

            if (
              wallet.cdf <
              amountCdf
            ) {
              throw new Error(
                "INSUFFICIENT_FUNDS"
              );
            }

            db.prepare(`
              UPDATE wallets
              SET cdf = cdf - ?
              WHERE user_id = ?
            `).run(
              amountCdf,
              req.user.id
            );

          } else {

            if (
              wallet.usd_cents <
              amountUsdCents
            ) {
              throw new Error(
                "INSUFFICIENT_FUNDS"
              );
            }

            db.prepare(`
              UPDATE wallets
              SET usd_cents =
                usd_cents - ?
              WHERE user_id = ?
            `).run(
              amountUsdCents,
              req.user.id
            );
          }

          const reference =
            generateReference(
              "PAY"
            );

          db.prepare(`
            INSERT INTO transactions (
              user_id,
              type,
              currency,
              amount_cdf,
              amount_usd_cents,
              description,
              reference
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
          `).run(
            req.user.id,
            "payment",
            currency,
            amountCdf,
            amountUsdCents,
            merchant,
            reference
          );

          return reference;
        });

      res.json({
        ok: true,
        message:
          "Paiement simulé effectué.",
        reference: payment
      });

    } catch (error) {

      if (
        error.message ===
        "INSUFFICIENT_FUNDS"
      ) {
        return res.status(400).json({
          ok: false,
          message:
            "Solde insuffisant."
        });
      }

      console.error(
        "Erreur paiement :",
        error
      );

      res.status(500).json({
        ok: false,
        message:
          "Impossible d'effectuer le paiement."
      });
    }
  }
);

/* =========================================================
   ADMIN DASHBOARD
   ========================================================= */

app.get(
  "/api/admin/dashboard",
  authenticateToken,
  requireAdmin,
  (req, res) => {

    const totalUsers =
      db.prepare(`
        SELECT COUNT(*) AS count
        FROM users
        WHERE role = 'user'
      `).get().count;

    const activeUsers =
      db.prepare(`
        SELECT COUNT(*) AS count
        FROM users
        WHERE role = 'user'
          AND status = 'active'
      `).get().count;

    const blockedUsers =
      db.prepare(`
        SELECT COUNT(*) AS count
        FROM users
        WHERE role = 'user'
          AND status = 'blocked'
      `).get().count;

    const totalTransactions =
      db.prepare(`
        SELECT COUNT(*) AS count
        FROM transactions
      `).get().count;

    const totalCdf =
      db.prepare(`
        SELECT COALESCE(
          SUM(cdf),
          0
        ) AS total
        FROM wallets
      `).get().total;

    const totalUsdCents =
      db.prepare(`
        SELECT COALESCE(
          SUM(usd_cents),
          0
        ) AS total
        FROM wallets
      `).get().total;

    res.json({
      ok: true,
      stats: {
        totalUsers,
        activeUsers,
        blockedUsers,
        totalTransactions,
        totalCdf,
        totalUsd:
          totalUsdCents / 100
      }
    });
  }
);

/* =========================================================
   ADMIN USERS
   ========================================================= */

app.get(
  "/api/admin/users",
  authenticateToken,
  requireAdmin,
  (req, res) => {

    const users =
      db.prepare(`
        SELECT
          u.id,
          u.account_id,
          u.name,
          u.email,
          u.role,
          u.status,
          u.created_at,
          COALESCE(w.cdf, 0) AS cdf,
          COALESCE(
            w.usd_cents,
            0
          ) AS usd_cents
        FROM users u
        LEFT JOIN wallets w
          ON w.user_id = u.id
        ORDER BY u.id DESC
      `).all();

    res.json({
      ok: true,
      users: users.map(
        (user) => ({
          id: user.id,
          account_id:
            user.account_id,
          name: user.name,
          email: user.email,
          role: user.role,
          status: user.status,
          created_at:
            user.created_at,

          wallet: {
            CDF: user.cdf,
            USD:
              user.usd_cents / 100
          }
        })
      )
    });
  }
);

/* =========================================================
   ADMIN CREDIT
   ========================================================= */

app.post(
  "/api/admin/credit",
  authenticateToken,
  requireAdmin,
  (req, res) => {

    const userId =
      Number(
        req.body.userId ||
        req.body.user_id
      );

    const currency =
      String(
        req.body.currency ||
        "CDF"
      ).toUpperCase();

    const amount =
      Number(req.body.amount);

    const description =
      String(
        req.body.description ||
        "Crédit administrateur"
      )
        .trim()
        .slice(0, 200);

    if (
      !Number.isInteger(userId) ||
      userId <= 0
    ) {
      return res.status(400).json({
        ok: false,
        message:
          "Utilisateur invalide."
      });
    }

    if (!["CDF", "USD"].includes(currency)) {
      return res.status(400).json({
        ok: false,
        message:
          "Devise invalide."
      });
    }

    if (
      !Number.isFinite(amount) ||
      amount <= 0
    ) {
      return res.status(400).json({
        ok: false,
        message:
          "Montant invalide."
      });
    }

    const targetUser =
      getUserById(userId);

    if (!targetUser) {
      return res.status(404).json({
        ok: false,
        message:
          "Utilisateur introuvable."
      });
    }

    let amountCdf = 0;
    let amountUsdCents = 0;

    if (currency === "CDF") {
      amountCdf =
        Math.round(amount);
    } else {
      amountUsdCents =
        Math.round(amount * 100);
    }

    try {

      const credit =
        db.transaction(() => {

          const wallet =
            getWallet(userId);

          if (!wallet) {
            throw new Error(
              "WALLET_NOT_FOUND"
            );
          }

          if (currency === "CDF") {

            db.prepare(`
              UPDATE wallets
              SET cdf = cdf + ?
              WHERE user_id = ?
            `).run(
              amountCdf,
              userId
            );

          } else {

            db.prepare(`
              UPDATE wallets
              SET usd_cents =
                usd_cents + ?
              WHERE user_id = ?
            `).run(
              amountUsdCents,
              userId
            );
          }

          const reference =
            generateReference(
              "ADM"
            );

          db.prepare(`
            INSERT INTO transactions (
              user_id,
              type,
              currency,
              amount_cdf,
              amount_usd_cents,
              description,
              reference
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
          `).run(
            userId,
            "credit",
            currency,
            amountCdf,
            amountUsdCents,
            description,
            reference
          );

          return reference;
        });

      res.json({
        ok: true,
        message:
          "Solde ajouté avec succès.",
        reference: credit
      });

    } catch (error) {

      console.error(
        "Erreur crédit admin :",
        error
      );

      res.status(500).json({
        ok: false,
        message:
          "Impossible d'ajouter le solde."
      });
    }
  }
);

/* =========================================================
   ADMIN BLOCK / UNBLOCK
   ========================================================= */

app.post(
  "/api/admin/block",
  authenticateToken,
  requireAdmin,
  (req, res) => {

    const userId =
      Number(
        req.body.userId ||
        req.body.user_id
      );

    if (
      !Number.isInteger(userId) ||
      userId <= 0
    ) {
      return res.status(400).json({
        ok: false,
        message:
          "Utilisateur invalide."
      });
    }

    const target =
      getUserById(userId);

    if (!target) {
      return res.status(404).json({
        ok: false,
        message:
          "Utilisateur introuvable."
      });
    }

    if (target.role === "admin") {
      return res.status(403).json({
        ok: false,
        message:
          "Le compte administrateur ne peut pas être bloqué depuis cette interface."
      });
    }

    db.prepare(`
      UPDATE users
      SET status = 'blocked'
      WHERE id = ?
    `).run(userId);

    res.json({
      ok: true,
      message:
        "Compte bloqué."
    });
  }
);

app.post(
  "/api/admin/unblock",
  authenticateToken,
  requireAdmin,
  (req, res) => {

    const userId =
      Number(
        req.body.userId ||
        req.body.user_id
      );

    if (
      !Number.isInteger(userId) ||
      userId <= 0
    ) {
      return res.status(400).json({
        ok: false,
        message:
          "Utilisateur invalide."
      });
    }

    const target =
      getUserById(userId);

    if (!target) {
      return res.status(404).json({
        ok: false,
        message:
          "Utilisateur introuvable."
      });
    }

    db.prepare(`
      UPDATE users
      SET status = 'active'
      WHERE id = ?
    `).run(userId);

    res.json({
      ok: true,
      message:
        "Compte débloqué."
    });
  }
);

/* =========================================================
   ADMIN SINGLE USER
   ========================================================= */

app.get(
  "/api/admin/users/:id",
  authenticateToken,
  requireAdmin,
  (req, res) => {

    const userId =
      Number(req.params.id);

    const data =
      getAccountData(userId);

    if (!data) {
      return res.status(404).json({
        ok: false,
        message:
          "Utilisateur introuvable."
      });
    }

    res.json({
      ok: true,
      user: data
    });
  }
);

/* =========================================================
   ADMIN TRANSACTIONS
   ========================================================= */

app.get(
  "/api/admin/transactions",
  authenticateToken,
  requireAdmin,
  (req, res) => {

    const limit =
      Math.min(
        Math.max(
          Number(req.query.limit) || 100,
          1
        ),
        500
      );

    const transactions =
      db.prepare(`
        SELECT
          t.id,
          t.user_id,
          t.type,
          t.currency,
          t.amount_cdf,
          t.amount_usd_cents,
          t.description,
          t.reference,
          t.created_at,
          u.account_id,
          u.name,
          u.email
        FROM transactions t
        JOIN users u
          ON u.id = t.user_id
        ORDER BY t.id DESC
        LIMIT ?
      `).all(limit);

    res.json({
      ok: true,
      transactions
    });
  }
);

/* =========================================================
   LOGOUT
   ========================================================= */

app.post(
  "/api/auth/logout",
  authenticateToken,
  (req, res) => {

    /*
      JWT stateless :
      le frontend supprime simplement le token.
    */

    res.json({
      ok: true,
      message:
        "Déconnexion effectuée."
    });
  }
);

/* =========================================================
   404
   ========================================================= */

app.use((req, res) => {
  res.status(404).json({
    ok: false,
    message:
      "Route API introuvable."
  });
});

/* =========================================================
   ERROR HANDLER
   ========================================================= */

app.use(
  (error, req, res, next) => {

    console.error(
      "Erreur serveur :",
      error
    );

    if (res.headersSent) {
      return next(error);
    }

    res.status(500).json({
      ok: false,
      message:
        "Erreur interne du serveur."
    });
  }
);

/* =========================================================
   START
   ========================================================= */

app.listen(
  PORT,
  "0.0.0.0",
  () => {

    console.log("");
    console.log(
      "======================================"
    );

    console.log(
      "       DALZON WALLET v3.0"
    );

    console.log(
      "======================================"
    );

    console.log(
      `Port       : ${PORT}`
    );

    console.log(
      `Database   : ${DB_PATH}`
    );

    console.log(
      "Admin setup: application"
    );

    console.log(
      "Mode       : simulation éducative"
    );

    console.log(
      "======================================"
    );

    console.log("");
  }
);

/* =========================================================
   GRACEFUL SHUTDOWN
   ========================================================= */

function shutdown() {
  console.log(
    "Arrêt de DALZON Wallet..."
  );

  try {
    db.close();
  } catch (error) {
    console.error(error);
  }

  process.exit(0);
}

process.on(
  "SIGINT",
  shutdown
);

process.on(
  "SIGTERM",
  shutdown
);