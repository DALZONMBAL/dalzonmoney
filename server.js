const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const cors = require("cors");

const app = express();

const PORT = process.env.PORT || 10000;

const JWT_SECRET =
  process.env.JWT_SECRET || "DALZON_WALLET_DEV_SECRET_CHANGE_ME";

const dbPath = path.join(__dirname, "dalzon.db");
const db = new Database(dbPath);

db.pragma("foreign_keys = ON");

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* =========================================================
   BASE DE DONNÉES
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
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS cards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER UNIQUE NOT NULL,
    card_number TEXT UNIQUE NOT NULL,
    expiry TEXT NOT NULL,
    holder_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    currency TEXT NOT NULL,
    amount_cdf INTEGER DEFAULT 0,
    amount_usd_cents INTEGER DEFAULT 0,
    description TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

/* =========================================================
   OUTILS
========================================================= */

function generateAccountId() {
  let accountId;

  do {
    accountId =
      "DLZ-" + Math.floor(10000 + Math.random() * 90000);
  } while (
    db
      .prepare("SELECT id FROM users WHERE account_id = ?")
      .get(accountId)
  );

  return accountId;
}

function generateCardNumber() {
  let cardNumber;

  do {
    const p1 = Math.floor(1000 + Math.random() * 9000);
    const p2 = Math.floor(1000 + Math.random() * 9000);
    const p3 = Math.floor(1000 + Math.random() * 9000);
    const p4 = Math.floor(1000 + Math.random() * 9000);

    cardNumber = `DLZ ${p1} ${p2} ${p3} ${p4}`;
  } while (
    db
      .prepare("SELECT id FROM cards WHERE card_number = ?")
      .get(cardNumber)
  );

  return cardNumber;
}

function generateExpiry() {
  const date = new Date();

  date.setFullYear(date.getFullYear() + 4);

  const month = String(date.getMonth() + 1).padStart(2, "0");
  const year = String(date.getFullYear()).slice(-2);

  return `${month}/${year}`;
}

/* =========================================================
   AUTHENTIFICATION
========================================================= */

function auth(req, res, next) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Authentification requise."
    });
  }

  const token = header.substring(7);

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (error) {
    return res.status(401).json({
      error: "Session invalide ou expirée."
    });
  }
}

function adminOnly(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({
      error: "Accès administrateur requis."
    });
  }

  next();
}

/* =========================================================
   INSCRIPTION
========================================================= */

app.post("/api/auth/register", async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const email = String(req.body.email || "")
      .trim()
      .toLowerCase();

    const password = String(req.body.password || "");

    if (!name || !email || !password) {
      return res.status(400).json({
        error: "Tous les champs sont obligatoires."
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: "Le mot de passe doit contenir au moins 6 caractères."
      });
    }

    const existingUser = db
      .prepare("SELECT id FROM users WHERE email = ?")
      .get(email);

    if (existingUser) {
      return res.status(409).json({
        error: "Cette adresse e-mail est déjà utilisée."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const accountId = generateAccountId();
    const cardNumber = generateCardNumber();
    const expiry = generateExpiry();

    const createUser = db.transaction(() => {
      const result = db
        .prepare(`
          INSERT INTO users
          (account_id, name, email, password_hash, role, status)
          VALUES (?, ?, ?, ?, 'user', 'active')
        `)
        .run(
          accountId,
          name,
          email,
          passwordHash
        );

      const userId = result.lastInsertRowid;

      db.prepare(`
        INSERT INTO wallets
        (user_id, cdf, usd_cents)
        VALUES (?, 0, 0)
      `).run(userId);

      db.prepare(`
        INSERT INTO cards
        (user_id, card_number, expiry, holder_name, status)
        VALUES (?, ?, ?, ?, 'active')
      `).run(
        userId,
        cardNumber,
        expiry,
        name.toUpperCase()
      );

      return userId;
    });

    const userId = createUser();

    return res.status(201).json({
      success: true,
      account_id: accountId,
      message: "Compte créé avec succès.",
      user: {
        id: userId,
        account_id: accountId,
        name,
        email,
        role: "user",
        status: "active"
      }
    });

  } catch (error) {
    console.error("REGISTER ERROR:", error);

    return res.status(500).json({
      error: "Impossible de créer le compte."
    });
  }
});

/* =========================================================
   CONNEXION
========================================================= */

app.post("/api/auth/login", async (req, res) => {
  try {
    const email = String(req.body.email || "")
      .trim()
      .toLowerCase();

    const password = String(req.body.password || "");

    if (!email || !password) {
      return res.status(400).json({
        error: "E-mail et mot de passe requis."
      });
    }

    const user = db
      .prepare(`
        SELECT *
        FROM users
        WHERE email = ?
      `)
      .get(email);

    if (!user) {
      return res.status(401).json({
        error: "E-mail ou mot de passe incorrect."
      });
    }

    if (user.status === "blocked") {
      return res.status(403).json({
        error: "Ce compte est bloqué."
      });
    }

    const passwordOk = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!passwordOk) {
      return res.status(401).json({
        error: "E-mail ou mot de passe incorrect."
      });
    }

    const token = jwt.sign(
      {
        id: user.id,
        account_id: user.account_id,
        role: user.role
      },
      JWT_SECRET,
      {
        expiresIn: "7d"
      }
    );

    return res.json({
      success: true,
      token,
      user: {
        id: user.id,
        account_id: user.account_id,
        name: user.name,
        email: user.email,
        role: user.role,
        status: user.status
      }
    });

  } catch (error) {
    console.error("LOGIN ERROR:", error);

    return res.status(500).json({
      error: "Impossible de se connecter."
    });
  }
});

/* =========================================================
   INFORMATIONS DU COMPTE
========================================================= */

app.get("/api/account", auth, (req, res) => {
  try {
    const account = db
      .prepare(`
        SELECT
          u.id,
          u.account_id,
          u.name,
          u.email,
          u.role,
          u.status,
          u.created_at,

          w.cdf,
          w.usd_cents,

          c.card_number,
          c.expiry,
          c.holder_name,
          c.status AS card_status

        FROM users u

        LEFT JOIN wallets w
          ON w.user_id = u.id

        LEFT JOIN cards c
          ON c.user_id = u.id

        WHERE u.id = ?
      `)
      .get(req.user.id);

    if (!account) {
      return res.status(404).json({
        error: "Compte introuvable."
      });
    }

    const user = {
      id: account.id,
      account_id: account.account_id,
      name: account.name,
      email: account.email,
      role: account.role,
      status: account.status,
      created_at: account.created_at,

      cdf: Number(account.cdf || 0),

      usd:
        Number(account.usd_cents || 0) / 100,

      wallet: {
        CDF: Number(account.cdf || 0),
        USD:
          Number(account.usd_cents || 0) / 100
      },

      card: {
        number: account.card_number || "",
        expiry: account.expiry || "",
        holder_name: account.holder_name || "",
        status: account.card_status || "active"
      }
    };

    return res.json({
      success: true,

      /* Format principal utilisé par l'index.html */
      user,

      /* Compatibilité */
      account: user
    });

  } catch (error) {
    console.error("ACCOUNT ERROR:", error);

    return res.status(500).json({
      error: "Impossible de charger le compte."
    });
  }
});

/* =========================================================
   HISTORIQUE DES TRANSACTIONS
========================================================= */

app.get("/api/transactions", auth, (req, res) => {
  try {
    const transactions = db
      .prepare(`
        SELECT
          id,
          type,
          currency,
          amount_cdf,
          amount_usd_cents,
          amount_usd_cents / 100.0 AS amount_usd,
          description,
          created_at

        FROM transactions

        WHERE user_id = ?

        ORDER BY id DESC

        LIMIT 100
      `)
      .all(req.user.id);

    return res.json({
      success: true,
      transactions
    });

  } catch (error) {
    console.error("TRANSACTIONS ERROR:", error);

    return res.status(500).json({
      error: "Impossible de charger l'historique."
    });
  }
});

/* =========================================================
   ADMIN — LISTE DES UTILISATEURS
========================================================= */

app.get(
  "/api/admin/users",
  auth,
  adminOnly,
  (req, res) => {
    try {
      const users = db
        .prepare(`
          SELECT
            u.id,
            u.account_id,
            u.name,
            u.email,
            u.role,
            u.status,
            u.created_at,

            COALESCE(w.cdf, 0) AS cdf,
            COALESCE(w.usd_cents, 0) AS usd_cents

          FROM users u

          LEFT JOIN wallets w
            ON w.user_id = u.id

          ORDER BY u.id DESC
        `)
        .all();

      const result = users.map((user) => ({
        ...user,

        cdf: Number(user.cdf || 0),

        usd_cents:
          Number(user.usd_cents || 0),

        usd:
          Number(user.usd_cents || 0) / 100
      }));

      return res.json({
        success: true,
        users: result
      });

    } catch (error) {
      console.error("ADMIN USERS ERROR:", error);

      return res.status(500).json({
        error: "Impossible de charger les utilisateurs."
      });
    }
  }
);

/* =========================================================
   ADMIN — CRÉDITER UN COMPTE
========================================================= */

app.post(
  "/api/admin/credit",
  auth,
  adminOnly,
  (req, res) => {
    try {
      const userId = Number(req.body.user_id);
      const currency = String(
        req.body.currency || ""
      ).toUpperCase();

      const amount = Number(req.body.amount);

      const description =
        String(
          req.body.description ||
          "Crédit administratif DALZON"
        ).trim();

      if (!Number.isInteger(userId)) {
        return res.status(400).json({
          error: "Utilisateur invalide."
        });
      }

      if (
        currency !== "CDF" &&
        currency !== "USD"
      ) {
        return res.status(400).json({
          error: "Devise invalide. Utilisez CDF ou USD."
        });
      }

      if (
        !Number.isFinite(amount) ||
        amount <= 0
      ) {
        return res.status(400).json({
          error: "Le montant doit être supérieur à zéro."
        });
      }

      const targetUser = db
        .prepare(`
          SELECT id, status
          FROM users
          WHERE id = ?
        `)
        .get(userId);

      if (!targetUser) {
        return res.status(404).json({
          error: "Utilisateur introuvable."
        });
      }

      if (targetUser.status === "blocked") {
        return res.status(400).json({
          error: "Impossible de créditer un compte bloqué."
        });
      }

      const creditTransaction = db.transaction(() => {

        if (currency === "CDF") {
          const amountCdf = Math.round(amount);

          db.prepare(`
            UPDATE wallets
            SET cdf = cdf + ?
            WHERE user_id = ?
          `).run(
            amountCdf,
            userId
          );

          db.prepare(`
            INSERT INTO transactions
            (
              user_id,
              type,
              currency,
              amount_cdf,
              amount_usd_cents,
              description
            )
            VALUES (?, 'credit', 'CDF', ?, 0, ?)
          `).run(
            userId,
            amountCdf,
            description
          );

          return {
            currency: "CDF",
            amount: amountCdf
          };
        }

        const amountUsdCents =
          Math.round(amount * 100);

        db.prepare(`
          UPDATE wallets
          SET usd_cents = usd_cents + ?
          WHERE user_id = ?
        `).run(
          amountUsdCents,
          userId
        );

        db.prepare(`
          INSERT INTO transactions
          (
            user_id,
            type,
            currency,
            amount_cdf,
            amount_usd_cents,
            description
          )
          VALUES (?, 'credit', 'USD', 0, ?, ?)
        `).run(
          userId,
          amountUsdCents,
          description
        );

        return {
          currency: "USD",
          amount:
            amountUsdCents / 100
        };
      });

      const result = creditTransaction();

      return res.json({
        success: true,
        message: "Compte crédité avec succès.",
        transaction: result
      });

    } catch (error) {
      console.error("ADMIN CREDIT ERROR:", error);

      return res.status(500).json({
        error: "Impossible de créditer le compte."
      });
    }
  }
);

/* =========================================================
   ADMIN — BLOQUER / DÉBLOQUER
========================================================= */

app.post(
  "/api/admin/block",
  auth,
  adminOnly,
  (req, res) => {
    try {
      const userId = Number(req.body.user_id);
      const blocked =
        req.body.blocked === true;

      if (!Number.isInteger(userId)) {
        return res.status(400).json({
          error: "Utilisateur invalide."
        });
      }

      const user = db
        .prepare(`
          SELECT id, role, status
          FROM users
          WHERE id = ?
        `)
        .get(userId);

      if (!user) {
        return res.status(404).json({
          error: "Utilisateur introuvable."
        });
      }

      if (user.role === "admin") {
        return res.status(400).json({
          error: "Un administrateur ne peut pas être bloqué."
        });
      }

      const newStatus =
        blocked ? "blocked" : "active";

      db.prepare(`
        UPDATE users
        SET status = ?
        WHERE id = ?
      `).run(
        newStatus,
        userId
      );

      return res.json({
        success: true,
        message: blocked
          ? "Compte bloqué."
          : "Compte débloqué.",
        status: newStatus
      });

    } catch (error) {
      console.error("ADMIN BLOCK ERROR:", error);

      return res.status(500).json({
        error: "Impossible de modifier le statut du compte."
      });
    }
  }
);

/* =========================================================
   SANTÉ DU SERVEUR
========================================================= */

app.get("/api/health", (req, res) => {
  return res.json({
    success: true,
    service: "DALZON Wallet",
    status: "online"
  });
});

/* =========================================================
   FICHIERS DU SITE
========================================================= */

app.use(express.static(__dirname));

/* =========================================================
   PAGE PRINCIPALE
========================================================= */

app.get("/", (req, res) => {
  res.sendFile(
    path.join(__dirname, "index.html")
  );
});

/* =========================================================
   404 API
========================================================= */

app.use("/api", (req, res) => {
  res.status(404).json({
    error: "Route API introuvable."
  });
});

/* =========================================================
   GESTION DES ERREURS
========================================================= */

app.use((error, req, res, next) => {
  console.error("SERVER ERROR:", error);

  if (res.headersSent) {
    return next(error);
  }

  res.status(500).json({
    error: "Erreur interne du serveur."
  });
});

/* =========================================================
   DÉMARRAGE
========================================================= */

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `DALZON Wallet server running on port ${PORT}`
    );
  }
);