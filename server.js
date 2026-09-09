const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const cors = require("cors");

const app = express();

const PORT = process.env.PORT || 10000;
const JWT_SECRET =
  process.env.JWT_SECRET || "DALZON_WALLET_DEV_SECRET_CHANGE_ME";

// ===============================
// DATABASE
// ===============================

const db = new Database("dalzon.db");

db.pragma("foreign_keys = ON");

// ===============================
// MIDDLEWARE
// ===============================

app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"]
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ===============================
// DATABASE TABLES
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
    holder_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    currency TEXT NOT NULL,
    amount_cdf INTEGER NOT NULL DEFAULT 0,
    amount_usd_cents INTEGER NOT NULL DEFAULT 0,
    description TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

// ===============================
// HELPERS
// ===============================

function generateAccountId() {
  let accountId;

  do {
    accountId =
      "DAL" +
      Math.floor(10000000 + Math.random() * 90000000).toString();
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
    cardNumber =
      "5399" +
      Math.floor(100000000000 + Math.random() * 900000000000).toString();
  } while (
    db
      .prepare("SELECT id FROM cards WHERE card_number = ?")
      .get(cardNumber)
  );

  return cardNumber;
}

function generateExpiry() {
  const now = new Date();

  const month = String(now.getMonth() + 1).padStart(2, "0");
  const year = String((now.getFullYear() + 4) % 100).padStart(2, "0");

  return `${month}/${year}`;
}

// ===============================
// JWT TOKEN
// ===============================

function createToken(user) {
  return jwt.sign(
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
}

// ===============================
// AUTH MIDDLEWARE
// ===============================

function authenticate(req, res, next) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Authentification requise."
      });
    }

    const token = authHeader.split(" ")[1];

    const decoded = jwt.verify(token, JWT_SECRET);

    const user = db
      .prepare(
        `
        SELECT
          id,
          account_id,
          name,
          email,
          role,
          status
        FROM users
        WHERE id = ?
        `
      )
      .get(decoded.id);

    if (!user) {
      return res.status(401).json({
        error: "Utilisateur introuvable."
      });
    }

    if (user.status === "blocked") {
      return res.status(403).json({
        error: "Ce compte est bloqué."
      });
    }

    req.user = user;

    next();
  } catch (error) {
    return res.status(401).json({
      error: "Session invalide ou expirée."
    });
  }
}

// ===============================
// ADMIN MIDDLEWARE
// ===============================

function adminOnly(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({
      error: "Accès administrateur requis."
    });
  }

  next();
}

// ===============================
// CREATE USER
// ===============================

const createUser = db.transaction(
  (name, email, passwordHash, accountId) => {
    const userResult = db
      .prepare(
        `
        INSERT INTO users (
          account_id,
          name,
          email,
          password_hash,
          role,
          status
        )
        VALUES (?, ?, ?, ?, 'user', 'active')
        `
      )
      .run(
        accountId,
        name,
        email,
        passwordHash
      );

    const userId = userResult.lastInsertRowid;

    db.prepare(
      `
      INSERT INTO wallets (
        user_id,
        cdf,
        usd_cents
      )
      VALUES (?, 0, 0)
      `
    ).run(userId);

    db.prepare(
      `
      INSERT INTO cards (
        user_id,
        card_number,
        expiry,
        holder_name,
        status
      )
      VALUES (?, ?, ?, ?, 'active')
      `
    ).run(
      userId,
      generateCardNumber(),
      generateExpiry(),
      name
    );

    return userId;
  }
);

// ===============================
// REGISTER
// ===============================

app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        error: "Tous les champs sont obligatoires."
      });
    }

    if (String(name).trim().length < 2) {
      return res.status(400).json({
        error: "Le nom est trop court."
      });
    }

    if (String(password).length < 6) {
      return res.status(400).json({
        error: "Le mot de passe doit contenir au moins 6 caractères."
      });
    }

    const normalizedEmail = String(email)
      .trim()
      .toLowerCase();

    const existingUser = db
      .prepare(
        "SELECT id FROM users WHERE email = ?"
      )
      .get(normalizedEmail);

    if (existingUser) {
      return res.status(409).json({
        error: "Cette adresse e-mail est déjà utilisée."
      });
    }

    const passwordHash = await bcrypt.hash(
      String(password),
      10
    );

    const accountId = generateAccountId();

    const userId = createUser(
      String(name).trim(),
      normalizedEmail,
      passwordHash,
      accountId
    );

    // Création automatique de la session
    const token = createToken({
      id: userId,
      account_id: accountId,
      role: "user"
    });

    return res.status(201).json({
      success: true,
      token,
      account_id: accountId,
      message: "Compte créé avec succès.",
      user: {
        id: userId,
        account_id: accountId,
        name: String(name).trim(),
        email: normalizedEmail,
        role: "user",
        status: "active"
      }
    });
  } catch (error) {
    console.error("REGISTER ERROR:", error);

    return res.status(500).json({
      error: "Erreur lors de la création du compte."
    });
  }
});

// ===============================
// LOGIN
// ===============================

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: "L'e-mail et le mot de passe sont obligatoires."
      });
    }

    const normalizedEmail = String(email)
      .trim()
      .toLowerCase();

    const user = db
      .prepare(
        `
        SELECT
          id,
          account_id,
          name,
          email,
          password_hash,
          role,
          status
        FROM users
        WHERE email = ?
        `
      )
      .get(normalizedEmail);

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

    const passwordMatch = await bcrypt.compare(
      String(password),
      user.password_hash
    );

    if (!passwordMatch) {
      return res.status(401).json({
        error: "E-mail ou mot de passe incorrect."
      });
    }

    const token = createToken({
      id: user.id,
      account_id: user.account_id,
      role: user.role
    });

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
      error: "Erreur lors de la connexion."
    });
  }
});

// ===============================
// ACCOUNT
// ===============================

app.get(
  "/api/account",
  authenticate,
  (req, res) => {
    try {
      const user = db
        .prepare(
          `
          SELECT
            id,
            account_id,
            name,
            email,
            role,
            status,
            created_at
          FROM users
          WHERE id = ?
          `
        )
        .get(req.user.id);

      const wallet = db
        .prepare(
          `
          SELECT
            cdf,
            usd_cents
          FROM wallets
          WHERE user_id = ?
          `
        )
        .get(req.user.id);

      const card = db
        .prepare(
          `
          SELECT
            card_number,
            expiry,
            holder_name,
            status
          FROM cards
          WHERE user_id = ?
          `
        )
        .get(req.user.id);

      if (!user || !wallet) {
        return res.status(404).json({
          error: "Compte introuvable."
        });
      }

      return res.json({
        success: true,

        user: {
          id: user.id,
          account_id: user.account_id,
          name: user.name,
          email: user.email,
          role: user.role,
          status: user.status,
          created_at: user.created_at
        },

        account: {
          cdf: wallet.cdf,
          usd: wallet.usd_cents / 100,

          wallet: {
            CDF: wallet.cdf,
            USD: wallet.usd_cents / 100
          },

          card: card
            ? {
                number: card.card_number,
                expiry: card.expiry,
                holder_name: card.holder_name,
                status: card.status
              }
            : null
        }
      });
    } catch (error) {
      console.error("ACCOUNT ERROR:", error);

      return res.status(500).json({
        error: "Impossible de récupérer le compte."
      });
    }
  }
);

// ===============================
// TRANSACTIONS
// ===============================

app.get(
  "/api/transactions",
  authenticate,
  (req, res) => {
    try {
      const transactions = db
        .prepare(
          `
          SELECT
            id,
            type,
            currency,
            amount_cdf,
            amount_usd_cents,
            amount_usd,
            description,
            created_at
          FROM transactions
          WHERE user_id = ?
          ORDER BY id DESC
          `
        )
        .all(req.user.id)
        .map((transaction) => ({
          id: transaction.id,
          type: transaction.type,
          currency: transaction.currency,
          amount_cdf: transaction.amount_cdf,
          amount_usd_cents: transaction.amount_usd_cents,
          amount_usd:
            transaction.amount_usd_cents / 100,
          description: transaction.description,
          created_at: transaction.created_at
        }));

      return res.json({
        success: true,
        transactions
      });
    } catch (error) {
      console.error("TRANSACTIONS ERROR:", error);

      return res.status(500).json({
        error: "Impossible de récupérer les transactions."
      });
    }
  }
);

// ===============================
// ADMIN - USERS
// ===============================

app.get(
  "/api/admin/users",
  authenticate,
  adminOnly,
  (req, res) => {
    try {
      const users = db
        .prepare(
          `
          SELECT
            u.id,
            u.account_id,
            u.name,
            u.email,
            u.role,
            u.status,
            u.created_at,
            w.cdf,
            w.usd_cents
          FROM users u
          LEFT JOIN wallets w
            ON w.user_id = u.id
          ORDER BY u.id DESC
          `
        )
        .all()
        .map((user) => ({
          id: user.id,
          account_id: user.account_id,
          name: user.name,
          email: user.email,
          role: user.role,
          status: user.status,
          created_at: user.created_at,
          cdf: user.cdf || 0,
          usd_cents: user.usd_cents || 0,
          usd: (user.usd_cents || 0) / 100
        }));

      return res.json({
        success: true,
        users
      });
    } catch (error) {
      console.error("ADMIN USERS ERROR:", error);

      return res.status(500).json({
        error: "Impossible de récupérer les utilisateurs."
      });
    }
  }
);

// ===============================
// ADMIN - CREDIT
// ===============================

app.post(
  "/api/admin/credit",
  authenticate,
  adminOnly,
  (req, res) => {
    try {
      const {
        userId,
        currency,
        amount,
        description
      } = req.body;

      const numericUserId = Number(userId);
      const numericAmount = Number(amount);

      if (!Number.isInteger(numericUserId)) {
        return res.status(400).json({
          error: "Utilisateur invalide."
        });
      }

      if (
        !["CDF", "USD"].includes(
          String(currency).toUpperCase()
        )
      ) {
        return res.status(400).json({
          error: "Devise invalide."
        });
      }

      if (
        !Number.isFinite(numericAmount) ||
        numericAmount <= 0
      ) {
        return res.status(400).json({
          error: "Montant invalide."
        });
      }

      const targetUser = db
        .prepare(
          "SELECT id FROM users WHERE id = ?"
        )
        .get(numericUserId);

      if (!targetUser) {
        return res.status(404).json({
          error: "Utilisateur introuvable."
        });
      }

      const normalizedCurrency =
        String(currency).toUpperCase();

      const credit = db.transaction(() => {
        if (normalizedCurrency === "CDF") {
          db.prepare(
            `
            UPDATE wallets
            SET cdf = cdf + ?
            WHERE user_id = ?
            `
          ).run(
            Math.round(numericAmount),
            numericUserId
          );

          db.prepare(
            `
            INSERT INTO transactions (
              user_id,
              type,
              currency,
              amount_cdf,
              amount_usd_cents,
              description
            )
            VALUES (?, 'credit', 'CDF', ?, 0, ?)
            `
          ).run(
            numericUserId,
            Math.round(numericAmount),
            description ||
              "Crédit administrateur"
          );
        } else {
          const usdCents = Math.round(
            numericAmount * 100
          );

          db.prepare(
            `
            UPDATE wallets
            SET usd_cents = usd_cents + ?
            WHERE user_id = ?
            `
          ).run(
            usdCents,
            numericUserId
          );

          db.prepare(
            `
            INSERT INTO transactions (
              user_id,
              type,
              currency,
              amount_cdf,
              amount_usd_cents,
              description
            )
            VALUES (?, 'credit', 'USD', 0, ?, ?)
            `
          ).run(
            numericUserId,
            usdCents,
            description ||
              "Crédit administrateur"
          );
        }
      });

      credit();

      return res.json({
        success: true,
        message: "Compte crédité avec succès."
      });
    } catch (error) {
      console.error("ADMIN CREDIT ERROR:", error);

      return res.status(500).json({
        error: "Impossible de créditer le compte."
      });
    }
  }
);

// ===============================
// ADMIN - BLOCK / UNBLOCK
// ===============================

app.post(
  "/api/admin/block",
  authenticate,
  adminOnly,
  (req, res) => {
    try {
      const numericUserId = Number(
        req.body.userId
      );

      if (!Number.isInteger(numericUserId)) {
        return res.status(400).json({
          error: "Utilisateur invalide."
        });
      }

      if (numericUserId === req.user.id) {
        return res.status(400).json({
          error:
            "Vous ne pouvez pas bloquer votre propre compte."
        });
      }

      const user = db
        .prepare(
          `
          SELECT
            id,
            role,
            status
          FROM users
          WHERE id = ?
          `
        )
        .get(numericUserId);

      if (!user) {
        return res.status(404).json({
          error: "Utilisateur introuvable."
        });
      }

      if (user.role === "admin") {
        return res.status(403).json({
          error:
            "Un compte administrateur ne peut pas être bloqué."
        });
      }

      const newStatus =
        user.status === "blocked"
          ? "active"
          : "blocked";

      db.prepare(
        `
        UPDATE users
        SET status = ?
        WHERE id = ?
        `
      ).run(
        newStatus,
        numericUserId
      );

      return res.json({
        success: true,
        status: newStatus,
        message:
          newStatus === "blocked"
            ? "Utilisateur bloqué."
            : "Utilisateur débloqué."
      });
    } catch (error) {
      console.error("ADMIN BLOCK ERROR:", error);

      return res.status(500).json({
        error:
          "Impossible de modifier le statut du compte."
      });
    }
  }
);

// ===============================
// HEALTH CHECK
// ===============================

app.get("/api/health", (req, res) => {
  return res.json({
    success: true,
    status: "online",
    service: "DALZON Wallet API"
  });
});

// ===============================
// STATIC FILES
// ===============================

app.use(express.static(__dirname));

// ===============================
// ROOT
// ===============================

app.get("/", (req, res) => {
  res.sendFile(
    require("path").join(
      __dirname,
      "index.html"
    )
  );
});

// ===============================
// API 404
// ===============================

app.use("/api", (req, res) => {
  res.status(404).json({
    error: "Route API introuvable."
  });
});

// ===============================
// GLOBAL ERROR HANDLER
// ===============================

app.use((err, req, res, next) => {
  console.error("SERVER ERROR:", err);

  res.status(500).json({
    error: "Erreur interne du serveur."
  });
});

// ===============================
// START SERVER
// ===============================

app.listen(PORT, () => {
  console.log(
    `DALZON Wallet API démarrée sur le port ${PORT}`
  );
});