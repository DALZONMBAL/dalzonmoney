const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");

const app = express();

const PORT = process.env.PORT || 10000;
const JWT_SECRET =
  process.env.JWT_SECRET || "DALZON_WALLET_DEV_SECRET_CHANGE_ME";

const db = new Database(path.join(__dirname, "dalzon.db"));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// =========================
// DATABASE
// =========================

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

// =========================
// HELPERS
// =========================

function generateAccountId() {
  let id;

  do {
    id =
      "DLZ-" +
      Math.floor(10000 + Math.random() * 90000);
  } while (
    db
      .prepare("SELECT id FROM users WHERE account_id = ?")
      .get(id)
  );

  return id;
}

function generateCardNumber() {
  let number;

  do {
    number =
      "DLZ " +
      Math.floor(1000 + Math.random() * 9000) +
      " " +
      Math.floor(1000 + Math.random() * 9000) +
      " " +
      Math.floor(1000 + Math.random() * 9000) +
      " " +
      Math.floor(1000 + Math.random() * 9000);
  } while (
    db
      .prepare("SELECT id FROM cards WHERE card_number = ?")
      .get(number)
  );

  return number;
}

function generateExpiry() {
  const date = new Date();

  const month = String(
    date.getMonth() + 1
  ).padStart(2, "0");

  const year = String(
    (date.getFullYear() + 4) % 100
  ).padStart(2, "0");

  return `${month}/${year}`;
}

// =========================
// AUTHENTICATION
// =========================

function auth(req, res, next) {
  const header =
    req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Authentification requise."
    });
  }

  const token = header.substring(7);

  try {
    req.user = jwt.verify(
      token,
      JWT_SECRET
    );

    next();
  } catch {
    return res.status(401).json({
      error: "Session invalide ou expirée."
    });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({
      error: "Accès administrateur requis."
    });
  }

  next();
}

// =========================
// REGISTER
// =========================

app.post(
  "/api/auth/register",
  async (req, res) => {
    try {
      const {
        name,
        email,
        password
      } = req.body;

      if (!name || !email || !password) {
        return res.status(400).json({
          error:
            "Nom, email et mot de passe requis."
        });
      }

      if (password.length < 6) {
        return res.status(400).json({
          error:
            "Le mot de passe doit contenir au moins 6 caractères."
        });
      }

      const normalizedEmail =
        String(email)
          .trim()
          .toLowerCase();

      const existing =
        db
          .prepare(
            "SELECT id FROM users WHERE email = ?"
          )
          .get(normalizedEmail);

      if (existing) {
        return res.status(409).json({
          error:
            "Cette adresse email existe déjà."
        });
      }

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );

      const accountId =
        generateAccountId();

      const createAccount =
        db.transaction(() => {
          const result =
            db
              .prepare(`
                INSERT INTO users
                (
                  account_id,
                  name,
                  email,
                  password_hash,
                  role,
                  status
                )
                VALUES
                (?, ?, ?, ?, 'user', 'active')
              `)
              .run(
                accountId,
                String(name).trim(),
                normalizedEmail,
                passwordHash
              );

          const userId =
            result.lastInsertRowid;

          db.prepare(`
            INSERT INTO wallets
            (
              user_id,
              cdf,
              usd_cents
            )
            VALUES (?, 0, 0)
          `).run(userId);

          db.prepare(`
            INSERT INTO cards
            (
              user_id,
              card_number,
              expiry,
              holder_name,
              status
            )
            VALUES
            (?, ?, ?, ?, 'active')
          `).run(
            userId,
            generateCardNumber(),
            generateExpiry(),
            String(name)
              .trim()
              .toUpperCase()
          );
        });

      createAccount();

      res.status(201).json({
        success: true,
        account_id: accountId,
        message:
          "Compte créé avec succès."
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          "Erreur lors de la création du compte."
      });
    }
  }
);

// =========================
// LOGIN
// =========================

app.post(
  "/api/auth/login",
  async (req, res) => {
    try {
      const {
        email,
        password
      } = req.body;

      if (!email || !password) {
        return res.status(400).json({
          error:
            "Email et mot de passe requis."
        });
      }

      const normalizedEmail =
        String(email)
          .trim()
          .toLowerCase();

      const user =
        db
          .prepare(
            "SELECT * FROM users WHERE email = ?"
          )
          .get(normalizedEmail);

      if (!user) {
        return res.status(401).json({
          error:
            "Identifiants incorrects."
        });
      }

      if (user.status !== "active") {
        return res.status(403).json({
          error:
            "Ce compte est bloqué."
        });
      }

      const valid =
        await bcrypt.compare(
          password,
          user.password_hash
        );

      if (!valid) {
        return res.status(401).json({
          error:
            "Identifiants incorrects."
        });
      }

      const token =
        jwt.sign(
          {
            id: user.id,
            account_id:
              user.account_id,
            role: user.role
          },
          JWT_SECRET,
          {
            expiresIn: "7d"
          }
        );

      res.json({
        success: true,
        token,
        user: {
          id: user.id,
          account_id:
            user.account_id,
          name: user.name,
          email: user.email,
          role: user.role
        }
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          "Erreur de connexion."
      });
    }
  }
);

// =========================
// ACCOUNT
// =========================

app.get(
  "/api/account",
  auth,
  (req, res) => {
    const account =
      db
        .prepare(`
          SELECT
            u.id,
            u.account_id,
            u.name,
            u.email,
            u.role,
            u.status,
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
        error:
          "Compte introuvable."
      });
    }

    res.json({
      success: true,
      account: {
        ...account,
        usd:
          Number(
            account.usd_cents || 0
          ) / 100
      }
    });
  }
);

// =========================
// TRANSACTIONS
// =========================

app.get(
  "/api/transactions",
  auth,
  (req, res) => {
    const transactions =
      db
        .prepare(`
          SELECT
            id,
            type,
            currency,
            amount_cdf,
            amount_usd_cents,
            description,
            created_at
          FROM transactions
          WHERE user_id = ?
          ORDER BY id DESC
        `)
        .all(req.user.id);

    res.json({
      success: true,
      transactions:
        transactions.map(
          (transaction) => ({
            ...transaction,
            amount_usd:
              Number(
                transaction.amount_usd_cents ||
                  0
              ) / 100
          })
        )
    });
  }
);

// =========================
// ADMIN USERS
// =========================

app.get(
  "/api/admin/users",
  auth,
  adminOnly,
  (req, res) => {
    const users =
      db
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
            w.usd_cents
          FROM users u
          LEFT JOIN wallets w
            ON w.user_id = u.id
          ORDER BY u.id DESC
        `)
        .all();

    res.json({
      success: true,
      users:
        users.map((user) => ({
          ...user,
          usd:
            Number(
              user.usd_cents || 0
            ) / 100
        }))
    });
  }
);

// =========================
// ADMIN CREDIT
// =========================

app.post(
  "/api/admin/credit",
  auth,
  adminOnly,
  (req, res) => {
    try {
      const {
        user_id,
        currency,
        amount,
        description
      } = req.body;

      const numericAmount =
        Number(amount);

      if (
        !user_id ||
        !currency ||
        !Number.isFinite(
          numericAmount
        )
      ) {
        return res.status(400).json({
          error:
            "Données de crédit invalides."
        });
      }

      if (numericAmount <= 0) {
        return res.status(400).json({
          error:
            "Le montant doit être supérieur à zéro."
        });
      }

      if (
        !["CDF", "USD"].includes(
          currency
        )
      ) {
        return res.status(400).json({
          error:
            "Devise invalide."
        });
      }

      const user =
        db
          .prepare(`
            SELECT
              id,
              name,
              status
            FROM users
            WHERE id = ?
          `)
          .get(Number(user_id));

      if (!user) {
        return res.status(404).json({
          error:
            "Utilisateur introuvable."
        });
      }

      if (user.status !== "active") {
        return res.status(400).json({
          error:
            "Le compte est bloqué."
        });
      }

      const credit =
        db.transaction(() => {
          if (currency === "CDF") {
            const amountCdf =
              Math.round(
                numericAmount
              );

            db.prepare(`
              UPDATE wallets
              SET cdf = cdf + ?
              WHERE user_id = ?
            `).run(
              amountCdf,
              user.id
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
              VALUES
              (?, 'credit', 'CDF', ?, 0, ?)
            `).run(
              user.id,
              amountCdf,
              description ||
                "Crédit administrateur"
            );
          }

          if (currency === "USD") {
            const amountUsdCents =
              Math.round(
                numericAmount * 100
              );

            db.prepare(`
              UPDATE wallets
              SET usd_cents =
                usd_cents + ?
              WHERE user_id = ?
            `).run(
              amountUsdCents,
              user.id
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
              VALUES
              (?, 'credit', 'USD', 0, ?, ?)
            `).run(
              user.id,
              amountUsdCents,
              description ||
                "Crédit administrateur"
            );
          }
        });

      credit();

      res.json({
        success: true,
        message:
          "Crédit effectué avec succès."
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          "Erreur lors du crédit."
      });
    }
  }
);

// =========================
// ADMIN BLOCK / UNBLOCK
// =========================

app.post(
  "/api/admin/block",
  auth,
  adminOnly,
  (req, res) => {
    const {
      user_id,
      blocked
    } = req.body;

    const user =
      db
        .prepare(`
          SELECT id, role
          FROM users
          WHERE id = ?
        `)
        .get(Number(user_id));

    if (!user) {
      return res.status(404).json({
        error:
          "Utilisateur introuvable."
      });
    }

    if (user.role === "admin") {
      return res.status(400).json({
        error:
          "Impossible de bloquer un administrateur."
      });
    }

    db.prepare(`
      UPDATE users
      SET status = ?
      WHERE id = ?
    `).run(
      blocked
        ? "blocked"
        : "active",
      user.id
    );

    res.json({
      success: true,
      message: blocked
        ? "Compte bloqué."
        : "Compte débloqué."
    });
  }
);

// =========================
// HEALTH CHECK
// =========================

app.get(
  "/api/health",
  (req, res) => {
    res.json({
      success: true,
      service: "DALZON Wallet",
      status: "online"
    });
  }
);

// =========================
// FRONTEND
// =========================

app.use(
  express.static(__dirname)
);

// IMPORTANT :
// Express 5 n'accepte pas app.get("*")
// ici. On utilise une RegExp.

app.get(/.*/, (req, res) => {
  res.sendFile(
    path.join(
      __dirname,
      "index.html"
    )
  );
});

// =========================
// START
// =========================

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `DALZON Wallet server running on port ${PORT}`
    );
  }
);