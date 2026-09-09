const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const path = require("path");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 3000;
const JWT_SECRET =
  process.env.JWT_SECRET || "DALZON_SIMULATION_CHANGE_THIS_SECRET";

app.use(express.json());
app.use(express.static(__dirname));

// =====================================================
// BASE DE DONNÉES
// =====================================================

const db = new Database(
  path.join(__dirname, "dalzon.db")
);

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

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

    FOREIGN KEY(user_id)
    REFERENCES users(id)
    ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER UNIQUE NOT NULL,
    card_number TEXT UNIQUE NOT NULL,
    expiry TEXT NOT NULL,

    FOREIGN KEY(user_id)
    REFERENCES users(id)
    ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    currency TEXT NOT NULL,
    amount INTEGER NOT NULL,
    description TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY(user_id)
    REFERENCES users(id)
    ON DELETE CASCADE
);
`);

// =====================================================
// GÉNÉRATION DES IDENTIFIANTS
// =====================================================

function generateAccountId() {
    let accountId;

    do {
        accountId =
            "DLZ-" +
            crypto.randomInt(10000, 99999);
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
        cardNumber =
            "DLZ " +
            crypto.randomInt(1000, 9999) +
            " " +
            crypto.randomInt(1000, 9999) +
            " " +
            crypto.randomInt(1000, 9999) +
            " " +
            crypto.randomInt(1000, 9999);
    } while (
        db.prepare(
            "SELECT id FROM cards WHERE card_number = ?"
        ).get(cardNumber)
    );

    return cardNumber;
}

function generateExpiry() {
    const date = new Date();

    const month = String(
        date.getMonth() + 1
    ).padStart(2, "0");

    const year = String(
        date.getFullYear() + 4
    ).slice(-2);

    return `${month}/${year}`;
}

// =====================================================
// FORMAT UTILISATEUR
// =====================================================

function getUserData(user) {

    const wallet = db.prepare(`
        SELECT cdf, usd_cents
        FROM wallets
        WHERE user_id = ?
    `).get(user.id);

    const card = db.prepare(`
        SELECT card_number, expiry
        FROM cards
        WHERE user_id = ?
    `).get(user.id);

    const transactions = db.prepare(`
        SELECT
            id,
            type,
            currency,
            amount,
            description,
            created_at
        FROM transactions
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 50
    `).all(user.id);

    return {

        id: user.account_id,

        name: user.name,

        email: user.email,

        role: user.role,

        status: user.status,

        wallet: {

            CDF: wallet
                ? wallet.cdf
                : 0,

            USD: wallet
                ? wallet.usd_cents / 100
                : 0
        },

        card: card
            ? {
                number: card.card_number,
                expiry: card.expiry
            }
            : null,

        transactions
    };
}

// =====================================================
// AUTHENTIFICATION
// =====================================================

function authenticate(req, res, next) {

    const authorization =
        req.headers.authorization;

    if (
        !authorization ||
        !authorization.startsWith("Bearer ")
    ) {

        return res.status(401).json({
            success: false,
            message: "Authentification requise."
        });
    }

    const token =
        authorization.substring(7);

    try {

        const decoded =
            jwt.verify(
                token,
                JWT_SECRET
            );

        const user =
            db.prepare(`
                SELECT *
                FROM users
                WHERE id = ?
            `).get(decoded.userId);

        if (!user) {

            return res.status(401).json({
                success: false,
                message: "Utilisateur introuvable."
            });
        }

        if (user.status !== "active") {

            return res.status(403).json({
                success: false,
                message: "Compte bloqué."
            });
        }

        req.user = user;

        next();

    } catch (error) {

        return res.status(401).json({
            success: false,
            message: "Session invalide ou expirée."
        });
    }
}

// =====================================================
// ADMIN
// =====================================================

function requireAdmin(req, res, next) {

    if (req.user.role !== "admin") {

        return res.status(403).json({
            success: false,
            message: "Accès administrateur refusé."
        });
    }

    next();
}

// =====================================================
// INSCRIPTION
// =====================================================

app.post(
    "/api/auth/register",
    async (req, res) => {

        try {

            const {
                name,
                email,
                password
            } = req.body;

            if (
                !name ||
                !email ||
                !password
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Nom, email et mot de passe sont obligatoires."
                });
            }

            if (password.length < 6) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Le mot de passe doit contenir au moins 6 caractères."
                });
            }

            const normalizedEmail =
                String(email)
                    .trim()
                    .toLowerCase();

            const existing =
                db.prepare(`
                    SELECT id
                    FROM users
                    WHERE email = ?
                `).get(normalizedEmail);

            if (existing) {

                return res.status(409).json({
                    success: false,
                    message:
                        "Cette adresse email est déjà utilisée."
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
                        db.prepare(`
                            INSERT INTO users
                            (
                                account_id,
                                name,
                                email,
                                password_hash,
                                role
                            )
                            VALUES (?, ?, ?, ?, 'user')
                        `).run(
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
                            expiry
                        )
                        VALUES (?, ?, ?)
                    `).run(
                        userId,
                        generateCardNumber(),
                        generateExpiry()
                    );

                    return userId;
                });

            const userId =
                createAccount();

            const user =
                db.prepare(`
                    SELECT *
                    FROM users
                    WHERE id = ?
                `).get(userId);

            const token =
                jwt.sign(
                    {
                        userId: user.id
                    },
                    JWT_SECRET,
                    {
                        expiresIn: "7d"
                    }
                );

            res.json({

                success: true,

                message:
                    "Compte DALZON créé.",

                token,

                user:
                    getUserData(user)
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message:
                    "Erreur lors de la création du compte."
            });
        }
    }
);

// =====================================================
// CONNEXION
// =====================================================

app.post(
    "/api/auth/login",
    async (req, res) => {

        try {

            const {
                email,
                password
            } = req.body;

            if (
                !email ||
                !password
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Email et mot de passe requis."
                });
            }

            const user =
                db.prepare(`
                    SELECT *
                    FROM users
                    WHERE email = ?
                `).get(
                    String(email)
                        .trim()
                        .toLowerCase()
                );

            if (!user) {

                return res.status(401).json({
                    success: false,
                    message:
                        "Email ou mot de passe incorrect."
                });
            }

            const valid =
                await bcrypt.compare(
                    password,
                    user.password_hash
                );

            if (!valid) {

                return res.status(401).json({
                    success: false,
                    message:
                        "Email ou mot de passe incorrect."
                });
            }

            if (
                user.status !== "active"
            ) {

                return res.status(403).json({
                    success: false,
                    message:
                        "Ce compte est bloqué."
                });
            }

            const token =
                jwt.sign(
                    {
                        userId: user.id
                    },
                    JWT_SECRET,
                    {
                        expiresIn: "7d"
                    }
                );

            res.json({

                success: true,

                message:
                    "Connexion réussie.",

                token,

                user:
                    getUserData(user)
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message:
                    "Erreur serveur."
            });
        }
    }
);

// =====================================================
// COMPTE CONNECTÉ
// =====================================================

app.get(
    "/api/account",
    authenticate,
    (req, res) => {

        res.json({

            success: true,

            user:
                getUserData(req.user)
        });
    }
);

// =====================================================
// UTILISATEURS — ADMIN
// =====================================================

app.get(
    "/api/admin/users",
    authenticate,
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
                    w.cdf,
                    w.usd_cents
                FROM users u
                LEFT JOIN wallets w
                    ON w.user_id = u.id
                ORDER BY u.id DESC
            `).all();

        res.json({

            success: true,

            users:
                users.map(user => ({

                    id: user.account_id,

                    name: user.name,

                    email: user.email,

                    role: user.role,

                    status: user.status,

                    createdAt:
                        user.created_at,

                    wallet: {

                        CDF:
                            user.cdf || 0,

                        USD:
                            (user.usd_cents || 0) /
                            100
                    }
                }))
        });
    }
);

// =====================================================
// CRÉDIT CDF / USD — ADMIN
// =====================================================

app.post(
    "/api/admin/credit",
    authenticate,
    requireAdmin,
    (req, res) => {

        const {
            accountId,
            currency,
            amount,
            description
        } = req.body;

        if (
            !accountId ||
            !currency ||
            amount === undefined
        ) {

            return res.status(400).json({
                success: false,
                message:
                    "Informations incomplètes."
            });
        }

        if (
            currency !== "CDF" &&
            currency !== "USD"
        ) {

            return res.status(400).json({
                success: false,
                message:
                    "Devise non autorisée."
            });
        }

        const numericAmount =
            Number(amount);

        if (
            !Number.isFinite(
                numericAmount
            ) ||
            numericAmount <= 0
        ) {

            return res.status(400).json({
                success: false,
                message:
                    "Montant invalide."
            });
        }

        const target =
            db.prepare(`
                SELECT *
                FROM users
                WHERE account_id = ?
            `).get(accountId);

        if (!target) {

            return res.status(404).json({
                success: false,
                message:
                    "Utilisateur introuvable."
            });
        }

        if (
            target.status !== "active"
        ) {

            return res.status(400).json({
                success: false,
                message:
                    "Ce compte est bloqué."
            });
        }

        let storedAmount;

        if (currency === "CDF") {

            if (
                !Number.isInteger(
                    numericAmount
                )
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Le montant CDF doit être entier."
                });
            }

            storedAmount =
                numericAmount;

        } else {

            storedAmount =
                Math.round(
                    numericAmount * 100
                );
        }

        const credit =
            db.transaction(() => {

                if (currency === "CDF") {

                    db.prepare(`
                        UPDATE wallets
                        SET cdf = cdf + ?
                        WHERE user_id = ?
                    `).run(
                        storedAmount,
                        target.id
                    );

                } else {

                    db.prepare(`
                        UPDATE wallets
                        SET usd_cents =
                            usd_cents + ?
                        WHERE user_id = ?
                    `).run(
                        storedAmount,
                        target.id
                    );
                }

                db.prepare(`
                    INSERT INTO transactions
                    (
                        user_id,
                        type,
                        currency,
                        amount,
                        description
                    )
                    VALUES (?, 'credit', ?, ?, ?)
                `).run(
                    target.id,
                    currency,
                    storedAmount,
                    description ||
                    "Crédit attribué par l'administration"
                );
            });

        credit();

        const updatedUser =
            db.prepare(`
                SELECT *
                FROM users
                WHERE id = ?
            `).get(target.id);

        res.json({

            success: true,

            message:
                "Crédit ajouté avec succès.",

            user:
                getUserData(updatedUser)
        });
    }
);

// =====================================================
// BLOQUER / DÉBLOQUER UN COMPTE
// =====================================================

app.post(
    "/api/admin/block",
    authenticate,
    requireAdmin,
    (req, res) => {

        const {
            accountId,
            blocked
        } = req.body;

        if (!accountId) {

            return res.status(400).json({
                success: false,
                message:
                    "Identifiant requis."
            });
        }

        const target =
            db.prepare(`
                SELECT *
                FROM users
                WHERE account_id = ?
            `).get(accountId);

        if (!target) {

            return res.status(404).json({
                success: false,
                message:
                    "Utilisateur introuvable."
            });
        }

        if (
            target.role === "admin"
        ) {

            return res.status(400).json({
                success: false,
                message:
                    "Le compte administrateur ne peut pas être bloqué."
            });
        }

        const status =
            blocked
                ? "blocked"
                : "active";

        db.prepare(`
            UPDATE users
            SET status = ?
            WHERE id = ?
        `).run(
            status,
            target.id
        );

        res.json({

            success: true,

            message:
                blocked
                    ? "Compte bloqué."
                    : "Compte débloqué."
        });
    }
);

// =====================================================
// HISTORIQUE
// =====================================================

app.get(
    "/api/transactions",
    authenticate,
    (req, res) => {

        const transactions =
            db.prepare(`
                SELECT
                    id,
                    type,
                    currency,
                    amount,
                    description,
                    created_at
                FROM transactions
                WHERE user_id = ?
                ORDER BY id DESC
                LIMIT 100
            `).all(req.user.id);

        res.json({

            success: true,

            transactions:
                transactions.map(t => ({

                    ...t,

                    amount:
                        t.currency === "USD"
                            ? t.amount / 100
                            : t.amount
                }))
        });
    }
);

// =====================================================
// ROUTE PRINCIPALE
// =====================================================

app.get("*", (req, res) => {

    res.sendFile(
        path.join(
            __dirname,
            "index.html"
        )
    );
});

// =====================================================
// DÉMARRAGE
// =====================================================

app.listen(
    PORT,
    () => {

        console.log("");
        console.log(
            "================================="
        );
        console.log(
            "       DALZON WALLET SERVER"
        );
        console.log(
            "================================="
        );
        console.log(
            `Serveur : http://localhost:${PORT}`
        );
        console.log(
            "Base : dalzon.db"
        );
        console.log(
            "================================="
        );
        console.log("");
    }
);