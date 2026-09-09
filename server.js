const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const path = require("path");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 10000;

const JWT_SECRET =
    process.env.JWT_SECRET ||
    "DALZON_WALLET_DEV_SECRET_CHANGE_ME";

const db = new Database(path.join(__dirname, "dalzon.db"));

/* =========================================================
   CONFIGURATION DATABASE
========================================================= */

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
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS cards (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE NOT NULL,
        card_number TEXT NOT NULL,
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

/* =========================================================
   MIDDLEWARES
========================================================= */

app.use(
    cors({
        origin: true,
        credentials: false
    })
);

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

/* =========================================================
   OUTILS
========================================================= */

function generateAccountId() {
    let accountId;

    do {
        accountId =
            "DLZ-" +
            crypto.randomInt(100000, 999999);
    } while (
        db.prepare(
            "SELECT id FROM users WHERE account_id = ?"
        ).get(accountId)
    );

    return accountId;
}

function generateCardNumber() {
    let number;

    do {
        number =
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
        ).get(number)
    );

    return number;
}

function generateExpiry() {
    const now = new Date();

    const year =
        String(now.getFullYear() + 4).slice(-2);

    const month =
        String(now.getMonth() + 1).padStart(2, "0");

    return `${month}/${year}`;
}

function normalizeEmail(email) {
    return String(email || "")
        .trim()
        .toLowerCase();
}

function sanitizeUser(user) {
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

/* =========================================================
   CREATION UTILISATEUR
========================================================= */

const createUser = db.transaction(
    ({
        name,
        email,
        passwordHash,
        role = "user"
    }) => {

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
            VALUES (?, ?, ?, ?, ?, 'active')
        `).run(
            accountId,
            name,
            email,
            passwordHash,
            role
        );

        const userId =
            Number(result.lastInsertRowid);

        db.prepare(`
            INSERT INTO wallets (
                user_id,
                cdf,
                usd_cents
            )
            VALUES (?, 0, 0)
        `).run(userId);

        /*
          Les administrateurs créés par create-admin.js
          peuvent ne pas avoir de carte.
          Les utilisateurs normaux en auront une.
        */

        if (role !== "admin") {
            db.prepare(`
                INSERT INTO cards (
                    user_id,
                    card_number,
                    expiry,
                    holder_name,
                    status
                )
                VALUES (?, ?, ?, ?, 'active')
            `).run(
                userId,
                generateCardNumber(),
                generateExpiry(),
                name
            );
        }

        return userId;
    }
);

/* =========================================================
   AUTHENTIFICATION
========================================================= */

function createToken(user) {
    return jwt.sign(
        {
            id: user.id,
            role: user.role
        },
        JWT_SECRET,
        {
            expiresIn: "7d"
        }
    );
}

function authMiddleware(req, res, next) {
    try {
        const authHeader =
            req.headers.authorization || "";

        if (!authHeader.startsWith("Bearer ")) {
            return res.status(401).json({
                success: false,
                message: "Authentification requise."
            });
        }

        const token =
            authHeader.substring(7);

        const decoded =
            jwt.verify(token, JWT_SECRET);

        const user =
            db.prepare(`
                SELECT
                    id,
                    account_id,
                    name,
                    email,
                    password_hash,
                    role,
                    status,
                    created_at
                FROM users
                WHERE id = ?
            `).get(decoded.id);

        if (!user) {
            return res.status(401).json({
                success: false,
                message: "Utilisateur introuvable."
            });
        }

        if (user.status !== "active") {
            return res.status(403).json({
                success: false,
                message: "Ce compte est bloqué."
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

function adminMiddleware(req, res, next) {

    if (!req.user) {
        return res.status(401).json({
            success: false,
            message: "Authentification requise."
        });
    }

    if (req.user.role !== "admin") {
        return res.status(403).json({
            success: false,
            message: "Accès administrateur requis."
        });
    }

    next();
}

/* =========================================================
   ROUTE DE SANTÉ
========================================================= */

app.get("/api/health", (req, res) => {

    res.json({
        success: true,
        status: "online",
        service: "DALZON Wallet API"
    });
});

/* =========================================================
   INSCRIPTION
========================================================= */

app.post("/api/auth/register", async (req, res) => {

    try {

        const name =
            String(req.body.name || "").trim();

        const email =
            normalizeEmail(req.body.email);

        const password =
            String(req.body.password || "");

        if (!name || !email || !password) {
            return res.status(400).json({
                success: false,
                message:
                    "Veuillez remplir tous les champs."
            });
        }

        if (name.length < 2) {
            return res.status(400).json({
                success: false,
                message:
                    "Le nom est trop court."
            });
        }

        if (password.length < 6) {
            return res.status(400).json({
                success: false,
                message:
                    "Le mot de passe doit contenir au moins 6 caractères."
            });
        }

        const existing =
            db.prepare(`
                SELECT id
                FROM users
                WHERE email = ?
            `).get(email);

        if (existing) {
            return res.status(409).json({
                success: false,
                message:
                    "Cette adresse email est déjà utilisée."
            });
        }

        const passwordHash =
            await bcrypt.hash(password, 12);

        const userId =
            createUser({
                name,
                email,
                passwordHash,
                role: "user"
            });

        const user =
            db.prepare(`
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
            `).get(userId);

        const token =
            createToken(user);

        res.status(201).json({
            success: true,
            message:
                "Compte créé avec succès.",
            token,
            user: sanitizeUser(user)
        });

    } catch (error) {

        console.error(
            "REGISTER ERROR:",
            error
        );

        res.status(500).json({
            success: false,
            message:
                "Erreur lors de la création du compte."
        });
    }
});

/* =========================================================
   CONNEXION
========================================================= */

app.post("/api/auth/login", async (req, res) => {

    try {

        const email =
            normalizeEmail(req.body.email);

        const password =
            String(req.body.password || "");

        if (!email || !password) {
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
            `).get(email);

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

        if (user.status !== "active") {
            return res.status(403).json({
                success: false,
                message:
                    "Ce compte est bloqué."
            });
        }

        const token =
            createToken(user);

        res.json({
            success: true,
            message:
                "Connexion réussie.",
            token,
            user: sanitizeUser(user)
        });

    } catch (error) {

        console.error(
            "LOGIN ERROR:",
            error
        );

        res.status(500).json({
            success: false,
            message:
                "Erreur lors de la connexion."
        });
    }
});

/* =========================================================
   COMPTE
========================================================= */

app.get(
    "/api/account",
    authMiddleware,
    (req, res) => {

        try {

            const user =
                db.prepare(`
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
                `).get(req.user.id);

            if (!user) {
                return res.status(404).json({
                    success: false,
                    message:
                        "Compte introuvable."
                });
            }

            const wallet =
                db.prepare(`
                    SELECT
                        cdf,
                        usd_cents
                    FROM wallets
                    WHERE user_id = ?
                `).get(req.user.id);

            const card =
                db.prepare(`
                    SELECT
                        card_number,
                        expiry,
                        holder_name,
                        status
                    FROM cards
                    WHERE user_id = ?
                `).get(req.user.id);

            const walletData = {
                CDF: wallet
                    ? wallet.cdf
                    : 0,

                USD: wallet
                    ? wallet.usd_cents / 100
                    : 0
            };

            /*
              IMPORTANT :
              On met wallet + card directement
              dans "user" afin de correspondre
              au index.html actuel.
            */

            const userData = {
                ...sanitizeUser(user),
                wallet: walletData,
                card: card || null
            };

            res.json({
                success: true,

                user: userData,

                account: {
                    ...userData,

                    cdf: walletData.CDF,
                    usd: walletData.USD,

                    wallet: walletData,

                    card: card || null
                }
            });

        } catch (error) {

            console.error(
                "ACCOUNT ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Impossible de charger le compte."
            });
        }
    }
);

/* =========================================================
   TRANSACTIONS
========================================================= */

app.get(
    "/api/transactions",
    authMiddleware,
    (req, res) => {

        try {

            const transactions =
                db.prepare(`
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
                    LIMIT 100
                `).all(req.user.id);

            const formatted =
                transactions.map((tx) => ({
                    id: tx.id,
                    type: tx.type,
                    currency: tx.currency,

                    amount_cdf:
                        tx.amount_cdf,

                    amount_usd_cents:
                        tx.amount_usd_cents,

                    amount_usd:
                        tx.amount_usd_cents / 100,

                    description:
                        tx.description,

                    created_at:
                        tx.created_at
                }));

            res.json({
                success: true,
                transactions: formatted
            });

        } catch (error) {

            console.error(
                "TRANSACTIONS ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Impossible de charger les transactions."
            });
        }
    }
);

/* =========================================================
   ADMIN : LISTE UTILISATEURS
========================================================= */

app.get(
    "/api/admin/users",
    authMiddleware,
    adminMiddleware,
    (req, res) => {

        try {

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

                        COALESCE(w.cdf, 0)
                            AS cdf,

                        COALESCE(w.usd_cents, 0)
                            AS usd_cents

                    FROM users u

                    LEFT JOIN wallets w
                        ON w.user_id = u.id

                    ORDER BY u.id DESC
                `).all();

            const result =
                users.map((user) => ({
                    id: user.id,
                    account_id: user.account_id,
                    name: user.name,
                    email: user.email,
                    role: user.role,
                    status: user.status,
                    created_at: user.created_at,

                    wallet: {
                        CDF: user.cdf,
                        USD: user.usd_cents / 100
                    }
                }));

            res.json({
                success: true,
                users: result
            });

        } catch (error) {

            console.error(
                "ADMIN USERS ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Impossible de charger les utilisateurs."
            });
        }
    }
);

/* =========================================================
   ADMIN : CRÉDITER UN COMPTE
========================================================= */

app.post(
    "/api/admin/credit",
    authMiddleware,
    adminMiddleware,
    (req, res) => {

        try {

            const userId =
                Number(
                    req.body.userId ??
                    req.body.user_id
                );

            const currency =
                String(
                    req.body.currency || ""
                ).toUpperCase();

            const amount =
                Number(req.body.amount);

            const description =
                String(
                    req.body.description ||
                    "Crédit administrateur"
                ).trim();

            if (
                !Number.isInteger(userId) ||
                userId <= 0
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Utilisateur invalide."
                });
            }

            if (
                currency !== "CDF" &&
                currency !== "USD"
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Devise invalide."
                });
            }

            if (
                !Number.isFinite(amount) ||
                amount <= 0
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Montant invalide."
                });
            }

            const user =
                db.prepare(`
                    SELECT id
                    FROM users
                    WHERE id = ?
                `).get(userId);

            if (!user) {
                return res.status(404).json({
                    success: false,
                    message:
                        "Utilisateur introuvable."
                });
            }

            const credit =
                db.transaction(() => {

                    if (currency === "CDF") {

                        const amountCDF =
                            Math.round(amount);

                        db.prepare(`
                            UPDATE wallets
                            SET cdf = cdf + ?
                            WHERE user_id = ?
                        `).run(
                            amountCDF,
                            userId
                        );

                        db.prepare(`
                            INSERT INTO transactions (
                                user_id,
                                type,
                                currency,
                                amount_cdf,
                                amount_usd_cents,
                                description
                            )
                            VALUES (
                                ?,
                                'credit',
                                'CDF',
                                ?,
                                0,
                                ?
                            )
                        `).run(
                            userId,
                            amountCDF,
                            description
                        );

                    } else {

                        const amountUSDCents =
                            Math.round(amount * 100);

                        db.prepare(`
                            UPDATE wallets
                            SET usd_cents =
                                usd_cents + ?
                            WHERE user_id = ?
                        `).run(
                            amountUSDCents,
                            userId
                        );

                        db.prepare(`
                            INSERT INTO transactions (
                                user_id,
                                type,
                                currency,
                                amount_cdf,
                                amount_usd_cents,
                                description
                            )
                            VALUES (
                                ?,
                                'credit',
                                'USD',
                                0,
                                ?,
                                ?
                            )
                        `).run(
                            userId,
                            amountUSDCents,
                            description
                        );
                    }

                });

            credit();

            const wallet =
                db.prepare(`
                    SELECT
                        cdf,
                        usd_cents
                    FROM wallets
                    WHERE user_id = ?
                `).get(userId);

            res.json({
                success: true,
                message:
                    "Compte crédité avec succès.",
                wallet: {
                    CDF: wallet.cdf,
                    USD: wallet.usd_cents / 100
                }
            });

        } catch (error) {

            console.error(
                "ADMIN CREDIT ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Impossible de créditer le compte."
            });
        }
    }
);

/* =========================================================
   ADMIN : BLOQUER / DÉBLOQUER
========================================================= */

app.post(
    "/api/admin/block",
    authMiddleware,
    adminMiddleware,
    (req, res) => {

        try {

            /*
              Compatible avec :
              userId
              ET
              user_id
            */

            const userId =
                Number(
                    req.body.userId ??
                    req.body.user_id
                );

            if (
                !Number.isInteger(userId) ||
                userId <= 0
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Utilisateur invalide."
                });
            }

            if (userId === req.user.id) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Vous ne pouvez pas bloquer votre propre compte."
                });
            }

            const user =
                db.prepare(`
                    SELECT
                        id,
                        status
                    FROM users
                    WHERE id = ?
                `).get(userId);

            if (!user) {
                return res.status(404).json({
                    success: false,
                    message:
                        "Utilisateur introuvable."
                });
            }

            /*
              Si le frontend envoie explicitement
              blocked=true/false, on le respecte.
              Sinon, on inverse l'état actuel.
            */

            let newStatus;

            if (
                typeof req.body.blocked === "boolean"
            ) {

                newStatus =
                    req.body.blocked
                        ? "blocked"
                        : "active";

            } else {

                newStatus =
                    user.status === "blocked"
                        ? "active"
                        : "blocked";
            }

            db.prepare(`
                UPDATE users
                SET status = ?
                WHERE id = ?
            `).run(
                newStatus,
                userId
            );

            res.json({
                success: true,

                message:
                    newStatus === "blocked"
                        ? "Utilisateur bloqué."
                        : "Utilisateur débloqué.",

                status: newStatus,

                blocked:
                    newStatus === "blocked"
            });

        } catch (error) {

            console.error(
                "ADMIN BLOCK ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Impossible de modifier le statut."
            });
        }
    }
);

/* =========================================================
   ADMIN : INFORMATIONS UTILISATEUR
========================================================= */

app.get(
    "/api/admin/users/:id",
    authMiddleware,
    adminMiddleware,
    (req, res) => {

        try {

            const userId =
                Number(req.params.id);

            const user =
                db.prepare(`
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
                `).get(userId);

            if (!user) {
                return res.status(404).json({
                    success: false,
                    message:
                        "Utilisateur introuvable."
                });
            }

            const wallet =
                db.prepare(`
                    SELECT
                        cdf,
                        usd_cents
                    FROM wallets
                    WHERE user_id = ?
                `).get(userId);

            const transactions =
                db.prepare(`
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
                    LIMIT 100
                `).all(userId);

            res.json({
                success: true,

                user: {
                    ...sanitizeUser(user),

                    wallet: {
                        CDF: wallet
                            ? wallet.cdf
                            : 0,

                        USD: wallet
                            ? wallet.usd_cents / 100
                            : 0
                    }
                },

                transactions:
                    transactions.map((tx) => ({
                        ...tx,
                        amount_usd:
                            tx.amount_usd_cents / 100
                    }))
            });

        } catch (error) {

            console.error(
                "ADMIN USER ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Impossible de charger l'utilisateur."
            });
        }
    }
);

/* =========================================================
   SERVIR LE SITE
========================================================= */

app.use(
    express.static(__dirname)
);

app.get("/", (req, res) => {

    res.sendFile(
        path.join(
            __dirname,
            "index.html"
        )
    );
});

/* =========================================================
   API 404
========================================================= */

app.use("/api", (req, res) => {

    res.status(404).json({
        success: false,
        message:
            "Route API introuvable."
    });
});

/* =========================================================
   ERREUR GLOBALE
========================================================= */

app.use((error, req, res, next) => {

    console.error(
        "SERVER ERROR:",
        error
    );

    if (res.headersSent) {
        return next(error);
    }

    res.status(500).json({
        success: false,
        message:
            "Une erreur interne du serveur est survenue."
    });
});

/* =========================================================
   DÉMARRAGE
========================================================= */

app.listen(PORT, "0.0.0.0", () => {

    console.log("");
    console.log("========================================");
    console.log("        DALZON WALLET API");
    console.log("========================================");
    console.log(`Serveur démarré sur le port ${PORT}`);
    console.log(`Mode : ${process.env.NODE_ENV || "development"}`);
    console.log("Database : dalzon.db");
    console.log("========================================");
    console.log("");
});