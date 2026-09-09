"use strict";

/*
============================================================
 DALZON WALLET v2.2
 Backend — Express + SQLite + JWT
 Simulation éducative CDF / USD
============================================================
*/

const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const path = require("path");

/* =========================================================
   CONFIGURATION
========================================================= */

const app = express();

const PORT =
    Number(process.env.PORT) || 3000;

const JWT_SECRET =
    process.env.JWT_SECRET ||
    "DALZON_WALLET_CHANGE_THIS_SECRET_2026";

const JWT_EXPIRES =
    process.env.JWT_EXPIRES ||
    "7d";

const DB_PATH =
    process.env.DB_PATH ||
    path.join(__dirname, "dalzon.db");


/* =========================================================
   EXPRESS
========================================================= */

app.disable("x-powered-by");

app.use(
    express.json({
        limit: "100kb"
    })
);

app.use(
    express.urlencoded({
        extended: false,
        limit: "100kb"
    })
);


/* =========================================================
   CORS
========================================================= */

app.use(
    (req, res, next) => {

        res.setHeader(
            "Access-Control-Allow-Origin",
            "*"
        );

        res.setHeader(
            "Access-Control-Allow-Methods",
            "GET,POST,PUT,PATCH,DELETE,OPTIONS"
        );

        res.setHeader(
            "Access-Control-Allow-Headers",
            "Content-Type, Authorization"
        );

        if(req.method === "OPTIONS"){
            return res.sendStatus(204);
        }

        next();
    }
);


/* =========================================================
   SQLITE
========================================================= */

const db =
    new Database(DB_PATH);

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.pragma("busy_timeout = 5000");


/* =========================================================
   TABLES
========================================================= */

db.exec(`
    CREATE TABLE IF NOT EXISTS users (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        account_id TEXT NOT NULL UNIQUE,

        name TEXT NOT NULL,

        email TEXT NOT NULL UNIQUE,

        password_hash TEXT NOT NULL,

        role TEXT NOT NULL DEFAULT 'user',

        status TEXT NOT NULL DEFAULT 'active',

        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP

    );


    CREATE TABLE IF NOT EXISTS wallets (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        user_id INTEGER NOT NULL UNIQUE,

        cdf INTEGER NOT NULL DEFAULT 0,

        usd_cents INTEGER NOT NULL DEFAULT 0,

        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

        FOREIGN KEY(user_id)
            REFERENCES users(id)
            ON DELETE CASCADE

    );


    CREATE TABLE IF NOT EXISTS cards (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        user_id INTEGER NOT NULL UNIQUE,

        card_number TEXT NOT NULL UNIQUE,

        expiry TEXT NOT NULL,

        status TEXT NOT NULL DEFAULT 'active',

        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

        FOREIGN KEY(user_id)
            REFERENCES users(id)
            ON DELETE CASCADE

    );


    CREATE TABLE IF NOT EXISTS transactions (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        user_id INTEGER NOT NULL,

        type TEXT NOT NULL,

        currency TEXT NOT NULL,

        amount_cdf INTEGER NOT NULL DEFAULT 0,

        amount_usd_cents INTEGER NOT NULL DEFAULT 0,

        description TEXT,

        reference TEXT,

        related_user_id INTEGER,

        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

        FOREIGN KEY(user_id)
            REFERENCES users(id)
            ON DELETE CASCADE,

        FOREIGN KEY(related_user_id)
            REFERENCES users(id)
            ON DELETE SET NULL

    );


    CREATE INDEX IF NOT EXISTS
        idx_transactions_user
    ON transactions(user_id);


    CREATE INDEX IF NOT EXISTS
        idx_transactions_created
    ON transactions(created_at);


    CREATE INDEX IF NOT EXISTS
        idx_users_account
    ON users(account_id);


    CREATE INDEX IF NOT EXISTS
        idx_users_email
    ON users(email);
`);


/* =========================================================
   MIGRATION DE SÉCURITÉ
========================================================= */

/*
 Si une ancienne version utilisait amount_usd,
 on ne la lit jamais.
 La v2.2 utilise uniquement :

 amount_cdf
 amount_usd_cents
*/


/* =========================================================
   OUTILS
========================================================= */

function cleanText(
    value,
    maxLength = 200
){

    if(value === undefined || value === null){
        return "";
    }

    return String(value)
        .trim()
        .slice(0, maxLength);
}


function normalizeEmail(email){

    return cleanText(
        email,
        160
    ).toLowerCase();
}


function isValidEmail(email){

    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/
        .test(email);
}


function generateAccountId(){

    let accountId;

    do{

        accountId =
            "DLZ-" +
            new Date().getFullYear() +
            "-" +
            crypto
                .randomInt(
                    100000,
                    999999
                );

    }while(
        db.prepare(`
            SELECT id
            FROM users
            WHERE account_id = ?
        `).get(accountId)
    );

    return accountId;
}


function generateCardNumber(){

    let cardNumber;

    do{

        const a =
            crypto.randomInt(
                1000,
                9999
            );

        const b =
            crypto.randomInt(
                1000,
                9999
            );

        const c =
            crypto.randomInt(
                1000,
                9999
            );

        cardNumber =
            `DLZ ${a} ${b} ${c}`;

    }while(
        db.prepare(`
            SELECT id
            FROM cards
            WHERE card_number = ?
        `).get(cardNumber)
    );

    return cardNumber;
}


function generateExpiry(){

    const now =
        new Date();

    const year =
        now.getFullYear() + 4;

    const month =
        String(
            now.getMonth() + 1
        ).padStart(2,"0");

    return `${month}/${String(year).slice(-2)}`;
}


/*
 USD :

 frontend envoie par exemple :

 25.50

 serveur convertit :

 2550 cents
*/

function usdToCents(value){

    const number =
        Number(value);

    if(
        !Number.isFinite(number) ||
        number <= 0
    ){
        return null;
    }

    const cents =
        Math.round(
            number * 100
        );

    if(cents <= 0){
        return null;
    }

    return cents;
}


/*
 CDF :

 on travaille avec des nombres entiers.
*/

function cdfAmount(value){

    const number =
        Number(value);

    if(
        !Number.isFinite(number) ||
        number <= 0
    ){
        return null;
    }

    const amount =
        Math.round(number);

    if(amount <= 0){
        return null;
    }

    return amount;
}


function normalizeCurrency(currency){

    const value =
        String(
            currency || ""
        )
        .trim()
        .toUpperCase();

    if(
        value !== "CDF" &&
        value !== "USD"
    ){
        return null;
    }

    return value;
}


/* =========================================================
   JWT
========================================================= */

function createToken(user){

    return jwt.sign(
        {
            id: user.id,
            account_id: user.account_id,
            role: user.role
        },
        JWT_SECRET,
        {
            expiresIn: JWT_EXPIRES
        }
    );
}


/* =========================================================
   AUTH MIDDLEWARE
========================================================= */

function authenticate(
    req,
    res,
    next
){

    const header =
        req.headers.authorization || "";

    if(
        !header.startsWith("Bearer ")
    ){

        return res.status(401).json({
            error:
                "Authentification requise."
        });
    }

    const token =
        header.slice(7).trim();

    if(!token){

        return res.status(401).json({
            error:
                "Session invalide."
        });
    }

    try{

        const decoded =
            jwt.verify(
                token,
                JWT_SECRET
            );

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
            `).get(decoded.id);

        if(!user){

            return res.status(401).json({
                error:
                    "Compte introuvable."
            });
        }

        if(
            user.status !== "active"
        ){

            return res.status(403).json({
                error:
                    "Votre compte est bloqué."
            });
        }

        req.user = user;

        next();

    }catch(error){

        return res.status(401).json({
            error:
                "Session invalide ou expirée."
        });
    }
}


/* =========================================================
   ADMIN MIDDLEWARE
========================================================= */

function requireAdmin(
    req,
    res,
    next
){

    if(
        !req.user ||
        req.user.role !== "admin"
    ){

        return res.status(403).json({
            error:
                "Accès administrateur refusé."
        });
    }

    next();
}


/* =========================================================
   WALLET
========================================================= */

function getWallet(
    userId
){

    return db.prepare(`
        SELECT
            cdf,
            usd_cents
        FROM wallets
        WHERE user_id = ?
    `).get(userId);
}


function getCard(
    userId
){

    return db.prepare(`
        SELECT
            card_number,
            expiry,
            status
        FROM cards
        WHERE user_id = ?
    `).get(userId);
}


/* =========================================================
   UTILISATEUR POUR FRONTEND
========================================================= */

function publicUser(
    userId
){

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

    if(!user){
        return null;
    }

    const wallet =
        getWallet(userId);

    const card =
        getCard(userId);

    return {

        id:
            user.id,

        account_id:
            user.account_id,

        name:
            user.name,

        email:
            user.email,

        role:
            user.role,

        status:
            user.status,

        created_at:
            user.created_at,

        wallet:{
            CDF:
                wallet
                    ? wallet.cdf
                    : 0,

            USD:
                wallet
                    ? wallet.usd_cents / 100
                    : 0
        },

        card:
            card
                ? {
                    number:
                        card.card_number,

                    expiry:
                        card.expiry,

                    status:
                        card.status
                  }
                : null
    };
}


/* =========================================================
   HEALTH
========================================================= */

app.get(
    "/api/health",
    (req,res) => {

        res.json({

            ok:true,

            app:
                "DALZON Wallet",

            version:
                "2.2",

            mode:
                "educational-simulation",

            database:
                "sqlite",

            time:
                new Date().toISOString()
        });
    }
);


/* =========================================================
   ROOT
========================================================= */

app.get(
    "/",
    (req,res) => {

        res.json({

            app:
                "DALZON Wallet",

            version:
                "2.2",

            status:
                "online",

            message:
                "DALZON Wallet API opérationnelle."
        });
    }
);


/* =========================================================
   REGISTER
========================================================= */

app.post(
    "/api/auth/register",
    async (req,res) => {

        try{

            const name =
                cleanText(
                    req.body.name,
                    100
                );

            const email =
                normalizeEmail(
                    req.body.email
                );

            const password =
                String(
                    req.body.password || ""
                );

            if(
                !name ||
                !email ||
                !password
            ){

                return res.status(400).json({
                    error:
                        "Tous les champs sont obligatoires."
                });
            }

            if(
                name.length < 2
            ){

                return res.status(400).json({
                    error:
                        "Nom invalide."
                });
            }

            if(
                !isValidEmail(email)
            ){

                return res.status(400).json({
                    error:
                        "Adresse email invalide."
                });
            }

            if(
                password.length < 6
            ){

                return res.status(400).json({
                    error:
                        "Le mot de passe doit contenir au moins 6 caractères."
                });
            }

            const exists =
                db.prepare(`
                    SELECT id
                    FROM users
                    WHERE email = ?
                `).get(email);

            if(exists){

                return res.status(409).json({
                    error:
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

            const cardNumber =
                generateCardNumber();

            const expiry =
                generateExpiry();

            const createUser =
                db.transaction(() => {

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
                            VALUES (
                                ?,
                                ?,
                                ?,
                                ?,
                                'user',
                                'active'
                            )
                        `).run(
                            accountId,
                            name,
                            email,
                            passwordHash
                        );

                    const userId =
                        Number(
                            result.lastInsertRowid
                        );

                    db.prepare(`
                        INSERT INTO wallets (
                            user_id,
                            cdf,
                            usd_cents
                        )
                        VALUES (
                            ?,
                            0,
                            0
                        )
                    `).run(userId);

                    db.prepare(`
                        INSERT INTO cards (
                            user_id,
                            card_number,
                            expiry,
                            status
                        )
                        VALUES (
                            ?,
                            ?,
                            ?,
                            'active'
                        )
                    `).run(
                        userId,
                        cardNumber,
                        expiry
                    );

                    return userId;
                });

            const userId =
                createUser();

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

            return res.status(201).json({

                message:
                    "Compte créé avec succès.",

                token,

                user:
                    publicUser(userId)
            });

        }catch(error){

            console.error(
                "REGISTER ERROR:",
                error
            );

            return res.status(500).json({
                error:
                    "Impossible de créer le compte."
            });
        }
    }
);


/* =========================================================
   LOGIN
========================================================= */

app.post(
    "/api/auth/login",
    async (req,res) => {

        try{

            const email =
                normalizeEmail(
                    req.body.email
                );

            const password =
                String(
                    req.body.password || ""
                );

            if(
                !email ||
                !password
            ){

                return res.status(400).json({
                    error:
                        "Email et mot de passe requis."
                });
            }

            const user =
                db.prepare(`
                    SELECT *
                    FROM users
                    WHERE email = ?
                `).get(email);

            if(!user){

                return res.status(401).json({
                    error:
                        "Email ou mot de passe incorrect."
                });
            }

            const valid =
                await bcrypt.compare(
                    password,
                    user.password_hash
                );

            if(!valid){

                return res.status(401).json({
                    error:
                        "Email ou mot de passe incorrect."
                });
            }

            if(
                user.status !== "active"
            ){

                return res.status(403).json({
                    error:
                        "Votre compte est bloqué."
                });
            }

            const token =
                createToken(user);

            return res.json({

                message:
                    "Connexion réussie.",

                token,

                user:
                    publicUser(
                        user.id
                    )
            });

        }catch(error){

            console.error(
                "LOGIN ERROR:",
                error
            );

            return res.status(500).json({
                error:
                    "Connexion impossible."
            });
        }
    }
);


/* =========================================================
   ACCOUNT
========================================================= */

app.get(
    "/api/account",
    authenticate,
    (req,res) => {

        const user =
            publicUser(
                req.user.id
            );

        if(!user){

            return res.status(404).json({
                error:
                    "Compte introuvable."
            });
        }

        res.json({
            user
        });
    }
);


/* =========================================================
   TRANSACTIONS
========================================================= */

app.get(
    "/api/transactions",
    authenticate,
    (req,res) => {

        try{

            const rows =
                db.prepare(`
                    SELECT
                        id,
                        type,
                        currency,
                        amount_cdf,
                        amount_usd_cents,
                        description,
                        reference,
                        related_user_id,
                        created_at
                    FROM transactions
                    WHERE user_id = ?
                    ORDER BY id DESC
                    LIMIT 100
                `).all(
                    req.user.id
                );

            const transactions =
                rows.map(
                    row => ({

                        id:
                            row.id,

                        type:
                            row.type,

                        currency:
                            row.currency,

                        amount_cdf:
                            row.amount_cdf,

                        amount_usd_cents:
                            row.amount_usd_cents,

                        description:
                            row.description,

                        reference:
                            row.reference,

                        related_user_id:
                            row.related_user_id,

                        created_at:
                            row.created_at
                    })
                );

            res.json({
                transactions
            });

        }catch(error){

            console.error(
                "TRANSACTIONS ERROR:",
                error
            );

            res.status(500).json({
                error:
                    "Impossible de charger l'historique."
            });
        }
    }
);


/* =========================================================
   TRANSFERT
========================================================= */

app.post(
    "/api/transfer",
    authenticate,
    (req,res) => {

        try{

            const recipientInput =
                cleanText(
                    req.body.recipient,
                    100
                );

            const currency =
                normalizeCurrency(
                    req.body.currency
                );

            const description =
                cleanText(
                    req.body.description,
                    120
                ) ||
                "Transfert DALZON";

            if(
                !recipientInput ||
                !currency
            ){

                return res.status(400).json({
                    error:
                        "Informations de transfert invalides."
                });
            }

            let amount;

            if(currency === "USD"){

                amount =
                    usdToCents(
                        req.body.amount
                    );

            }else{

                amount =
                    cdfAmount(
                        req.body.amount
                    );
            }

            if(amount === null){

                return res.status(400).json({
                    error:
                        "Montant invalide."
                });
            }

            const recipient =
                db.prepare(`
                    SELECT
                        id,
                        account_id,
                        name,
                        email,
                        status
                    FROM users
                    WHERE
                        account_id = ?
                        OR email = ?
                    LIMIT 1
                `).get(
                    recipientInput,
                    recipientInput.toLowerCase()
                );

            if(!recipient){

                return res.status(404).json({
                    error:
                        "Compte destinataire introuvable."
                });
            }

            if(
                Number(recipient.id) ===
                Number(req.user.id)
            ){

                return res.status(400).json({
                    error:
                        "Vous ne pouvez pas vous envoyer un transfert à vous-même."
                });
            }

            if(
                recipient.status !== "active"
            ){

                return res.status(400).json({
                    error:
                        "Le compte destinataire est bloqué."
                });
            }

            const senderWallet =
                getWallet(
                    req.user.id
                );

            if(!senderWallet){

                return res.status(404).json({
                    error:
                        "Portefeuille introuvable."
                });
            }

            if(currency === "CDF"){

                if(
                    senderWallet.cdf <
                    amount
                ){

                    return res.status(400).json({
                        error:
                            "Solde CDF insuffisant."
                    });
                }

            }else{

                if(
                    senderWallet.usd_cents <
                    amount
                ){

                    return res.status(400).json({
                        error:
                            "Solde USD insuffisant."
                    });
                }
            }

            const reference =
                "TRF-" +
                crypto
                    .randomBytes(5)
                    .toString("hex")
                    .toUpperCase();

            const transfer =
                db.transaction(() => {

                    if(currency === "CDF"){

                        db.prepare(`
                            UPDATE wallets
                            SET
                                cdf = cdf - ?,
                                updated_at = CURRENT_TIMESTAMP
                            WHERE user_id = ?
                        `).run(
                            amount,
                            req.user.id
                        );

                        db.prepare(`
                            UPDATE wallets
                            SET
                                cdf = cdf + ?,
                                updated_at = CURRENT_TIMESTAMP
                            WHERE user_id = ?
                        `).run(
                            amount,
                            recipient.id
                        );

                    }else{

                        db.prepare(`
                            UPDATE wallets
                            SET
                                usd_cents =
                                    usd_cents - ?,
                                updated_at =
                                    CURRENT_TIMESTAMP
                            WHERE user_id = ?
                        `).run(
                            amount,
                            req.user.id
                        );

                        db.prepare(`
                            UPDATE wallets
                            SET
                                usd_cents =
                                    usd_cents + ?,
                                updated_at =
                                    CURRENT_TIMESTAMP
                            WHERE user_id = ?
                        `).run(
                            amount,
                            recipient.id
                        );
                    }

                    db.prepare(`
                        INSERT INTO transactions (
                            user_id,
                            type,
                            currency,
                            amount_cdf,
                            amount_usd_cents,
                            description,
                            reference,
                            related_user_id
                        )
                        VALUES (
                            ?,
                            'debit',
                            ?,
                            ?,
                            ?,
                            ?,
                            ?,
                            ?
                        )
                    `).run(
                        req.user.id,
                        currency,
                        currency === "CDF"
                            ? amount
                            : 0,
                        currency === "USD"
                            ? amount
                            : 0,
                        description,
                        reference,
                        recipient.id
                    );

                    db.prepare(`
                        INSERT INTO transactions (
                            user_id,
                            type,
                            currency,
                            amount_cdf,
                            amount_usd_cents,
                            description,
                            reference,
                            related_user_id
                        )
                        VALUES (
                            ?,
                            'credit',
                            ?,
                            ?,
                            ?,
                            ?,
                            ?,
                            ?
                        )
                    `).run(
                        recipient.id,
                        currency,
                        currency === "CDF"
                            ? amount
                            : 0,
                        currency === "USD"
                            ? amount
                            : 0,
                        "Réception de " +
                            req.user.account_id,
                        reference,
                        req.user.id
                    );
                });

            transfer();

            res.json({

                message:
                    "Transfert effectué.",

                reference,

                recipient:{
                    account_id:
                        recipient.account_id,

                    name:
                        recipient.name
                },

                currency,

                amount:
                    currency === "USD"
                        ? amount / 100
                        : amount
            });

        }catch(error){

            console.error(
                "TRANSFER ERROR:",
                error
            );

            res.status(500).json({
                error:
                    "Impossible d'effectuer le transfert."
            });
        }
    }
);


/* =========================================================
   PAIEMENT SIMULÉ
========================================================= */

app.post(
    "/api/payment",
    authenticate,
    (req,res) => {

        try{

            const merchant =
                cleanText(
                    req.body.merchant,
                    100
                );

            const currency =
                normalizeCurrency(
                    req.body.currency
                );

            const referenceInput =
                cleanText(
                    req.body.reference,
                    100
                );

            if(
                !merchant ||
                !currency
            ){

                return res.status(400).json({
                    error:
                        "Informations de paiement invalides."
                });
            }

            let amount;

            if(currency === "USD"){

                amount =
                    usdToCents(
                        req.body.amount
                    );

            }else{

                amount =
                    cdfAmount(
                        req.body.amount
                    );
            }

            if(amount === null){

                return res.status(400).json({
                    error:
                        "Montant invalide."
                });
            }

            const wallet =
                getWallet(
                    req.user.id
                );

            if(!wallet){

                return res.status(404).json({
                    error:
                        "Portefeuille introuvable."
                });
            }

            if(currency === "CDF"){

                if(
                    wallet.cdf <
                    amount
                ){

                    return res.status(400).json({
                        error:
                            "Solde CDF insuffisant."
                    });
                }

            }else{

                if(
                    wallet.usd_cents <
                    amount
                ){

                    return res.status(400).json({
                        error:
                            "Solde USD insuffisant."
                    });
                }
            }

            const reference =
                referenceInput ||
                (
                    "PAY-" +
                    crypto
                        .randomBytes(5)
                        .toString("hex")
                        .toUpperCase()
                );

            db.transaction(() => {

                if(currency === "CDF"){

                    db.prepare(`
                        UPDATE wallets
                        SET
                            cdf = cdf - ?,
                            updated_at =
                                CURRENT_TIMESTAMP
                        WHERE user_id = ?
                    `).run(
                        amount,
                        req.user.id
                    );

                }else{

                    db.prepare(`
                        UPDATE wallets
                        SET
                            usd_cents =
                                usd_cents - ?,
                            updated_at =
                                CURRENT_TIMESTAMP
                        WHERE user_id = ?
                    `).run(
                        amount,
                        req.user.id
                    );
                }

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
                    VALUES (
                        ?,
                        'debit',
                        ?,
                        ?,
                        ?,
                        ?,
                        ?
                    )
                `).run(
                    req.user.id,
                    currency,
                    currency === "CDF"
                        ? amount
                        : 0,
                    currency === "USD"
                        ? amount
                        : 0,
                    "Paiement — " + merchant,
                    reference
                );

            })();

            res.json({

                message:
                    "Paiement simulé effectué.",

                reference,

                merchant,

                currency,

                amount:
                    currency === "USD"
                        ? amount / 100
                        : amount
            });

        }catch(error){

            console.error(
                "PAYMENT ERROR:",
                error
            );

            res.status(500).json({
                error:
                    "Impossible d'effectuer le paiement."
            });
        }
    }
);


/* =========================================================
   ADMIN — UTILISATEURS
========================================================= */

app.get(
    "/api/admin/users",
    authenticate,
    requireAdmin,
    (req,res) => {

        try{

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

                    ORDER BY
                        u.id DESC
                `).all();

            const result =
                users.map(
                    user => ({

                        id:
                            user.id,

                        account_id:
                            user.account_id,

                        name:
                            user.name,

                        email:
                            user.email,

                        role:
                            user.role,

                        status:
                            user.status,

                        created_at:
                            user.created_at,

                        cdf:
                            Number(
                                user.cdf || 0
                            ),

                        usd:
                            Number(
                                user.usd_cents || 0
                            ) / 100
                    })
                );

            res.json({
                users:result
            });

        }catch(error){

            console.error(
                "ADMIN USERS ERROR:",
                error
            );

            res.status(500).json({
                error:
                    "Impossible de charger les utilisateurs."
            });
        }
    }
);


/* =========================================================
   ADMIN — CRÉDITER
========================================================= */

app.post(
    "/api/admin/credit",
    authenticate,
    requireAdmin,
    (req,res) => {

        try{

            /*
             Accepte :

             userId
             ou
             user_id

             pour compatibilité avec les anciennes versions.
            */

            const targetId =
                Number(
                    req.body.userId ??
                    req.body.user_id
                );

            if(
                !Number.isInteger(
                    targetId
                )
            ){

                return res.status(400).json({
                    error:
                        "Utilisateur invalide."
                });
            }

            const target =
                db.prepare(`
                    SELECT
                        id,
                        account_id,
                        name,
                        status
                    FROM users
                    WHERE id = ?
                `).get(targetId);

            if(!target){

                return res.status(404).json({
                    error:
                        "Utilisateur introuvable."
                });
            }

            const currency =
                normalizeCurrency(
                    req.body.currency
                );

            if(!currency){

                return res.status(400).json({
                    error:
                        "Devise invalide."
                });
            }

            let amount;

            if(currency === "USD"){

                amount =
                    usdToCents(
                        req.body.amount
                    );

            }else{

                amount =
                    cdfAmount(
                        req.body.amount
                    );
            }

            if(amount === null){

                return res.status(400).json({
                    error:
                        "Montant invalide."
                });
            }

            const description =
                cleanText(
                    req.body.description,
                    120
                ) ||
                "Crédit administratif";

            const reference =
                "ADM-" +
                crypto
                    .randomBytes(5)
                    .toString("hex")
                    .toUpperCase();

            db.transaction(() => {

                if(currency === "CDF"){

                    db.prepare(`
                        UPDATE wallets
                        SET
                            cdf = cdf + ?,
                            updated_at =
                                CURRENT_TIMESTAMP
                        WHERE user_id = ?
                    `).run(
                        amount,
                        targetId
                    );

                }else{

                    db.prepare(`
                        UPDATE wallets
                        SET
                            usd_cents =
                                usd_cents + ?,
                            updated_at =
                                CURRENT_TIMESTAMP
                        WHERE user_id = ?
                    `).run(
                        amount,
                        targetId
                    );
                }

                db.prepare(`
                    INSERT INTO transactions (
                        user_id,
                        type,
                        currency,
                        amount_cdf,
                        amount_usd_cents,
                        description,
                        reference,
                        related_user_id
                    )
                    VALUES (
                        ?,
                        'credit',
                        ?,
                        ?,
                        ?,
                        ?,
                        ?,
                        ?
                    )
                `).run(
                    targetId,
                    currency,
                    currency === "CDF"
                        ? amount
                        : 0,
                    currency === "USD"
                        ? amount
                        : 0,
                    description,
                    reference,
                    req.user.id
                );

            })();

            res.json({

                message:
                    "Compte crédité.",

                reference,

                user:{
                    id:
                        target.id,

                    account_id:
                        target.account_id,

                    name:
                        target.name
                },

                currency,

                amount:
                    currency === "USD"
                        ? amount / 100
                        : amount
            });

        }catch(error){

            console.error(
                "ADMIN CREDIT ERROR:",
                error
            );

            res.status(500).json({
                error:
                    "Impossible de créditer le compte."
            });
        }
    }
);


/* =========================================================
   ADMIN — BLOQUER / DÉBLOQUER
========================================================= */

app.post(
    "/api/admin/block",
    authenticate,
    requireAdmin,
    (req,res) => {

        try{

            const targetId =
                Number(
                    req.body.userId ??
                    req.body.user_id
                );

            const blocked =
                Boolean(
                    req.body.blocked
                );

            if(
                !Number.isInteger(
                    targetId
                )
            ){

                return res.status(400).json({
                    error:
                        "Utilisateur invalide."
                });
            }

            if(
                targetId ===
                Number(req.user.id)
            ){

                return res.status(400).json({
                    error:
                        "Vous ne pouvez pas bloquer votre propre compte administrateur."
                });
            }

            const target =
                db.prepare(`
                    SELECT
                        id,
                        role,
                        status
                    FROM users
                    WHERE id = ?
                `).get(targetId);

            if(!target){

                return res.status(404).json({
                    error:
                        "Utilisateur introuvable."
                });
            }

            if(
                target.role === "admin"
            ){

                return res.status(403).json({
                    error:
                        "Un administrateur ne peut pas être bloqué depuis cette interface."
                });
            }

            const newStatus =
                blocked
                    ? "blocked"
                    : "active";

            db.prepare(`
                UPDATE users
                SET
                    status = ?,
                    updated_at =
                        CURRENT_TIMESTAMP
                WHERE id = ?
            `).run(
                newStatus,
                targetId
            );

            res.json({

                message:
                    blocked
                        ? "Utilisateur bloqué."
                        : "Utilisateur débloqué.",

                status:
                    newStatus
            });

        }catch(error){

            console.error(
                "ADMIN BLOCK ERROR:",
                error
            );

            res.status(500).json({
                error:
                    "Impossible de modifier le statut."
            });
        }
    }
);


/* =========================================================
   ADMIN — STATISTIQUES
========================================================= */

app.get(
    "/api/admin/stats",
    authenticate,
    requireAdmin,
    (req,res) => {

        try{

            const totalUsers =
                db.prepare(`
                    SELECT COUNT(*) AS total
                    FROM users
                `).get().total;

            const activeUsers =
                db.prepare(`
                    SELECT COUNT(*) AS total
                    FROM users
                    WHERE status = 'active'
                `).get().total;

            const blockedUsers =
                db.prepare(`
                    SELECT COUNT(*) AS total
                    FROM users
                    WHERE status = 'blocked'
                `).get().total;

            const balances =
                db.prepare(`
                    SELECT

                        COALESCE(
                            SUM(cdf),
                            0
                        ) AS total_cdf,

                        COALESCE(
                            SUM(usd_cents),
                            0
                        ) AS total_usd_cents

                    FROM wallets
                `).get();

            res.json({

                users:{
                    total:
                        totalUsers,

                    active:
                        activeUsers,

                    blocked:
                        blockedUsers
                },

                balances:{
                    CDF:
                        Number(
                            balances.total_cdf
                        ),

                    USD:
                        Number(
                            balances.total_usd_cents
                        ) / 100
                }
            });

        }catch(error){

            console.error(
                "ADMIN STATS ERROR:",
                error
            );

            res.status(500).json({
                error:
                    "Impossible de charger les statistiques."
            });
        }
    }
);


/* =========================================================
   404 API
========================================================= */

app.use(
    "/api",
    (req,res) => {

        res.status(404).json({
            error:
                "Route API introuvable."
        });
    }
);


/* =========================================================
   ERREUR EXPRESS
========================================================= */

app.use(
    (error,req,res,next) => {

        console.error(
            "SERVER ERROR:",
            error
        );

        if(
            error instanceof SyntaxError &&
            error.status === 400 &&
            "body" in error
        ){

            return res.status(400).json({
                error:
                    "JSON invalide."
            });
        }

        res.status(500).json({
            error:
                "Erreur interne du serveur."
        });
    }
);


/* =========================================================
   DÉMARRAGE
========================================================= */

app.listen(
    PORT,
    "0.0.0.0",
    () => {

        console.log("");
        console.log(
            "=========================================="
        );
        console.log(
            "       DALZON WALLET v2.2"
        );
        console.log(
            "=========================================="
        );
        console.log(
            "Mode       : Simulation éducative"
        );
        console.log(
            "Port       : " + PORT
        );
        console.log(
            "Database   : " + DB_PATH
        );
        console.log(
            "API        : opérationnelle"
        );
        console.log(
            "=========================================="
        );
        console.log("");
    }
);