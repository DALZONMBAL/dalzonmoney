# DALZON Money

DALZON Money est une simulation éducative de portefeuille CDF/USD.

## Architecture

- Frontend : `index.html`, PWA et GitHub Pages.
- API : Node.js + Express, déployable comme fonction serverless.
- Base de données : PostgreSQL.
- Authentification : bcrypt + JWT.
- Déploiement de l'API : Vercel.

## Nouvelle API

L'ancienne configuration Render a été retirée.

Le frontend GitHub Pages utilise maintenant :

`https://dalzonmoney-api.vercel.app`

L'API expose notamment :

- `GET /api/health`
- `GET /api/setup/status`
- `POST /api/setup/admin`
- `POST /api/auth/register`
- `POST /api/auth/login`
- `GET /api/account`
- `GET /api/transactions`
- `POST /api/transfer`
- `POST /api/payment`
- `GET /api/admin/dashboard`
- `GET /api/admin/users`
- `POST /api/admin/credit`
- `POST /api/admin/block`
- `POST /api/admin/unblock`

## Variables du serveur

Le serveur doit recevoir :

- `DATABASE_URL`
- `JWT_SECRET`
- `FRONTEND_ORIGIN`
- `NODE_ENV=production`

Les secrets ne doivent jamais être placés dans GitHub.

## Premier administrateur

Lorsque la base est vide, utilise l'écran de création du premier administrateur.

Aucun mot de passe administrateur n'est stocké dans le dépôt.

## Important

DALZON Money reste une simulation éducative : les opérations affichées ne correspondent pas à de l'argent réel.
