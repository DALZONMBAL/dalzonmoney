# DALZON Money

DALZON Money est une simulation éducative de portefeuille CDF/USD.

## Architecture

- Frontend : `index.html`, PWA et GitHub Pages.
- Backend : Node.js + Express.
- Base de données : PostgreSQL.
- Authentification : bcrypt + JWT.
- Déploiement backend : Render via `render.yaml`.

## Ce qui a été corrigé

Le frontend détecte maintenant GitHub Pages et utilise automatiquement l'API de production :

`https://dalzonmoney.onrender.com`

Le service worker a aussi reçu une nouvelle version de cache afin que les anciennes pages ne restent pas bloquées.

## Déploiement du backend

Le dépôt contient un Blueprint Render. Il définit :

1. un service Node.js ;
2. une base PostgreSQL ;
3. `DATABASE_URL` reliée automatiquement à la base ;
4. `JWT_SECRET` généré automatiquement ;
5. `FRONTEND_ORIGIN` pour autoriser le frontend GitHub Pages ;
6. `/api/health` comme contrôle de santé.

Dans Render, crée/synchronise le Blueprint à partir de ce dépôt. Après le déploiement, vérifie :

`https://dalzonmoney.onrender.com/api/health`

La réponse attendue contient `"ok": true` et `"database": "connected"`.

## Premier administrateur

Lorsque la base est vide, l'application affiche automatiquement l'écran de création du premier administrateur.

Aucun mot de passe administrateur n'est stocké dans le dépôt.

## Routes principales

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

## Sécurité

Les mots de passe sont hachés avec bcrypt. Les sessions utilisent des JWT. Les secrets et la connexion PostgreSQL doivent rester dans les variables d'environnement du serveur.

## Important

DALZON Money reste une simulation éducative : les opérations affichées ne correspondent pas à de l'argent réel.
