# VaultNest Local MVP

VaultNest is a local-first password/secrets vault with browser-side AES-GCM encryption, user accounts, email verification, and a separate admin console.

## Stack
- React + TypeScript + Vite
- FastAPI + SQLAlchemy
- PostgreSQL 17
- Mailpit for local email testing
- Docker Compose
- Argon2id for account password hashing
- Browser Web Crypto API for vault encryption

## Start locally

```bash
cp .env.example .env
docker compose up -d --build
docker compose ps
```

Open:
- User app: http://localhost:5173
- Admin console: http://localhost:5173/admin
- Local email inbox: http://localhost:8025
- API health: http://localhost:8000/health

## Default local admin

Configured by `.env`:
- Email: `admin@vaultnest.local`
- Password: `AdminLocalPassword123!`

Change this before any non-local deployment.

## Email verification flow

1. User registers.
2. API creates a one-time verification token and sends email through Mailpit.
3. Open http://localhost:8025 and open the VaultNest verification email.
4. Click the verification link.
5. User can then sign in.

For real email delivery, replace the SMTP settings with a transactional email provider and use HTTPS.

## Admin console

Go to `/admin` and sign in with the configured admin credentials.

The admin can:
- list regular users
- see verification status
- see active/disabled status
- disable/enable users
- permanently delete users
- see account creation time

Administrators cannot decrypt or view users' vault secrets. Deleting a user permanently deletes their encrypted vault records through the database cascade.

## Important local database note

The app contains a lightweight migration for the new user fields. If you are starting over and do not need current local data, you can reset everything with:

```bash
docker compose down -v
docker compose up -d --build
```

Do not use `down -v` when you need to keep your vault data.

## Security note

This is an MVP, not a production-ready password manager. Before production use, add a formal threat model, independent cryptographic/security review, MFA, rate limiting, secure session/cookie design, CSRF protection where applicable, audit logging, recovery design, dependency scanning, backups, key-management review, penetration testing, and secure email infrastructure.
