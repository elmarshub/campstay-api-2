# CampStay API — Auth Module (starter)

## What's in here

A working NestJS auth system: register, login, refresh (with rotation),
logout, and one protected route (`/auth/me`) to prove guards work.

## Getting it running on your machine

1. `npm install`
2. Copy `.env.example` to `.env` and fill in real secrets:
   ```
   cp .env.example .env
   ```
   Generate strong secrets with: `node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"`
3. Start Postgres locally (easiest: Docker)
   ```
   docker run --name campstay-db -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=campstay -p 5432:5432 -d postgres:16
   ```
4. Create the tables from the schema:
   ```
   npx prisma migrate dev --name init
   ```
5. Run it:
   ```
   npm run start:dev
   ```

## Try it with curl

```bash
# Register
curl -X POST http://localhost:4000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"martin@example.com","password":"Password123","firstName":"Martin","lastName":"E"}'

# Login (saves the refresh-token cookie to cookies.txt)
curl -X POST http://localhost:4000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{"email":"martin@example.com","password":"Password123"}'

# Call the protected route with the access token you got back from login
curl http://localhost:4000/api/v1/auth/me \
  -H "Authorization: Bearer <paste accessToken here>"

# Get a new access token using the refresh cookie
curl -X POST http://localhost:4000/api/v1/auth/refresh -b cookies.txt -c cookies.txt
```

## What to read, in order, to understand it

1. `prisma/schema.prisma` — the two tables: User, Session
2. `src/auth/auth.service.ts` — the actual logic (read the comments closely)
3. `src/auth/auth.controller.ts` — how the cookie gets set
4. `src/auth/strategies/jwt.strategy.ts` + `src/common/guards/jwt-auth.guard.ts` — how protected routes work

## Next module to build once this makes sense

`users` (profile data) and `camps` (listings) — ask and we'll do the same
file-by-file walkthrough for those.
