# ZT Visitor: Zero-Trust Visitor Management (BCA-32)

## Structure
```
zt-visitor/
  frontend/        index.html, app.js          (static site)
  backend/         app.js (Express API), server.js (local only)
  api/index.js     Vercel serverless entry
  vercel.json      routing + security headers
  package.json
  .env.example
```
The frontend calls the API with relative paths (/api/...), so no IP or URL is hard-coded. The same code runs on localhost and on Vercel.

## Run locally
1. `npm install`
2. Copy `.env.example` to `.env` and fill it in (local MongoDB or Atlas).
3. `npm start`, then open http://localhost:3000

## Deploy on Vercel
1. MongoDB Atlas: Database > Connect > Drivers, copy the connection string, add `/zt_visitor` before the `?`.
   Network Access > Add IP Address > Allow access from anywhere (0.0.0.0/0), because Vercel IPs change.
2. Push this folder to a GitHub repo (`.env` is ignored and must not be pushed).
3. vercel.com > Add New > Project > import the repo. Framework Preset: Other. Leave Build and Output settings empty (vercel.json sets them).
4. Settings > Environment Variables, add: `MONGO_URI`, `JWT_SECRET` (32+ random characters), `SEED_PASSWORD` (10+ characters, strong).
5. Deploy. Open `https://YOUR-APP.vercel.app/api/health`; it should show `{"ok":true}`.
6. Log in as `admin`, `host` or `security` with SEED_PASSWORD. The users are created on the first request.

## Known limits (mention in the report)
- Login rate limiting is per serverless instance, so it is weaker than on a single server. A production system would use a shared store such as Redis.
- Two simultaneous requests on different instances can fork the audit hash chain. Fine for a prototype; production would use a transaction or a single writer.
