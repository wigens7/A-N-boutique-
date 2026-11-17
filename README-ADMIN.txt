# A&N BOUTIQUE admin starter

Files:
- `package.json`: Node.js dependencies and start script.
- `server.js`: Express server, protected `/admin` route, admin login/session/logout endpoints.
- `private/admin.html`: admin dashboard interface.

## Railway
1. Add these variables to the A&N BOUTIQUE service:
   - `ADMIN_EMAIL`
   - `ADMIN_PASSWORD`
   - `NODE_ENV=production`
2. Optional but recommended: add a long random `SESSION_SECRET`.
3. Deploy this project with Node.js. Railway runs `npm start`.
4. The current frontend sign-in form still needs to be connected to `POST /api/admin/login`. On success, redirect to `/admin`.
5. Keep `private/admin.html` outside the public static root. Do not move it to the root.

## Important
The dashboard layout is created, but database operations are not connected yet. The protected API section routes intentionally return a not-ready response until the Supabase schema, policies, and storage are implemented. No demo sales or fake customer records are shown.
