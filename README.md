# SafeVault

An ASP.NET Core sample for the security activities: validation, parameterized database access, Basic authentication with hashed passwords, role-based access, and safe HTML output.

## Run

From this folder, set bootstrap admin credentials using user secrets, then run the app:

```bash
dotnet user-secrets init
dotnet user-secrets set "BootstrapAdmin:Username" "vault-admin"
dotnet user-secrets set "BootstrapAdmin:Password" "replace-with-a-long-password"
dotnet run
```

Trust the local HTTPS development certificate if needed with `dotnet dev-certs https --trust`. The local database is `safevault.db`. Override it with `ConnectionStrings:SafeVault` (environment variable `ConnectionStrings__SafeVault`). Set both bootstrap settings to create the first Admin account; startup will not overwrite an existing account's password.

Run the tests from the project root with:

```bash
dotnet test SafeVault.Tests/SafeVault.Tests.csproj
```

## Routes

| Method | Route | Access | Purpose |
| --- | --- | --- | --- |
| GET | `/health/live` | Public | Liveness check |
| GET | `/health/ready` | Public | Database readiness check |
| POST | `/api/admin/accounts` | Admin | Create a regular User account |
| GET | `/api/admin/accounts` | Admin | List safe account summaries |
| GET | `/api/vault?query=...` | Authenticated | Search only the caller's entries |
| GET | `/api/vault/{id}` | Authenticated | Retrieve one of the caller's entries |
| GET | `/api/vault/{id}/html` | Authenticated | Render the caller's entry with HTML encoding |
| POST | `/api/vault` | Authenticated | Save an entry owned by the caller |

Use HTTP Basic credentials (`username:password`, Base64 encoded in the Authorization header). Basic auth is accepted over HTTP only on loopback for local development; use HTTPS elsewhere.

## Security notes

- Usernames are validated against a small allow-list; other user text is preserved and encoded when rendered as HTML.
- Passwords use ASP.NET Core `PasswordHasher<T>`; only the encoded salted hash is stored.
- Vault content is protected with ASP.NET Core Data Protection before it is written to SQLite. Persist and protect the Data Protection key ring in deployed environments; losing the keys makes existing vault content unreadable.
- SQL values are bound as parameters. The search query also includes the authenticated account ID, preventing one user from reading another user's rows.
- Admin-only routes use an authorization policy that requires the `Admin` role. Public account creation cannot assign roles.
- Tests cover validation, password verification, XSS output encoding, SQL injection attempts, row ownership, and role checks.

The app uses direct parameterized SQLite commands to keep the sample self-contained. EF Core would be a reasonable alternative for a larger domain model and migrations. This code was created with AI assistance; review it, understand it, and follow your course's rules about disclosing or submitting AI-assisted work.
