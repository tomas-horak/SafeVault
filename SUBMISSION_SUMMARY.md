# SafeVault security summary

## Vulnerabilities considered and fixes

- **SQL injection:** Search text is bound as a SQLite parameter instead of being inserted into SQL text. Search also always filters by the authenticated account ID.
- **Cross-site scripting (XSS):** Stored text is encoded with `WebUtility.HtmlEncode` when rendered into HTML text nodes. Input is preserved as data rather than deleting characters that could also be legitimate content.
- **Weak password storage:** The app uses ASP.NET Core `PasswordHasher<T>`. The database stores the versioned, salted hash string, not the original password. Passwords must be at least 12 characters.
- **Unauthorized access and role escalation:** Vault routes require authentication and scope queries to the current account. Admin routes require the `Admin` role. Admin-created accounts always receive `User`; only the configured bootstrap account receives `Admin`.
- **Overly permissive input:** Account names use an allow-list and request fields have size limits. SQL safety still comes from parameters, and HTML safety comes from output encoding.

## Security tests

`SafeVault.Tests` checks account validation, password hash verification, encoded XSS payloads, SQL injection search input, vault ownership boundaries, and the AdminOnly role policy.

## AI assistance

This starter project was created with OpenAI Codex. It was not generated with Microsoft Copilot. Review the implementation and follow the course's rules for AI-assisted submissions; only describe Copilot's contribution if you actually use Copilot and record what it helped you change.
