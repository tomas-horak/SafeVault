using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;

public static class BootstrapAdmin
{
    public static async Task CreateIfConfiguredAsync(
        SqliteDatabase database,
        PasswordHasher<Account> passwordHasher,
        string? username,
        string? password,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(username) && string.IsNullOrWhiteSpace(password))
        {
            return;
        }
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
        {
            throw new InvalidOperationException("Set both BootstrapAdmin:Username and BootstrapAdmin:Password.");
        }

        var request = new CreateAccountRequest
        {
            Username = username,
            Email = "vault-admin@example.invalid",
            Password = password
        };
        if (InputValidation.ValidateNewAccount(request).Count != 0)
        {
            throw new InvalidOperationException("Bootstrap admin credentials do not meet the account requirements.");
        }

        string cleanUsername = username.Trim();
        var account = new Account(Guid.NewGuid(), cleanUsername, "", AccountRoles.Admin);
        account = account with { PasswordHash = passwordHasher.HashPassword(account, password) };

        await using SqliteConnection connection = await database.OpenConnectionAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO accounts (id, username, username_normalized, email, password_hash, role)
            VALUES ($id, $username, $normalizedUsername, $email, $passwordHash, $role)
            ON CONFLICT(username_normalized) DO NOTHING
            """;
        command.Parameters.AddWithValue("$id", account.Id.ToString("D"));
        command.Parameters.AddWithValue("$username", account.Username);
        command.Parameters.AddWithValue("$normalizedUsername", account.Username.ToUpperInvariant());
        command.Parameters.AddWithValue("$email", request.Email!);
        command.Parameters.AddWithValue("$passwordHash", account.PasswordHash);
        command.Parameters.AddWithValue("$role", account.Role);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
