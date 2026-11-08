using Microsoft.Data.Sqlite;

public sealed class AccountRepository(SqliteDatabase database)
{
    public async Task<Account?> FindByUsernameAsync(string username, CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = await database.OpenConnectionAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = """
            SELECT id, username, password_hash, role
            FROM accounts
            WHERE username_normalized = $normalizedUsername
            """;
        command.Parameters.AddWithValue("$normalizedUsername", NormalizeUsername(username));

        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadAccount(reader) : null;
    }

    public async Task<bool> CreateAsync(Account account, string email, CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = await database.OpenConnectionAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO accounts (id, username, username_normalized, email, password_hash, role)
            VALUES ($id, $username, $normalizedUsername, $email, $passwordHash, $role)
            ON CONFLICT(username_normalized) DO NOTHING
            """;
        command.Parameters.AddWithValue("$id", account.Id.ToString("D"));
        command.Parameters.AddWithValue("$username", account.Username);
        command.Parameters.AddWithValue("$normalizedUsername", NormalizeUsername(account.Username));
        command.Parameters.AddWithValue("$email", email);
        command.Parameters.AddWithValue("$passwordHash", account.PasswordHash);
        command.Parameters.AddWithValue("$role", account.Role);
        return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
    }

    public async Task<IReadOnlyList<AccountSummary>> ListAsync(CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = await database.OpenConnectionAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "SELECT id, username, role FROM accounts ORDER BY username_normalized";
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);

        var accounts = new List<AccountSummary>();
        while (await reader.ReadAsync(cancellationToken))
        {
            accounts.Add(new AccountSummary(
                Guid.Parse(reader.GetString(0)), reader.GetString(1), reader.GetString(2)));
        }
        return accounts;
    }

    private static Account ReadAccount(SqliteDataReader reader) => new(
        Guid.Parse(reader.GetString(0)),
        reader.GetString(1),
        reader.GetString(2),
        reader.GetString(3));

    private static string NormalizeUsername(string username) => username.ToUpperInvariant();
}
