using Microsoft.Data.Sqlite;
using System.Globalization;
using Microsoft.AspNetCore.DataProtection;

public sealed class VaultRepository(
    SqliteDatabase database,
    IDataProtectionProvider dataProtectionProvider)
{
    private readonly IDataProtector contentProtector =
        dataProtectionProvider.CreateProtector("SafeVault.VaultEntry.Content.v1");

    public async Task<VaultEntry> CreateAsync(
        Guid ownerId,
        string title,
        string content,
        CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = await database.OpenConnectionAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO vault_entries (owner_id, title, content, created_utc)
            VALUES ($ownerId, $title, $content, $createdUtc)
            RETURNING id, owner_id, title, content, created_utc
            """;
        command.Parameters.AddWithValue("$ownerId", ownerId.ToString("D"));
        command.Parameters.AddWithValue("$title", title);
        // Protect the sensitive note before it reaches the database. Protect/Unprotect
        // use the app's managed key ring and bind ciphertext to this purpose string.
        command.Parameters.AddWithValue("$content", contentProtector.Protect(content));
        command.Parameters.AddWithValue("$createdUtc", DateTimeOffset.UtcNow.ToString("O"));

        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        await reader.ReadAsync(cancellationToken);
        return ReadEntry(reader);
    }

    public async Task<IReadOnlyList<VaultEntry>> SearchOwnedAsync(
        Guid ownerId,
        string? query,
        CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = await database.OpenConnectionAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        // User text is a bound value. It is never concatenated into SQL syntax.
        command.CommandText = """
            SELECT id, owner_id, title, content, created_utc
            FROM vault_entries
            WHERE owner_id = $ownerId
              AND ($query IS NULL OR instr(title, $query) > 0 OR instr(content, $query) > 0)
            ORDER BY id
            """;
        command.Parameters.AddWithValue("$ownerId", ownerId.ToString("D"));
        command.Parameters.AddWithValue("$query", (object?)query ?? DBNull.Value);

        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        var results = new List<VaultEntry>();
        while (await reader.ReadAsync(cancellationToken))
        {
            results.Add(ReadEntry(reader));
        }
        return results;
    }

    public async Task<VaultEntry?> FindOwnedAsync(
        long id,
        Guid ownerId,
        CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = await database.OpenConnectionAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = """
            SELECT id, owner_id, title, content, created_utc
            FROM vault_entries
            WHERE id = $id AND owner_id = $ownerId
            """;
        command.Parameters.AddWithValue("$id", id);
        command.Parameters.AddWithValue("$ownerId", ownerId.ToString("D"));

        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadEntry(reader) : null;
    }

    private VaultEntry ReadEntry(SqliteDataReader reader) => new(
        reader.GetInt64(0),
        Guid.Parse(reader.GetString(1)),
        reader.GetString(2),
        contentProtector.Unprotect(reader.GetString(3)),
        DateTimeOffset.Parse(reader.GetString(4), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind));
}
