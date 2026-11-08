using Microsoft.AspNetCore.Authorization;

public sealed record Account(Guid Id, string Username, string PasswordHash, string Role);
public sealed record AccountSummary(Guid Id, string Username, string Role);
public sealed record VaultEntry(long Id, Guid OwnerId, string Title, string Content, DateTimeOffset CreatedUtc);

public sealed class CreateAccountRequest
{
    public string? Username { get; init; }
    public string? Email { get; init; }
    public string? Password { get; init; }
}

public sealed class CreateVaultEntryRequest
{
    public string? Title { get; init; }
    public string? Content { get; init; }
}

public static class AccountRoles
{
    public const string Admin = "Admin";
    public const string User = "User";
}

public static class AuthorizationPolicies
{
    public const string AdminOnly = "AdminOnly";

    public static void Configure(AuthorizationOptions options) =>
        options.AddPolicy(AdminOnly, policy => policy.RequireRole(AccountRoles.Admin));
}
