using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;

var builder = WebApplication.CreateBuilder(args);

string connectionString = builder.Configuration.GetConnectionString("SafeVault")
    ?? "Data Source=safevault.db";

builder.Services.AddSingleton(new SqliteDatabase(connectionString));
builder.Services.AddSingleton<PasswordHasher<Account>>();
builder.Services.AddDataProtection().SetApplicationName("SafeVault");
builder.Services.AddScoped<AccountRepository>();
builder.Services.AddScoped<VaultRepository>();
builder.Services.AddAuthentication(BasicAuthenticationHandler.SchemeName)
    .AddScheme<AuthenticationSchemeOptions, BasicAuthenticationHandler>(
        BasicAuthenticationHandler.SchemeName, _ => { });
builder.Services.AddAuthorization(options =>
    AuthorizationPolicies.Configure(options));
builder.Services.AddProblemDetails();

var app = builder.Build();
app.UseExceptionHandler();
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

var database = app.Services.GetRequiredService<SqliteDatabase>();
await database.InitializeAsync(app.Lifetime.ApplicationStopping);
await BootstrapAdmin.CreateIfConfiguredAsync(
    database,
    app.Services.GetRequiredService<PasswordHasher<Account>>(),
    builder.Configuration["BootstrapAdmin:Username"],
    builder.Configuration["BootstrapAdmin:Password"],
    app.Lifetime.ApplicationStopping);

app.MapGet("/health/live", () => Results.Ok(new { status = "ok" }));
app.MapGet("/health/ready", async (SqliteDatabase db, CancellationToken cancellationToken) =>
{
    try
    {
        await using SqliteConnection connection = await db.OpenConnectionAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "SELECT 1";
        await command.ExecuteScalarAsync(cancellationToken);
        return Results.Ok(new { status = "ready" });
    }
    catch (SqliteException)
    {
        return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
    }
});

var admin = app.MapGroup("/api/admin").RequireAuthorization(AuthorizationPolicies.AdminOnly);

admin.MapPost("/accounts", async (
    CreateAccountRequest request,
    AccountRepository accounts,
    PasswordHasher<Account> passwordHasher,
    CancellationToken cancellationToken) =>
{
    Dictionary<string, string[]> errors = InputValidation.ValidateNewAccount(request);
    if (errors.Count != 0)
    {
        return Results.ValidationProblem(errors);
    }

    string username = request.Username!.Trim();
    var account = new Account(Guid.NewGuid(), username, "", AccountRoles.User);
    string passwordHash = passwordHasher.HashPassword(account, request.Password!);
    account = account with { PasswordHash = passwordHash };

    bool created = await accounts.CreateAsync(account, request.Email!.Trim(), cancellationToken);
    return created
        ? Results.Created("/api/admin/accounts", new AccountSummary(account.Id, username, account.Role))
        : Results.Conflict(new { error = "That username is already in use." });
});

admin.MapGet("/accounts", async (AccountRepository accounts, CancellationToken cancellationToken) =>
    Results.Ok(await accounts.ListAsync(cancellationToken)));

var vault = app.MapGroup("/api/vault").RequireAuthorization();

vault.MapGet("", async (
    ClaimsPrincipal principal,
    string? query,
    VaultRepository entries,
    CancellationToken cancellationToken) =>
{
    Guid ownerId = CurrentAccountId(principal);
    return Results.Ok(await entries.SearchOwnedAsync(ownerId, query, cancellationToken));
});

vault.MapGet("/{id:long}", async (
    long id,
    ClaimsPrincipal principal,
    VaultRepository entries,
    CancellationToken cancellationToken) =>
{
    VaultEntry? entry = await entries.FindOwnedAsync(
        id, CurrentAccountId(principal), cancellationToken);
    return entry is null ? Results.NotFound() : Results.Ok(entry);
});

vault.MapGet("/{id:long}/html", async (
    long id,
    ClaimsPrincipal principal,
    VaultRepository entries,
    CancellationToken cancellationToken) =>
{
    VaultEntry? entry = await entries.FindOwnedAsync(
        id, CurrentAccountId(principal), cancellationToken);
    return entry is null
        ? Results.NotFound()
        : Results.Content(SafeHtmlRenderer.RenderEntry(entry), "text/html; charset=utf-8");
});

vault.MapPost("", async (
    CreateVaultEntryRequest request,
    ClaimsPrincipal principal,
    VaultRepository entries,
    CancellationToken cancellationToken) =>
{
    Dictionary<string, string[]> errors = InputValidation.ValidateVaultEntry(request);
    if (errors.Count != 0)
    {
        return Results.ValidationProblem(errors);
    }

    VaultEntry created = await entries.CreateAsync(
        CurrentAccountId(principal), request.Title!.Trim(), request.Content!, cancellationToken);
    return Results.Created($"/api/vault/{created.Id}", created);
});

app.Run();

static Guid CurrentAccountId(ClaimsPrincipal principal)
{
    string? value = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    return Guid.TryParse(value, out Guid id)
        ? id
        : throw new InvalidOperationException("Authenticated principal has no valid account ID claim.");
}

public partial class Program { }
