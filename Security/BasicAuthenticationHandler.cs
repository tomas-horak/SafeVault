using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

public sealed class BasicAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public const string SchemeName = "Basic";
    private readonly AccountRepository _accounts;
    private readonly PasswordHasher<Account> _passwordHasher;

    public BasicAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        AccountRepository accounts,
        PasswordHasher<Account> passwordHasher)
        : base(options, logger, encoder)
    {
        _accounts = accounts;
        _passwordHasher = passwordHasher;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.IsHttps && !IPAddress.IsLoopback(Context.Connection.RemoteIpAddress ?? IPAddress.None))
        {
            return AuthenticateResult.Fail("Basic authentication requires HTTPS.");
        }

        string? header = Request.Headers.Authorization.FirstOrDefault();
        if (header is null || !header.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            return AuthenticateResult.NoResult();
        }

        string credentials;
        try
        {
            credentials = Encoding.UTF8.GetString(Convert.FromBase64String(header[6..].Trim()));
        }
        catch (FormatException)
        {
            return AuthenticateResult.Fail("Invalid credentials.");
        }

        int colon = credentials.IndexOf(':');
        if (colon <= 0)
        {
            return AuthenticateResult.Fail("Invalid credentials.");
        }

        string username = credentials[..colon].Trim();
        string password = credentials[(colon + 1)..];
        Account? account = await _accounts.FindByUsernameAsync(username, Context.RequestAborted);
        if (account is null
            || _passwordHasher.VerifyHashedPassword(account, account.PasswordHash, password)
                == PasswordVerificationResult.Failed)
        {
            return AuthenticateResult.Fail("Invalid credentials.");
        }

        Claim[] claims =
        [
            new(ClaimTypes.NameIdentifier, account.Id.ToString("D")),
            new(ClaimTypes.Name, account.Username),
            new(ClaimTypes.Role, account.Role)
        ];
        var identity = new ClaimsIdentity(claims, SchemeName);
        var principal = new ClaimsPrincipal(identity);
        return AuthenticateResult.Success(new AuthenticationTicket(principal, SchemeName));
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.Headers.WWWAuthenticate = "Basic realm=\"SafeVault\", charset=\"UTF-8\"";
        return base.HandleChallengeAsync(properties);
    }
}
