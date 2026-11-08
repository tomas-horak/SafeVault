using System.Net.Mail;

public static class InputValidation
{
    public static Dictionary<string, string[]> ValidateNewAccount(CreateAccountRequest request)
    {
        var errors = new Dictionary<string, string[]>();
        string username = request.Username?.Trim() ?? "";
        string email = request.Email?.Trim() ?? "";

        if (username.Length is < 3 or > 32
            || username.Any(character => !char.IsAsciiLetterOrDigit(character)
                && character is not '.' and not '_' and not '-'))
        {
            errors["username"] = ["Use 3 to 32 letters, digits, periods, underscores, or hyphens."];
        }

        if (email.Length > 254 || !MailAddress.TryCreate(email, out _))
        {
            errors["email"] = ["Enter a valid email address of at most 254 characters."];
        }

        if (request.Password is null || request.Password.Length < 12 || request.Password.Length > 256)
        {
            errors["password"] = ["Password must be between 12 and 256 characters."];
        }

        return errors;
    }

    public static Dictionary<string, string[]> ValidateVaultEntry(CreateVaultEntryRequest request)
    {
        var errors = new Dictionary<string, string[]>();
        if (string.IsNullOrWhiteSpace(request.Title) || request.Title.Trim().Length > 120)
        {
            errors["title"] = ["Title is required and must be at most 120 characters."];
        }

        if (string.IsNullOrWhiteSpace(request.Content) || request.Content.Length > 5000)
        {
            errors["content"] = ["Content is required and must be at most 5000 characters."];
        }

        return errors;
    }
}
