using System.Net;
using System.Text;

public static class SafeHtmlRenderer
{
    public static string RenderEntry(VaultEntry entry)
    {
        // Encode each untrusted value at the point where it enters HTML output.
        // This preserves user text while turning <, >, &, and quotes into safe entities.
        string title = WebUtility.HtmlEncode(entry.Title);
        string content = WebUtility.HtmlEncode(entry.Content);
        var html = new StringBuilder();
        html.Append("<!doctype html><html><head><meta charset=\"utf-8\"><title>SafeVault entry</title></head><body>");
        html.Append("<h1>").Append(title).Append("</h1><p>").Append(content).Append("</p>");
        html.Append("</body></html>");
        return html.ToString();
    }
}
