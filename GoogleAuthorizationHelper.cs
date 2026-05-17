using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Windows.Forms;

namespace CyberSec
{
    /// <summary>
    /// Handles Google OAuth 2.0 authorization code flow.
    /// This implements the secure "Authorization Code Grant" flow where:
    /// 1. User is redirected to Google login (in browser)
    /// 2. User authorizes the app
    /// 3. Google redirects back with an authorization code
    /// 4. App exchanges code for access token (using client_secret backend-side)
    /// </summary>
    public class GoogleAuthorizationHelper
    {
        private readonly GoogleOAuthConfig _config;
        private const string GoogleAuthorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth";
        private const string GoogleTokenEndpoint = "https://oauth2.googleapis.com/token";
        private const string GoogleUserInfoEndpoint = "https://www.googleapis.com/oauth2/v2/userinfo";
        private const string Scope = "email profile openid";

        public GoogleAuthorizationHelper(GoogleOAuthConfig config)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));
        }

        /// <summary>
        /// Initiates the OAuth 2.0 authorization code flow.
        /// Opens browser for user to login and authorize the app.
        /// </summary>
        public async Task<GoogleUserInfo> AuthorizeAndGetUserInfoAsync()
        {
            try
            {
                // Step 1: Generate authorization code and state for CSRF protection
                var state = GenerateRandomString(32);
                var codeChallenge = GenerateRandomString(128); // For PKCE (code challenge)

                // Step 2: Build authorization URL
                var authUrl = BuildAuthorizationUrl(state, codeChallenge);

                // Step 3: Start local server to receive redirect
                using (var listener = new HttpListener())
                {
                    listener.Prefixes.Add(_config.RedirectUri + "/");
                    listener.Start();

                    // Step 4: Open browser for user authorization
                    OpenBrowser(authUrl);

                    // Step 5: Wait for callback with authorization code
                    var context = await listener.GetContextAsync();
                    var code = context.Request.QueryString["code"];
                    var returnedState = context.Request.QueryString["state"];

                    // Send success response to browser
                    using (var response = context.Response)
                    {
                        string responseString = "<html><body><h1>Authorization successful!</h1>" +
                            "<p>You can close this window and return to the application.</p></body></html>";
                        byte[] buffer = Encoding.UTF8.GetBytes(responseString);
                        response.ContentLength64 = buffer.Length;
                        response.OutputStream.Write(buffer, 0, buffer.Length);
                    }

                    listener.Stop();

                    // Step 6: Validate state for CSRF protection
                    if (!string.Equals(state, returnedState, StringComparison.Ordinal))
                    {
                        MessageBox.Show("Authorization failed: State mismatch. Possible CSRF attack.", 
                            "OAuth Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return null;
                    }

                    if (string.IsNullOrWhiteSpace(code))
                    {
                        return null;
                    }

                    // Step 7: Exchange authorization code for access token
                    var accessToken = await ExchangeCodeForTokenAsync(code, codeChallenge);
                    if (string.IsNullOrWhiteSpace(accessToken))
                    {
                        return null;
                    }

                    // Step 8: Get user information using access token
                    var userInfo = await GetUserInfoAsync(accessToken);
                    return userInfo;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("OAuth authorization failed: " + ex.Message, "OAuth Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
                return null;
            }
        }

        /// <summary>
        /// Builds the Google authorization URL with necessary parameters.
        /// </summary>
        private string BuildAuthorizationUrl(string state, string codeChallenge)
        {
            var parameters = new Dictionary<string, string>
            {
                { "client_id", _config.ClientId },
                { "redirect_uri", _config.RedirectUri },
                { "response_type", "code" },
                { "scope", Scope },
                { "state", state },
                { "code_challenge", codeChallenge },
                { "code_challenge_method", "plain" }
            };

            var query = string.Join("&", parameters.Select(p =>
                $"{Uri.EscapeDataString(p.Key)}={Uri.EscapeDataString(p.Value)}"));

            return $"{GoogleAuthorizationEndpoint}?{query}";
        }

        /// <summary>
        /// Exchanges the authorization code for an access token.
        /// This must be done server-side to keep client_secret secure.
        /// </summary>
        private async Task<string> ExchangeCodeForTokenAsync(string code, string codeVerifier)
        {
            try
            {
                var tokenRequest = new Dictionary<string, string>
                {
                    { "grant_type", "authorization_code" },
                    { "code", code },
                    { "client_id", _config.ClientId },
                    { "client_secret", _config.ClientSecret },
                    { "redirect_uri", _config.RedirectUri },
                    { "code_verifier", codeVerifier }
                };

                using (var client = new HttpClient())
                {
                    var content = new FormUrlEncodedContent(tokenRequest);
                    var response = await client.PostAsync(GoogleTokenEndpoint, content);

                    if (!response.IsSuccessStatusCode)
                    {
                        var errorContent = await response.Content.ReadAsStringAsync();
                        MessageBox.Show($"Token exchange failed: {errorContent}", "OAuth Error",
                            MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return null;
                    }

                    var jsonResponse = await response.Content.ReadAsStringAsync();
                    var accessToken = ExtractJsonValue(jsonResponse, "\"access_token\"");
                    return accessToken;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Token exchange error: " + ex.Message, "OAuth Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
                return null;
            }
        }

        /// <summary>
        /// Gets user information from Google using the access token.
        /// </summary>
        private async Task<GoogleUserInfo> GetUserInfoAsync(string accessToken)
        {
            try
            {
                using (var client = new HttpClient())
                {
                    client.DefaultRequestHeaders.Authorization = 
                        new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

                    var response = await client.GetAsync(GoogleUserInfoEndpoint);

                    if (!response.IsSuccessStatusCode)
                    {
                        return null;
                    }

                    var json = await response.Content.ReadAsStringAsync();
                    var email = ExtractJsonValue(json, "\"email\"");
                    var name = ExtractJsonValue(json, "\"name\"");

                    if (string.IsNullOrWhiteSpace(email))
                    {
                        return null;
                    }

                    return new GoogleUserInfo
                    {
                        Email = email,
                        Name = string.IsNullOrWhiteSpace(name) ? email : name
                    };
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Failed to retrieve user info: " + ex.Message, "OAuth Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
                return null;
            }
        }

        /// <summary>
        /// Opens the authorization URL in the system's default browser.
        /// </summary>
        private void OpenBrowser(string url)
        {
            try
            {
                Process.Start(url);
            }
            catch
            {
                // Fallback for different Windows versions
                try
                {
                    Process.Start(new ProcessStartInfo("cmd", $"/c start {url}") { CreateNoWindow = true });
                }
                catch
                {
                    MessageBox.Show($"Please open this URL in your browser:\r\n{url}",
                        "Manual Authorization Required", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
        }

        /// <summary>
        /// Extracts a JSON value by property name.
        /// </summary>
        private string ExtractJsonValue(string json, string propertyToken)
        {
            var tokenIndex = json.IndexOf(propertyToken, StringComparison.OrdinalIgnoreCase);
            if (tokenIndex < 0)
            {
                return null;
            }

            var colonIndex = json.IndexOf(':', tokenIndex);
            if (colonIndex < 0)
            {
                return null;
            }

            var firstQuote = json.IndexOf('"', colonIndex + 1);
            if (firstQuote < 0)
            {
                return null;
            }

            var secondQuote = json.IndexOf('"', firstQuote + 1);
            if (secondQuote < 0)
            {
                return null;
            }

            return json.Substring(firstQuote + 1, secondQuote - firstQuote - 1);
        }

        /// <summary>
        /// Generates a random string for state/challenge parameters.
        /// </summary>
        private string GenerateRandomString(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
            var random = new Random();
            var result = new StringBuilder(length);

            for (int i = 0; i < length; i++)
            {
                result.Append(chars[random.Next(chars.Length)]);
            }

            return result.ToString();
        }
    }

    /// <summary>
    /// Contains Google user information retrieved from OAuth.
    /// </summary>
    public class GoogleUserInfo
    {
        public string Email { get; set; }
        public string Name { get; set; }
    }
}
