using System;
using System.Windows.Forms;

namespace CyberSec
{
    /// <summary>
    /// Loads Google OAuth 2.0 credentials from PowerShell environment variables.
    /// Set these environment variables in PowerShell before running the app:
    /// 
    /// $env:GOOGLE_CLIENT_ID='YOUR_CLIENT_ID'
    /// $env:GOOGLE_CLIENT_SECRET='YOUR_CLIENT_SECRET'
    /// 
    /// Example with actual credentials (replace with your own):
    /// $env:GOOGLE_CLIENT_ID='508500391367-e2mlkso2hod2kjtn2peul9s8mq0srpbr.apps.googleusercontent.com'
    /// $env:GOOGLE_CLIENT_SECRET='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'
    /// </summary>
    public class GoogleOAuthConfig
    {
        public string ClientId { get; private set; }
        public string ClientSecret { get; private set; }
        public string RedirectUri { get; private set; }

        private GoogleOAuthConfig(string clientId, string clientSecret, string redirectUri)
        {
            ClientId = clientId;
            ClientSecret = clientSecret;
            RedirectUri = redirectUri;
        }

        /// <summary>
        /// Loads OAuth config from environment variables.
        /// Returns null and shows error if credentials are missing.
        /// </summary>
        public static GoogleOAuthConfig Load()
        {
            var clientId = GetEnvironmentVariable("GOOGLE_CLIENT_ID");
            var clientSecret = GetEnvironmentVariable("GOOGLE_CLIENT_SECRET");

            if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(clientSecret))
            {
                MessageBox.Show(
                    "Missing Google OAuth credentials.\r\n\r\n" +
                    "Set these in PowerShell before running the app:\r\n\r\n" +
                    "$env:GOOGLE_CLIENT_ID='YOUR_CLIENT_ID'\r\n" +
                    "$env:GOOGLE_CLIENT_SECRET='YOUR_CLIENT_SECRET'\r\n\r\n" +
                    "Get credentials from: https://console.cloud.google.com/apis/credentials",
                    "Google OAuth Configuration",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
                return null;
            }

            // Standard redirect URI for desktop app (loopback)
            var redirectUri = "http://localhost:8080/oauth2callback";

            return new GoogleOAuthConfig(clientId, clientSecret, redirectUri);
        }

        /// <summary>
        /// Loads environment variable from Process, User, or Machine scope.
        /// </summary>
        private static string GetEnvironmentVariable(string variableName)
        {
            var value = Environment.GetEnvironmentVariable(variableName, EnvironmentVariableTarget.Process);
            if (string.IsNullOrWhiteSpace(value))
            {
                value = Environment.GetEnvironmentVariable(variableName, EnvironmentVariableTarget.User);
            }

            if (string.IsNullOrWhiteSpace(value))
            {
                value = Environment.GetEnvironmentVariable(variableName, EnvironmentVariableTarget.Machine);
            }

            return value;
        }
    }
}
