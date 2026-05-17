using System;

namespace CyberSec
{
    /// <summary>
    /// Instructions for setting up Google OAuth credentials in PowerShell.
    /// 
    /// SETUP INSTRUCTIONS:
    /// ==================
    /// 
    /// 1. Get your credentials from Google Cloud Console:
    ///    - Go to https://console.cloud.google.com/
    ///    - Create a new OAuth 2.0 credential (Desktop app type)
    ///    - Copy the Client ID and Client Secret
    /// 
    /// 2. Set environment variables in PowerShell:
    ///    
    ///    # Open PowerShell and run:
    ///    $env:GOOGLE_CLIENT_ID='YOUR_CLIENT_ID_HERE'
    ///    $env:GOOGLE_CLIENT_SECRET='YOUR_CLIENT_SECRET_HERE'
    ///    
    ///    # Example:
    ///    $env:GOOGLE_CLIENT_ID='508500391367-e2mlkso2hod2kjtn2peul9s8mq0srpbr.apps.googleusercontent.com'
    ///    $env:GOOGLE_CLIENT_SECRET='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'
    /// 
    /// 3. Set AppKey (existing requirement):
    ///    
    ///    $env:CYBERSEC_APPKEY='LOCAL-DEV-APPKEY'
    /// 
    /// 4. Run the CyberSec application from the same PowerShell session
    /// 
    /// SECURITY NOTES:
    /// ================
    /// - NEVER commit secrets to source control (git, etc.)
    /// - NEVER share secrets in conversations, emails, or forums
    /// - Always regenerate credentials if they're exposed
    /// - Use environment variables instead of hardcoding secrets
    /// - The OAuth flow uses PKCE (Proof Key for Code Exchange) for extra security
    /// - Client secret is only used server-side, never exposed to the browser
    /// 
    /// TROUBLESHOOTING:
    /// ================
    /// - If you get "Missing Google OAuth credentials" error:
    ///   → Set the environment variables in PowerShell before running the app
    /// 
    /// - If the browser doesn't open for authorization:
    ///   → A manual URL will be shown; copy and paste it in your browser
    ///   → Ensure port 8080 is not blocked by firewall
    /// 
    /// - If authorization fails with "state mismatch":
    ///   → This is a security check; try the authorization again
    /// </summary>
    public static class OAuthSetupInstructions
    {
        /// <summary>
        /// Returns the setup instructions as a formatted string.
        /// </summary>
        public static string GetInstructions()
        {
            return @"
GOOGLE OAUTH 2.0 SETUP INSTRUCTIONS
=====================================

1. Get credentials from Google Cloud Console:
   https://console.cloud.google.com/apis/credentials

2. Set environment variables in PowerShell:

    $env:GOOGLE_CLIENT_ID='YOUR_CLIENT_ID_HERE'
    $env:GOOGLE_CLIENT_SECRET='YOUR_CLIENT_SECRET_HERE'
    $env:CYBERSEC_APPKEY='LOCAL-DEV-APPKEY'
    $env:CYBERSEC_SMTP_HOST='smtp.example.com'
    $env:CYBERSEC_SMTP_PORT='587'
    $env:CYBERSEC_SMTP_USERNAME='your-smtp-username'
    $env:CYBERSEC_SMTP_PASSWORD='your-smtp-password'
    $env:CYBERSEC_SMTP_FROM_ADDRESS='no-reply@example.com'
    $env:CYBERSEC_SMTP_FROM_NAME='CyberSec'
    $env:CYBERSEC_SMTP_ENABLE_SSL='true'

3. Run the CyberSec application from PowerShell:

   # Navigate to project folder
   cd E:\Vs Code\VStudio\CyberSec\

   # Run the application
   dotnet run

   # Or if using Visual Studio, just run from the IDE

4. Click 'Google SSO' button to start OAuth authorization

SECURITY REMINDERS:
- Never commit secrets to git
- Regenerate credentials if exposed
- Use environment variables, never hardcode secrets
";
        }
    }
}
