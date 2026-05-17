using System;
using System.Data.SqlClient;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Xml.Linq;

namespace CyberSec
{
    public partial class Login : Form
    {
        private const string ConnectionString =
            @"Data Source=DESKTOP-OI30C41\SQLEXPRESS;
            Initial Catalog=SecureLoginDB;
            Integrated Security=True";

        private readonly Random _random = new Random();
        private int _failedLoginAttempts;
        private DateTime? _lockoutEndsAtUtc;
        private const int MaxFailedLoginAttempts = 5;
        private static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(10);

        public Login()
        {
            InitializeComponent();
            textBox2.TextChanged += PasswordTextBox_TextChanged;
        }

        private void Login_Load(object sender, EventArgs e)
        {
            textBox3.Visible = false;
            label9.Visible = false;
            SetPasswordFieldMasked(false);
        }

        private void label1_Click(object sender, EventArgs e)
        {
        }

        private void label2_Click(object sender, EventArgs e)
        {
            using (var registrationForm = new Registration())
            {
                registrationForm.ShowDialog(this);
            }
        }

        private void Loginbtn_Click(object sender, EventArgs e)
        {
            if (!ValidateAppKey() || !EnsureLoginAllowed())
            {
                return;
            }

            var usernameOrEmail = GetUserInput(textBox1);
            var password = GetUserInput(textBox2);

            if (string.IsNullOrWhiteSpace(usernameOrEmail) || string.IsNullOrWhiteSpace(password))
            {
                var attemptsLeft = RegisterFailedAttempt();
                ShowAuthFailure("Enter username/email and password.", attemptsLeft);
                return;
            }

            if (!ValidateCredentials(usernameOrEmail, password))
            {
                var attemptsLeft = RegisterFailedAttempt();
                ShowAuthFailure("Invalid username/email or password.", attemptsLeft);
                return;
            }

            var otpEmail = GetOtpEmailForLogin(usernameOrEmail);
            if (string.IsNullOrWhiteSpace(otpEmail))
            {
                var attemptsLeft = RegisterFailedAttempt();
                ShowAuthFailure("Unable to determine the email address for OTP delivery.", attemptsLeft);
                return;
            }

            var displayName = GetDisplayNameForLogin(usernameOrEmail);
            if (string.IsNullOrWhiteSpace(displayName))
            {
                displayName = otpEmail;
            }

            if (!PerformOtpChallenge(otpEmail))
            {
                var attemptsLeft = RegisterFailedAttempt();
                ShowAuthFailure("OTP verification failed.", attemptsLeft);
                return;
            }

            ResetLoginAttempts();
            label6.Text = "Signed in";
            MessageBox.Show("Login successful with OTP verification.", "Authentication", MessageBoxButtons.OK, MessageBoxIcon.Information);
            OpenDashboard(displayName);
        }

        private async void SsoBtn_Click(object sender, EventArgs e)
        {
            if (!ValidateAppKey() || !EnsureLoginAllowed())
            {
                return;
            }

            try
            {
                // Load OAuth credentials from PowerShell environment variables
                var oauthConfig = GoogleOAuthConfig.Load();
                if (oauthConfig == null)
                {
                    RegisterFailedAttempt();
                    return;
                }

                // Perform secure OAuth 2.0 authorization code flow
                var authHelper = new GoogleAuthorizationHelper(oauthConfig);
                var userInfo = await authHelper.AuthorizeAndGetUserInfoAsync();
                if (userInfo == null)
                {
                    RegisterFailedAttempt();
                    MessageBox.Show("Unable to retrieve user information from Google.", "SSO", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                if (!PerformOtpChallenge(userInfo.Email))
                {
                    RegisterFailedAttempt();
                    return;
                }

                ResetLoginAttempts();
                label6.Text = userInfo.Name;
                MessageBox.Show("Google SSO successful with OTP verification.", "SSO", MessageBoxButtons.OK, MessageBoxIcon.Information);
                OpenDashboard(userInfo.Email);
            }
            catch (Exception ex)
            {
                RegisterFailedAttempt();
                MessageBox.Show("Google SSO failed: " + ex.Message, "SSO", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private bool ValidateAppKey()
        {
            const string expectedAppKey = "LOCAL-DEV-APPKEY";

            var appKey = Environment.GetEnvironmentVariable("CYBERSEC_APPKEY", EnvironmentVariableTarget.Process);
            if (string.IsNullOrWhiteSpace(appKey))
            {
                appKey = Environment.GetEnvironmentVariable("CYBERSEC_APPKEY", EnvironmentVariableTarget.User);
            }

            if (string.IsNullOrWhiteSpace(appKey))
            {
                appKey = Environment.GetEnvironmentVariable("CYBERSEC_APPKEY", EnvironmentVariableTarget.Machine);
            }

            if (string.IsNullOrWhiteSpace(appKey))
            {
                MessageBox.Show("Missing backend AppKey. Set it in PowerShell: $env:CYBERSEC_APPKEY='LOCAL-DEV-APPKEY'", "AppKey", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }

            if (!string.Equals(appKey.Trim(), expectedAppKey, StringComparison.Ordinal))
            {
                MessageBox.Show("Invalid backend AppKey from PowerShell environment.", "AppKey", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }

            return true;
        }

        private bool PerformOtpChallenge(string identity)
        {
            var otpLength = ReadIntSetting("Otp.Length", 6);
            var ttlMinutes = ReadIntSetting("Otp.TtlMinutes", 5);
            var otp = GenerateOtp(otpLength);
            var expiresAtUtc = DateTime.UtcNow.AddMinutes(ttlMinutes);

            try
            {
                SendOtpBySmtp(identity, otp);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Unable to send OTP: " + ex.Message, "OTP", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }

            var otpInput = PromptForInput("OTP Verification", "Enter the one-time password sent to your email address:");
            if (string.IsNullOrWhiteSpace(otpInput))
            {
                MessageBox.Show("OTP verification canceled.", "OTP", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }

            if (DateTime.UtcNow > expiresAtUtc)
            {
                MessageBox.Show("OTP expired. Please log in again.", "OTP", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }

            if (!string.Equals(otp.Trim(), otpInput.Trim(), StringComparison.Ordinal))
            {
                MessageBox.Show("Invalid OTP.", "OTP", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }

            return true;
        }

        private string GenerateOtp(int length)
        {
            var builder = new StringBuilder(length);
            for (var i = 0; i < length; i++)
            {
                builder.Append(_random.Next(0, 10));
            }

            return builder.ToString();
        }

        private int ReadIntSetting(string key, int fallback)
        {
            int value;
            return int.TryParse(GetSetting(key, fallback.ToString()), out value) ? value : fallback;
        }

        private string GetSetting(string key, string fallback)
        {
            try
            {
                var configPath = AppDomain.CurrentDomain.SetupInformation.ConfigurationFile;
                var doc = XDocument.Load(configPath);
                var node = doc.Descendants("add")
                    .FirstOrDefault(x => string.Equals((string)x.Attribute("key"), key, StringComparison.Ordinal));
                var value = node == null ? null : (string)node.Attribute("value");
                return string.IsNullOrWhiteSpace(value) ? fallback : value;
            }
            catch
            {
                return fallback;
            }
        }

        private void SendOtpBySmtp(string destination, string otp)
        {
            const string smtpHost = "smtp.gmail.com";
            const int smtpPort = 587;
            const bool enableSsl = true;
            const string fromAddress = "reyesjuris5@gmail.com";
            const string fromDisplayName = "RBAC";
            const string smtpUser = "reyesjuris5@gmail.com";
            const string smtpPassword = "lhzp ezcj frth fiiv";

            using (var message = new MailMessage())
            using (var smtpClient = new SmtpClient(smtpHost, smtpPort))
            {
                message.From = new MailAddress(fromAddress, fromDisplayName);
                message.To.Add(destination);
                message.Subject = "Your CyberSec OTP";
                message.Body = "Your one-time password is: " + otp;

                smtpClient.EnableSsl = enableSsl;
                smtpClient.UseDefaultCredentials = false;
                smtpClient.Credentials = new NetworkCredential(smtpUser, smtpPassword);
                smtpClient.Send(message);
            }
        }

        private string PromptForInput(string title, string prompt)
        {
            using (var promptForm = new Form())
            using (var textLabel = new Label())
            using (var inputBox = new TextBox())
            using (var confirmButton = new Button())
            {
                promptForm.Width = 460;
                promptForm.Height = 160;
                promptForm.Text = title;
                promptForm.StartPosition = FormStartPosition.CenterParent;
                promptForm.FormBorderStyle = FormBorderStyle.FixedDialog;
                promptForm.MinimizeBox = false;
                promptForm.MaximizeBox = false;

                textLabel.Left = 10;
                textLabel.Top = 10;
                textLabel.Width = 420;
                textLabel.Text = prompt;

                inputBox.Left = 10;
                inputBox.Top = 35;
                inputBox.Width = 420;

                confirmButton.Text = "OK";
                confirmButton.Left = 340;
                confirmButton.Width = 90;
                confirmButton.Top = 70;
                confirmButton.DialogResult = DialogResult.OK;

                promptForm.Controls.Add(textLabel);
                promptForm.Controls.Add(inputBox);
                promptForm.Controls.Add(confirmButton);
                promptForm.AcceptButton = confirmButton;

                return promptForm.ShowDialog(this) == DialogResult.OK ? inputBox.Text : null;
            }
        }

        private bool EnsureLoginAllowed()
        {
            if (_lockoutEndsAtUtc.HasValue)
            {
                if (DateTime.UtcNow < _lockoutEndsAtUtc.Value)
                {
                    var remaining = _lockoutEndsAtUtc.Value - DateTime.UtcNow;
                    MessageBox.Show(
                        string.Format("Too many failed attempts. Try again in {0} minute(s) and {1} second(s).", remaining.Minutes, remaining.Seconds),
                        "Locked Out",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Warning);
                    return false;
                }

                _lockoutEndsAtUtc = null;
                _failedLoginAttempts = 0;
            }

            return true;
        }

        private void ShowAuthFailure(string message, int attemptsLeft)
        {
            MessageBox.Show(
                string.Format("{0} Attempts left before timeout: {1}.", message, attemptsLeft),
                "Authentication",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        }

        private int RegisterFailedAttempt()
        {
            _failedLoginAttempts++;
            var attemptsLeft = MaxFailedLoginAttempts - _failedLoginAttempts;
            if (_failedLoginAttempts >= MaxFailedLoginAttempts)
            {
                _lockoutEndsAtUtc = DateTime.UtcNow.Add(LockoutDuration);
                _failedLoginAttempts = 0;
                attemptsLeft = 0;
                MessageBox.Show(
                    string.Format("Too many failed attempts. Login is locked for {0} minutes.", (int)LockoutDuration.TotalMinutes),
                    "Locked Out",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
            }

            return attemptsLeft;
        }

        private void ResetLoginAttempts()
        {
            _failedLoginAttempts = 0;
            _lockoutEndsAtUtc = null;
        }

        private void OpenDashboard(string displayName)
        {
            var dashboard = new Dashboard(displayName);
            dashboard.Show();
            this.Hide();
        }

        private string GetUserInput(TextBox textBox)
        {
            var placeholder = textBox.Tag as string ?? string.Empty;
            return string.Equals(textBox.Text, placeholder, StringComparison.Ordinal) ? string.Empty : textBox.Text.Trim();
        }

        private void TextBoxPlaceholder_Enter(object sender, EventArgs e)
        {
            var textBox = sender as TextBox;
            if (textBox == null)
            {
                return;
            }

            var placeholder = textBox.Tag as string ?? string.Empty;
            if (textBox.Text == placeholder)
            {
                textBox.Text = string.Empty;
                textBox.ForeColor = Color.Black;

                if (textBox == textBox2)
                {
                    SetPasswordFieldMasked(true);
                }
            }
        }

        private void TextBoxPlaceholder_Leave(object sender, EventArgs e)
        {
            var textBox = sender as TextBox;
            if (textBox == null)
            {
                return;
            }

            if (string.IsNullOrWhiteSpace(textBox.Text))
            {
                var placeholder = textBox.Tag as string ?? string.Empty;
                textBox.Text = placeholder;
                textBox.ForeColor = Color.Gray;

                if (textBox == textBox2)
                {
                    SetPasswordFieldMasked(false);
                }
            }
        }

        private bool ValidateCredentials(string usernameOrEmail, string password)
        {
            var passwordHash = HashPassword(password);
            var connectionString = GetDatabaseConnectionString();
            if (string.IsNullOrWhiteSpace(connectionString))
            {
                MessageBox.Show("Missing database connection string 'CyberSecDb'.", "Authentication", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }

            const string query = @"
SELECT TOP 1 Email
FROM dbo.Users
WHERE (Username = @Login OR Email = @Login)
  AND PasswordHash = @PasswordHash";

            try
            {
                using (var connection = new SqlConnection(connectionString))
                using (var command = new SqlCommand(query, connection))
                {
                    command.CommandTimeout = 10;
                    command.Parameters.AddWithValue("@Login", usernameOrEmail.Trim());
                    command.Parameters.AddWithValue("@PasswordHash", passwordHash);

                    connection.Open();
                    var email = command.ExecuteScalar() as string;
                    return !string.IsNullOrWhiteSpace(email);
                }
            }
            catch (SqlException ex)
            {
                MessageBox.Show("Database error while validating credentials: " + ex.Message, "Authentication", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }
            catch (Exception ex)
            {
                MessageBox.Show("Unable to validate credentials: " + ex.Message, "Authentication", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }
        }

        private string GetDatabaseConnectionString()
        {
            try
            {
                var configPath = AppDomain.CurrentDomain.SetupInformation.ConfigurationFile;
                var doc = XDocument.Load(configPath);
                var node = doc.Descendants("add")
                    .FirstOrDefault(x => string.Equals((string)x.Attribute("name"), "CyberSecDb", StringComparison.Ordinal));
                return node == null ? null : (string)node.Attribute("connectionString");
            }
            catch
            {
                return null;
            }
        }

        private string GetOtpEmailForLogin(string usernameOrEmail)
        {
            var connectionString = GetDatabaseConnectionString();
            if (string.IsNullOrWhiteSpace(connectionString))
            {
                return null;
            }

            const string query = @"
SELECT TOP 1 Email
FROM dbo.Users
WHERE Username = @Login OR Email = @Login";

            try
            {
                using (var connection = new SqlConnection(connectionString))
                using (var command = new SqlCommand(query, connection))
                {
                    command.CommandTimeout = 10;
                    command.Parameters.AddWithValue("@Login", usernameOrEmail.Trim());

                    connection.Open();
                    var email = command.ExecuteScalar() as string;
                    return string.IsNullOrWhiteSpace(email) ? null : email;
                }
            }
            catch
            {
                return null;
            }
        }

        private string GetDisplayNameForLogin(string usernameOrEmail)
        {
            var connectionString = GetDatabaseConnectionString();
            if (string.IsNullOrWhiteSpace(connectionString))
            {
                return null;
            }

            const string query = @"
SELECT TOP 1
    LTRIM(RTRIM(COALESCE(NULLIF(FirstName, ''), '') + CASE WHEN NULLIF(Surname, '') IS NULL THEN '' ELSE ' ' + Surname END)) AS FullName,
    Username,
    Email
FROM dbo.Users
WHERE Username = @Login OR Email = @Login";

            try
            {
                using (var connection = new SqlConnection(connectionString))
                using (var command = new SqlCommand(query, connection))
                {
                    command.CommandTimeout = 10;
                    command.Parameters.AddWithValue("@Login", usernameOrEmail.Trim());

                    connection.Open();
                    using (var reader = command.ExecuteReader())
                    {
                        if (!reader.Read())
                        {
                            return null;
                        }

                        var fullName = reader["FullName"] as string;
                        if (!string.IsNullOrWhiteSpace(fullName))
                        {
                            return fullName;
                        }

                        var username = reader["Username"] as string;
                        if (!string.IsNullOrWhiteSpace(username))
                        {
                            return username;
                        }

                        var email = reader["Email"] as string;
                        return string.IsNullOrWhiteSpace(email) ? null : email;
                    }
                }
            }
            catch
            {
                return null;
            }
        }

        private void PasswordTextBox_TextChanged(object sender, EventArgs e)
        {
            if (textBox2.Text == (textBox2.Tag as string ?? string.Empty))
            {
                return;
            }

            SetPasswordFieldMasked(!string.IsNullOrWhiteSpace(textBox2.Text));
        }

        private void SetPasswordFieldMasked(bool masked)
        {
            textBox2.UseSystemPasswordChar = masked;
            textBox2.PasswordChar = masked ? '*' : '\0';
        }

        private static string HashPassword(string password)
        {
            using (var sha256 = SHA256.Create())
            {
                var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
                var builder = new StringBuilder(hashBytes.Length * 2);

                foreach (var hashByte in hashBytes)
                {
                    builder.Append(hashByte.ToString("x2"));
                }

                return builder.ToString();
            }
        }
    }
}