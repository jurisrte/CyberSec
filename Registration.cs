using System;
using System.Data.SqlClient;
using System.Drawing;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

namespace CyberSec
{
    public partial class Registration : Form
    {
        private const string ConnectionString =
            @"Data Source=DESKTOP-OI30C41\SQLEXPRESS;
            Initial Catalog=SecureLoginDB;
            Integrated Security=True";
        private const string PasswordPlaceholder = "Strong password";
        private const string ConfirmPasswordPlaceholder = "Confirm password";

        public Registration()
        {
            InitializeComponent();
            button1.Click += button1_Click;
        }

        private void TextBoxPlaceholder_Enter(object sender, EventArgs e)
        {
            var textBox = (TextBox)sender;
            var placeholder = textBox.Tag as string;

            if (placeholder == null || textBox.Text != placeholder)
            {
                return;
            }

            textBox.Text = string.Empty;
            textBox.ForeColor = SystemColors.WindowText;
            textBox.Font = new Font(textBox.Font, FontStyle.Regular);

            if (placeholder == PasswordPlaceholder || placeholder == ConfirmPasswordPlaceholder)
            {
                textBox.PasswordChar = '*';
            }
        }

        private void TextBoxPlaceholder_Leave(object sender, EventArgs e)
        {
            var textBox = (TextBox)sender;
            var placeholder = textBox.Tag as string;

            if (placeholder == null || !string.IsNullOrWhiteSpace(textBox.Text))
            {
                return;
            }

            textBox.Text = placeholder;
            textBox.ForeColor = Color.Gray;
            textBox.Font = new Font(textBox.Font, FontStyle.Italic);

            if (placeholder == PasswordPlaceholder || placeholder == ConfirmPasswordPlaceholder)
            {
                textBox.PasswordChar = '\0';
            }
        }

        private void button1_Click(object sender, EventArgs e)
        {
            var firstName = textBox1.Text;
            var surname = textBox4.Text;
            var username = textBox6.Text;
            var email = textBox2.Text;
            var password = textBox3.Text;
            var confirmPassword = textBox5.Text;

            var missingFields = new System.Collections.Generic.List<string>();

            if (string.IsNullOrWhiteSpace(firstName))
            {
                missingFields.Add("First name");
            }

            if (string.IsNullOrWhiteSpace(surname))
            {
                missingFields.Add("Surname");
            }

            if (string.IsNullOrWhiteSpace(username))
            {
                missingFields.Add("Username");
            }

            if (string.IsNullOrWhiteSpace(email))
            {
                missingFields.Add("Email");
            }

            if (string.IsNullOrWhiteSpace(password))
            {
                missingFields.Add("Password");
            }

            if (string.IsNullOrWhiteSpace(confirmPassword))
            {
                missingFields.Add("Confirm password");
            }

            if (missingFields.Count > 0)
            {
                MessageBox.Show(
                    "Please fill in: " + string.Join(", ", missingFields) + ".",
                    "Registration Error",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
                return;
            }

            var missing = new System.Collections.Generic.List<string>();

            if (!password.Any(char.IsUpper))
            {
                missing.Add("an uppercase letter");
            }

            if (!password.Any(char.IsDigit))
            {
                missing.Add("a number");
            }

            if (password.Length < 7)
            {
                missing.Add("at least 7 characters");
            }

            if (!password.Any(c => !char.IsLetterOrDigit(c)))
            {
                missing.Add("a special character");
            }

            if (password != confirmPassword)
            {
                missing.Add("matching confirmation password");
            }

            if (missing.Count > 0)
            {
                MessageBox.Show(
                    "Password requirements missing: " + string.Join(", ", missing) + ".",
                    "Registration Error",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
                return;
            }

            try
            {
                const string insertQuery =
                    "INSERT INTO Users (FirstName, Surname, Username, Email, PasswordHash) VALUES (@FirstName, @Surname, @Username, @Email, @PasswordHash)";

                using (var connection = new SqlConnection(ConnectionString))
                using (var command = new SqlCommand(insertQuery, connection))
                {
                    command.Parameters.AddWithValue("@FirstName", firstName);
                    command.Parameters.AddWithValue("@Surname", surname);
                    command.Parameters.AddWithValue("@Username", username);
                    command.Parameters.AddWithValue("@Email", email);
                    command.Parameters.AddWithValue("@PasswordHash", HashPassword(password));

                    connection.Open();
                    command.ExecuteNonQuery();
                }

                MessageBox.Show(
                    "Registration successful.",
                    "Registration",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);

                DialogResult = DialogResult.OK;
                Close();
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    "Registration failed: " + ex.Message,
                    "Registration Error",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
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

        private void Registration_Load(object sender, EventArgs e)
        {

        }
    }
}