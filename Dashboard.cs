using System;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using System.Windows.Forms;
using System.Xml.Linq;

namespace CyberSec
{
    public partial class Dashboard : Form
    {
        private readonly string _displayName;

        public Dashboard() : this("Not Signed in")
        {
        }

        public Dashboard(string displayName)
        {
            _displayName = string.IsNullOrWhiteSpace(displayName) ? "Not Signed in" : displayName;
            InitializeComponent();
        }

        private void Dashboard_Load(object sender, EventArgs e)
        {
            label8.Text = _displayName;
            LoadDatabaseTables();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            LoadDatabaseTables();
        }

        private void signOutButton_Click(object sender, EventArgs e)
        {
            var login = new Login();
            login.Show();
            Close();
        }

        private void LoadDatabaseTables()
        {
            try
            {
                var connectionString = GetConnectionString("CyberSecDb");
                if (string.IsNullOrWhiteSpace(connectionString))
                {
                    MessageBox.Show("Missing database connection string 'CyberSecDb'.", "Dashboard", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                using (var connection = new SqlConnection(connectionString))
                using (var adapter = new SqlDataAdapter(@"
SELECT
    TABLE_SCHEMA AS [Schema],
    TABLE_NAME AS [Table Name],
    TABLE_TYPE AS [Type]
FROM INFORMATION_SCHEMA.TABLES
ORDER BY TABLE_SCHEMA, TABLE_NAME", connection))
                {
                    var table = new DataTable();
                    adapter.Fill(table);
                    dataGridView1.AutoGenerateColumns = true;
                    dataGridView1.DataSource = table;
                    dataGridView1.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Unable to load database tables: " + ex.Message, "Dashboard", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private string GetConnectionString(string name)
        {
            try
            {
                var configPath = AppDomain.CurrentDomain.SetupInformation.ConfigurationFile;
                var doc = XDocument.Load(configPath);
                var node = doc.Descendants("add")
                    .FirstOrDefault(x => string.Equals((string)x.Attribute("name"), name, StringComparison.Ordinal));
                return node == null ? null : (string)node.Attribute("connectionString");
            }
            catch
            {
                return null;
            }
        }
    }
}
