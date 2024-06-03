using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Xml.Linq;

namespace PenktasPraktinis
{
    public partial class MainWindow : Window
    {
        private string _currentUser;
        private CryptoService _cryptoService;

        public MainWindow()
        {
            InitializeComponent();
        }

        private void RegisterButton_Click(object sender, RoutedEventArgs e)
        {
            var username = RegisterUsernameTextBox.Text;
            var password = RegisterPasswordBox.Password;

            var hashedPassword = ComputeHash(password);

            // Save the user data
            File.WriteAllText($"{username}.txt", hashedPassword);

            MessageBox.Show("User registered successfully!");
        }

        private void LoginButton_Click(object sender, RoutedEventArgs e)
        {
            var username = LoginUsernameTextBox.Text;
            var password = LoginPasswordBox.Password;

            if (File.Exists($"{username}.txt"))
            {
                var savedHashedPassword = File.ReadAllText($"{username}.txt");

                if (VerifyHash(password, savedHashedPassword))
                {
                    _currentUser = username;
                    _cryptoService = new CryptoService(password);
                    MessageBox.Show("Login successful!");
                }
                else
                {
                    MessageBox.Show("Incorrect password!");
                }
            }
            else
            {
                MessageBox.Show("User not found!");
            }
        }

        private void SavePasswordButton_Click(object sender, RoutedEventArgs e)
        {
            if (_currentUser == null)
            {
                MessageBox.Show("Please login first.");
                return;
            }

            var name = PasswordNameTextBox.Text;
            var password = PasswordBox.Password;
            var url = PasswordUrlTextBox.Text;
            var comment = PasswordCommentTextBox.Text;

            var encryptedPassword = _cryptoService.Encrypt(password);

            var passwordsFile = $"{_currentUser}_passwords.xml";
            XElement passwords;

            if (File.Exists(passwordsFile))
            {
                passwords = XElement.Load(passwordsFile);
            }
            else
            {
                passwords = new XElement("Passwords");
            }

            passwords.Add(new XElement("Password",
                new XElement("Name", name),
                new XElement("EncryptedPassword", encryptedPassword),
                new XElement("URL", url),
                new XElement("Comment", comment)));

            passwords.Save(passwordsFile);

            MessageBox.Show("Password saved successfully!");
        }

        private void SearchPasswordButton_Click(object sender, RoutedEventArgs e)
        {
            if (_currentUser == null)
            {
                MessageBox.Show("Please login first.");
                return;
            }

            var name = SearchNameTextBox.Text;
            var passwordsFile = $"{_currentUser}_passwords.xml";

            if (File.Exists(passwordsFile))
            {
                var passwords = XElement.Load(passwordsFile);

                foreach (var password in passwords.Elements("Password"))
                {
                    if (password.Element("Name").Value == name)
                    {
                        EncryptedPasswordTextBlock.Text = $"Encrypted Password: {password.Element("EncryptedPassword").Value}";
                        return;
                    }
                }
            }

            MessageBox.Show("Password not found!");
        }

        private void ShowPasswordButton_Click(object sender, RoutedEventArgs e)
        {
            if (_currentUser == null)
            {
                MessageBox.Show("Please login first.");
                return;
            }

            var encryptedPassword = EncryptedPasswordTextBlock.Text.Replace("Encrypted Password: ", "");

            if (!string.IsNullOrEmpty(encryptedPassword))
            {
                var decryptedPassword = _cryptoService.Decrypt(encryptedPassword);
                MessageBox.Show($"Decrypted Password: {decryptedPassword}");
            }
        }

        private void CopyToClipboardButton_Click(object sender, RoutedEventArgs e)
        {
            var encryptedPassword = EncryptedPasswordTextBlock.Text.Replace("Encrypted Password: ", "");

            if (!string.IsNullOrEmpty(encryptedPassword))
            {
                Clipboard.SetText(encryptedPassword);
                MessageBox.Show("Encrypted password copied to clipboard.");
            }
        }

        private void UpdatePasswordButton_Click(object sender, RoutedEventArgs e)
        {
            if (_currentUser == null)
            {
                MessageBox.Show("Please login first.");
                return;
            }

            var name = SearchNameTextBox.Text;
            var newPassword = PasswordBox.Password;
            var passwordsFile = $"{_currentUser}_passwords.xml";

            if (File.Exists(passwordsFile))
            {
                var passwords = XElement.Load(passwordsFile);

                foreach (var password in passwords.Elements("Password"))
                {
                    if (password.Element("Name").Value == name)
                    {
                        password.Element("EncryptedPassword").Value = _cryptoService.Encrypt(newPassword);
                        passwords.Save(passwordsFile);
                        MessageBox.Show("Password updated successfully!");
                        return;
                    }
                }
            }

            MessageBox.Show("Password not found!");
        }

        private void DeletePasswordButton_Click(object sender, RoutedEventArgs e)
        {
            if (_currentUser == null)
            {
                MessageBox.Show("Please login first.");
                return;
            }

            var name = SearchNameTextBox.Text;
            var passwordsFile = $"{_currentUser}_passwords.xml";

            if (File.Exists(passwordsFile))
            {
                var passwords = XElement.Load(passwordsFile);

                foreach (var password in passwords.Elements("Password"))
                {
                    if (password.Element("Name").Value == name)
                    {
                        password.Remove();
                        passwords.Save(passwordsFile);
                        MessageBox.Show("Password deleted successfully!");
                        return;
                    }
                }
            }

            MessageBox.Show("Password not found!");
        }

        private void GenerateRandomPasswordButton_Click(object sender, RoutedEventArgs e)
        {
            var randomPassword = GenerateRandomPassword(16);
            PasswordBox.Password = randomPassword;
            MessageBox.Show($"Generated Password: {randomPassword}");
        }

        private string ComputeHash(string input)
        {
            using (var sha256 = SHA256.Create())
            {
                var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
                return Convert.ToBase64String(bytes);
            }
        }

        private bool VerifyHash(string input, string hash)
        {
            var computedHash = ComputeHash(input);
            return computedHash == hash;
        }

        private string GenerateRandomPassword(int length)
        {
            const string validChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
            StringBuilder res = new StringBuilder();
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                byte[] uintBuffer = new byte[sizeof(uint)];

                while (length-- > 0)
                {
                    rng.GetBytes(uintBuffer);
                    uint num = BitConverter.ToUInt32(uintBuffer, 0);
                    res.Append(validChars[(int)(num % (uint)validChars.Length)]);
                }
            }

            return res.ToString();
        }
    }

    public class CryptoService
    {
        private readonly byte[] key;
        private readonly byte[] iv;

        public CryptoService(string password)
        {
            using (var sha256 = SHA256.Create())
            {
                key = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
                iv = new byte[16];
                Array.Copy(key, iv, 16);
            }
        }

        public string Encrypt(string plainText)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;

                var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        using (var sw = new StreamWriter(cs))
                        {
                            sw.Write(plainText);
                        }
                    }
                    return Convert.ToBase64String(ms.ToArray());
                }
            }
        }

        public string Decrypt(string cipherText)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;

                var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (var ms = new MemoryStream(Convert.FromBase64String(cipherText)))
                {
                    using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        using (var sr = new StreamReader(cs))
                        {
                            return sr.ReadToEnd();
                        }
                    }
                }
            }
        }
    }
}
