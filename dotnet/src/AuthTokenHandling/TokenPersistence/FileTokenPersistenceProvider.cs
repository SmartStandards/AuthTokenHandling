using Newtonsoft.Json;
using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace Security.AccessTokenHandling {

  /// <summary>
  /// File based default implementation of ITokenPersistenceProvider.
  /// Stores one encrypted file per token source under
  /// '%LOCALAPPDATA%/&lt;ApplicationName&gt;/ATH/[&lt;customScope&gt;/]&lt;tokenSourceId&gt;.json'
  /// (or below the common application data folder, if userScope is false).
  /// The content is encrypted with AES-256-CBC and authenticated with HMAC-SHA256 (encrypt-then-MAC);
  /// both keys are derived from a caller-supplied passphrase via PBKDF2 (SHA256).
  /// This implementation is platform independent (no DPAPI).
  /// </summary>
  public class FileTokenPersistenceProvider : ITokenPersistenceProvider {

    private const int _SaltLength = 16;
    private const int _IvLength = 16;
    private const int _MacLength = 32;
    private const int _Pbkdf2Iterations = 100000;
    private const string _SubFolderName = "ATH";

    private string _Passphrase;
    private string _ApplicationName;
    private string _RootDirectoryOverride;

    /// <summary>
    /// Creates the provider.
    /// </summary>
    /// <param name="encryptionPassphrase">Secret used to derive the encryption keys (must not be empty).</param>
    /// <param name="applicationName">Name of the application folder (null or empty: name of the entry assembly).</param>
    public FileTokenPersistenceProvider(string encryptionPassphrase, string applicationName = null) {
      if (string.IsNullOrEmpty(encryptionPassphrase)) {
        throw new ArgumentException($"'{nameof(encryptionPassphrase)}' must not be empty!");
      }
      _Passphrase = encryptionPassphrase;
      if (string.IsNullOrWhiteSpace(applicationName)) {
        _ApplicationName = GetDefaultApplicationName();
      }
      else {
        _ApplicationName = applicationName;
      }
    }

    /// <summary>
    /// OPTIONAL: an explicit root directory which replaces the user/machine wide application data folder
    /// (for example for tests or for hosts with special storage locations).
    /// </summary>
    public string RootDirectoryOverride {
      get {
        return _RootDirectoryOverride;
      }
      set {
        _RootDirectoryOverride = value;
      }
    }

    /// <summary>
    /// Loads the persisted tokens of a token source.
    /// </summary>
    public bool TryLoadTokens(string tokenSourceId, bool userScope, string customScope, out PersistedTokenSet tokens) {
      tokens = null;
      string fileName = this.GetFileName(tokenSourceId, userScope, customScope);
      if (!File.Exists(fileName)) {
        return false;
      }
      byte[] encrypted = File.ReadAllBytes(fileName);
      string json;
      if (!this.TryDecrypt(encrypted, out json)) {
        return false;
      }
      tokens = JsonConvert.DeserializeObject<PersistedTokenSet>(json);
      if (tokens == null) {
        return false;
      }
      return true;
    }

    /// <summary>
    /// Saves (replaces) the persisted tokens of a token source.
    /// </summary>
    public void SaveTokens(string tokenSourceId, bool userScope, string customScope, PersistedTokenSet tokens) {
      if (tokens == null) {
        this.DeleteTokens(tokenSourceId, userScope, customScope);
        return;
      }
      string fileName = this.GetFileName(tokenSourceId, userScope, customScope);
      string directory = Path.GetDirectoryName(fileName);
      if (!Directory.Exists(directory)) {
        Directory.CreateDirectory(directory);
      }
      string json = JsonConvert.SerializeObject(tokens);
      File.WriteAllBytes(fileName, this.Encrypt(json));
    }

    /// <summary>
    /// Deletes the persisted tokens of a token source (if existing).
    /// </summary>
    public void DeleteTokens(string tokenSourceId, bool userScope, string customScope) {
      string fileName = this.GetFileName(tokenSourceId, userScope, customScope);
      if (File.Exists(fileName)) {
        File.Delete(fileName);
      }
    }

    /// <summary>
    /// Builds the full file name for a token source.
    /// </summary>
    internal string GetFileName(string tokenSourceId, bool userScope, string customScope) {
      string root;
      if (!string.IsNullOrWhiteSpace(_RootDirectoryOverride)) {
        root = _RootDirectoryOverride;
      }
      else if (userScope) {
        root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
      }
      else {
        root = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
      }
      string directory = Path.Combine(root, SanitizeFileNamePart(_ApplicationName), _SubFolderName);
      if (!string.IsNullOrWhiteSpace(customScope)) {
        directory = Path.Combine(directory, SanitizeFileNamePart(customScope));
      }
      return Path.Combine(directory, SanitizeFileNamePart(tokenSourceId) + ".json");
    }

    /// <summary>
    /// Replaces all characters which are not allowed (or dangerous) within a file or folder name.
    /// </summary>
    private static string SanitizeFileNamePart(string value) {
      if (string.IsNullOrWhiteSpace(value)) {
        return "_";
      }
      StringBuilder sb = new StringBuilder(value.Length);
      char[] invalidChars = Path.GetInvalidFileNameChars();
      foreach (char c in value) {
        if (Array.IndexOf(invalidChars, c) >= 0 || c == '/' || c == '\\' || c == ':') {
          sb.Append('_');
        }
        else {
          sb.Append(c);
        }
      }
      string result = sb.ToString();
      if (result == "." || result == "..") {
        return "_";
      }
      return result;
    }

    /// <summary>
    /// Determines the default application name (name of the entry assembly).
    /// </summary>
    private static string GetDefaultApplicationName() {
      Assembly entryAssembly = Assembly.GetEntryAssembly();
      if (entryAssembly != null) {
        string name = entryAssembly.GetName().Name;
        if (!string.IsNullOrWhiteSpace(name)) {
          return name;
        }
      }
      return "AuthTokenHandling";
    }

    #region " Encryption "

    /// <summary>
    /// Encrypts the given plain text. Layout: salt | iv | cipher | hmac(salt | iv | cipher).
    /// </summary>
    private byte[] Encrypt(string plainText) {
      byte[] salt = new byte[_SaltLength];
      byte[] iv = new byte[_IvLength];
      using (RandomNumberGenerator rng = RandomNumberGenerator.Create()) {
        rng.GetBytes(salt);
        rng.GetBytes(iv);
      }
      byte[] encryptionKey;
      byte[] macKey;
      this.DeriveKeys(salt, out encryptionKey, out macKey);

      byte[] cipher;
      using (Aes aes = Aes.Create()) {
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = encryptionKey;
        aes.IV = iv;
        using (ICryptoTransform encryptor = aes.CreateEncryptor()) {
          byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
          cipher = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
        }
      }

      byte[] result = new byte[_SaltLength + _IvLength + cipher.Length + _MacLength];
      Buffer.BlockCopy(salt, 0, result, 0, _SaltLength);
      Buffer.BlockCopy(iv, 0, result, _SaltLength, _IvLength);
      Buffer.BlockCopy(cipher, 0, result, _SaltLength + _IvLength, cipher.Length);
      byte[] mac;
      using (HMACSHA256 hmac = new HMACSHA256(macKey)) {
        mac = hmac.ComputeHash(result, 0, _SaltLength + _IvLength + cipher.Length);
      }
      Buffer.BlockCopy(mac, 0, result, _SaltLength + _IvLength + cipher.Length, _MacLength);
      return result;
    }

    /// <summary>
    /// Decrypts the given data. Returns false if the data is corrupt or was encrypted with another passphrase.
    /// </summary>
    private bool TryDecrypt(byte[] data, out string plainText) {
      plainText = null;
      if (data == null || data.Length < _SaltLength + _IvLength + _MacLength + 16) {
        return false;
      }
      int cipherLength = data.Length - _SaltLength - _IvLength - _MacLength;
      byte[] salt = new byte[_SaltLength];
      byte[] iv = new byte[_IvLength];
      byte[] cipher = new byte[cipherLength];
      byte[] mac = new byte[_MacLength];
      Buffer.BlockCopy(data, 0, salt, 0, _SaltLength);
      Buffer.BlockCopy(data, _SaltLength, iv, 0, _IvLength);
      Buffer.BlockCopy(data, _SaltLength + _IvLength, cipher, 0, cipherLength);
      Buffer.BlockCopy(data, _SaltLength + _IvLength + cipherLength, mac, 0, _MacLength);

      byte[] encryptionKey;
      byte[] macKey;
      this.DeriveKeys(salt, out encryptionKey, out macKey);

      byte[] expectedMac;
      using (HMACSHA256 hmac = new HMACSHA256(macKey)) {
        expectedMac = hmac.ComputeHash(data, 0, _SaltLength + _IvLength + cipherLength);
      }
      if (!FixedTimeEquals(mac, expectedMac)) {
        return false;
      }

      using (Aes aes = Aes.Create()) {
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = encryptionKey;
        aes.IV = iv;
        using (ICryptoTransform decryptor = aes.CreateDecryptor()) {
          byte[] plainBytes = decryptor.TransformFinalBlock(cipher, 0, cipher.Length);
          plainText = Encoding.UTF8.GetString(plainBytes);
        }
      }
      return true;
    }

    /// <summary>
    /// Derives the AES key and the HMAC key from the passphrase and the salt (PBKDF2-SHA256).
    /// </summary>
    private void DeriveKeys(byte[] salt, out byte[] encryptionKey, out byte[] macKey) {
      byte[] keyMaterial;
#if NET46
      using (Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(_Passphrase, salt, _Pbkdf2Iterations, HashAlgorithmName.SHA256)) {
        keyMaterial = pbkdf2.GetBytes(64);
      }
#else
      keyMaterial = Rfc2898DeriveBytes.Pbkdf2(
        Encoding.UTF8.GetBytes(_Passphrase), salt, _Pbkdf2Iterations, HashAlgorithmName.SHA256, 64
      );
#endif
      encryptionKey = new byte[32];
      macKey = new byte[32];
      Buffer.BlockCopy(keyMaterial, 0, encryptionKey, 0, 32);
      Buffer.BlockCopy(keyMaterial, 32, macKey, 0, 32);
    }

    /// <summary>
    /// Compares two byte arrays in constant time.
    /// </summary>
    private static bool FixedTimeEquals(byte[] a, byte[] b) {
      if (a.Length != b.Length) {
        return false;
      }
      int diff = 0;
      for (int i = 0; i < a.Length; i++) {
        diff |= a[i] ^ b[i];
      }
      return diff == 0;
    }

    #endregion

  }

}
