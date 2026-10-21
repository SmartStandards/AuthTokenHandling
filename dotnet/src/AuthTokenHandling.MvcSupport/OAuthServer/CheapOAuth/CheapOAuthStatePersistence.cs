using Logging.SmartStandards;
using Logging.SmartStandards.CopyForAuthTokenHandling;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Security.AccessTokenHandling.OAuth.Server {

  /// <summary>
  /// Persists the state of the Cheap OAuth Server (registered clients, access grants, refresh grants)
  /// into ONE encrypted file, so that logins survive a restart. Each component owns a named section.
  /// The content may contain retained secrets and is therefore ALWAYS encrypted
  /// (AES-256-CBC + HMAC-SHA256, keys derived via PBKDF2-SHA256). Only token hashes are stored - never raw tokens.
  /// </summary>
  public sealed class CheapOAuthStatePersistence {

    private const string _FileName = "cheap-oauth-state.protected";
    private const string _KeyFileName = "cheap-oauth-state.key";
    private const int _SaltLength = 16;
    private const int _IvLength = 16;
    private const int _MacLength = 32;
    private const int _Pbkdf2Iterations = 100000;

    private readonly string _FilePath;
    private readonly byte[] _EncryptionKey;
    private readonly byte[] _MacKey;
    private readonly byte[] _Salt;
    private readonly object _SyncRoot = new object();
    private readonly JObject _Sections;

    /// <summary>
    /// Creates the persistence for the given directory (created if missing) and loads the existing state.
    /// An unreadable state file (e.g. changed passphrase) is ignored - the clients then simply have to log in again.
    /// </summary>
    /// <param name="directory">The directory of the state file.</param>
    /// <param name="passphrase">
    /// null: a random key is generated once and stored in a key file within the same directory.
    /// </param>
    public CheapOAuthStatePersistence(string directory, string passphrase) {
      if (string.IsNullOrWhiteSpace(directory)) {
        throw new ArgumentException("The directory must not be empty.", nameof(directory));
      }
      string fullDirectory = Path.GetFullPath(directory);
      Directory.CreateDirectory(fullDirectory);
      _FilePath = Path.Combine(fullDirectory, _FileName);

      byte[] secret;
      if (string.IsNullOrEmpty(passphrase)) {
        secret = LoadOrCreateKeyFile(Path.Combine(fullDirectory, _KeyFileName));
      }
      else {
        secret = Encoding.UTF8.GetBytes(passphrase);
      }

      // one fixed salt per state file location (keys are derived once - PBKDF2 is expensive)
      _Salt = SHA256.HashData(Encoding.UTF8.GetBytes("CheapOAuthState|" + _FilePath.ToLowerInvariant()));
      Array.Resize(ref _Salt, _SaltLength);
      byte[] keyMaterial = Rfc2898DeriveBytes.Pbkdf2(secret, _Salt, _Pbkdf2Iterations, HashAlgorithmName.SHA256, 64);
      _EncryptionKey = new byte[32];
      _MacKey = new byte[32];
      Buffer.BlockCopy(keyMaterial, 0, _EncryptionKey, 0, 32);
      Buffer.BlockCopy(keyMaterial, 32, _MacKey, 0, 32);

      _Sections = this.ReadFile();
    }

    /// <summary>
    /// The full path of the (encrypted) state file.
    /// </summary>
    public string FilePath {
      get {
        return _FilePath;
      }
    }

    /// <summary>
    /// Returns a copy of the stored section content or null if there is none.
    /// </summary>
    public JToken Load(string sectionName) {
      lock (_SyncRoot) {
        JToken section = _Sections[sectionName];
        if (section == null) {
          return null;
        }
        return section.DeepClone();
      }
    }

    /// <summary>
    /// Replaces the section with the content created by 'createContent' and writes the file.
    /// 'createContent' is invoked INSIDE the lock, so concurrent snapshots can never overwrite newer ones.
    /// </summary>
    public void Save(string sectionName, Func<JToken> createContent) {
      lock (_SyncRoot) {
        _Sections[sectionName] = createContent.Invoke();
        this.WriteFile();
      }
    }

    private static byte[] LoadOrCreateKeyFile(string keyFilePath) {
      if (File.Exists(keyFilePath)) {
        byte[] existing = File.ReadAllBytes(keyFilePath);
        if (existing.Length >= 32) {
          return existing;
        }
      }
      byte[] key = RandomNumberGenerator.GetBytes(32);
      File.WriteAllBytes(keyFilePath, key);
      return key;
    }

    private JObject ReadFile() {
      if (!File.Exists(_FilePath)) {
        return new JObject();
      }
      try {
        byte[] data = File.ReadAllBytes(_FilePath);
        string json;
        if (!this.TryDecrypt(data, out json)) {
          return new JObject();
        }
        return JObject.Parse(json);
      }
      catch (CryptographicException ex) {
        DevLogger.LogError(ex);
        return new JObject();
      }
      catch (JsonException ex) {
        DevLogger.LogError(ex);
        return new JObject();
      }
    }

    private void WriteFile() {
      string json = _Sections.ToString(Formatting.None);
      byte[] data = this.Encrypt(json);
      string tempFilePath = _FilePath + ".tmp";
      File.WriteAllBytes(tempFilePath, data);
      File.Move(tempFilePath, _FilePath, true);
    }

    /// <summary>
    /// Layout: iv | cipher | hmac(iv | cipher).
    /// </summary>
    private byte[] Encrypt(string plainText) {
      byte[] iv = RandomNumberGenerator.GetBytes(_IvLength);
      byte[] cipher;
      using (Aes aes = Aes.Create()) {
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = _EncryptionKey;
        aes.IV = iv;
        using (ICryptoTransform encryptor = aes.CreateEncryptor()) {
          byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
          cipher = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
        }
      }
      byte[] result = new byte[_IvLength + cipher.Length + _MacLength];
      Buffer.BlockCopy(iv, 0, result, 0, _IvLength);
      Buffer.BlockCopy(cipher, 0, result, _IvLength, cipher.Length);
      byte[] mac;
      using (HMACSHA256 hmac = new HMACSHA256(_MacKey)) {
        mac = hmac.ComputeHash(result, 0, _IvLength + cipher.Length);
      }
      Buffer.BlockCopy(mac, 0, result, _IvLength + cipher.Length, _MacLength);
      return result;
    }

    private bool TryDecrypt(byte[] data, out string plainText) {
      plainText = null;
      if (data == null || data.Length < _IvLength + _MacLength + 16) {
        return false;
      }
      int cipherLength = data.Length - _IvLength - _MacLength;
      byte[] mac = new byte[_MacLength];
      Buffer.BlockCopy(data, _IvLength + cipherLength, mac, 0, _MacLength);
      byte[] expectedMac;
      using (HMACSHA256 hmac = new HMACSHA256(_MacKey)) {
        expectedMac = hmac.ComputeHash(data, 0, _IvLength + cipherLength);
      }
      if (!CryptographicOperations.FixedTimeEquals(mac, expectedMac)) {
        return false;
      }
      byte[] iv = new byte[_IvLength];
      Buffer.BlockCopy(data, 0, iv, 0, _IvLength);
      using (Aes aes = Aes.Create()) {
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = _EncryptionKey;
        aes.IV = iv;
        using (ICryptoTransform decryptor = aes.CreateDecryptor()) {
          byte[] plainBytes = decryptor.TransformFinalBlock(data, _IvLength, cipherLength);
          plainText = Encoding.UTF8.GetString(plainBytes);
        }
      }
      return true;
    }

    #region " Serialization Helpers "

    /// <summary>
    /// Converts a UTC timestamp into unix milliseconds.
    /// </summary>
    public static long ToUnixMilliseconds(DateTime utcValue) {
      DateTime utc = DateTime.SpecifyKind(utcValue, DateTimeKind.Utc);
      return new DateTimeOffset(utc).ToUnixTimeMilliseconds();
    }

    /// <summary>
    /// Converts unix milliseconds back into a UTC timestamp.
    /// </summary>
    public static DateTime FromUnixMilliseconds(JToken value) {
      return DateTimeOffset.FromUnixTimeMilliseconds(value.Value<long>()).UtcDateTime;
    }

    /// <summary>
    /// Converts a string array into a JSON array (null becomes an empty array).
    /// </summary>
    public static JArray ToJArray(string[] values) {
      JArray array = new JArray();
      if (values != null) {
        foreach (string value in values) {
          array.Add(value);
        }
      }
      return array;
    }

    /// <summary>
    /// Converts a JSON array into a string array (null becomes an empty array).
    /// </summary>
    public static string[] ToStringArray(JToken token) {
      List<string> values = new List<string>();
      JArray array = token as JArray;
      if (array != null) {
        foreach (JToken item in array) {
          values.Add(item.ToString());
        }
      }
      return values.ToArray();
    }

    #endregion

  }

}
