using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Security.AccessTokenHandling.SecretPersistation {

  public sealed class UserRegistrySecretStore : ISecretStore {

    private const string _DefaultBaseRegistryPath = @"Software\SmartStandards\ATH";

    /// <summary>
    /// Master key string used to derive the 3DES key.
    /// </summary>
    private readonly string _MasterKeyString;

    /// <summary>
    /// Base registry path under HKCU where secrets are stored.
    /// </summary>
    private readonly string _BaseRegistryPath;

    /// <summary>
    /// Initializes a new instance with the default base path.
    /// </summary>
    /// <param name="masterKeyString">Passphrase used to derive the 24-byte 3DES key.</param>
    public UserRegistrySecretStore(string masterKeyString)
     : this(masterKeyString, _DefaultBaseRegistryPath) {
    }

    /// <summary>
    /// Initializes a new instance with a required master passphrase and optional base path.
    /// </summary>
    /// <param name="masterKeyString">Passphrase used to derive the 24-byte 3DES key.</param>
    /// <param name="baseRegistryPath">Optional base registry path; defaults to _DefaultBaseRegistryPath.</param>
    public UserRegistrySecretStore(string masterKeyString, string baseRegistryPath) {

      if (masterKeyString == null) {
        throw new ArgumentNullException("masterKeyString", "Master key must not be null.");
      }
      if (masterKeyString.Length == 0) {
        throw new ArgumentException("Master key must not be empty.", "masterKeyString");
      }

      _MasterKeyString = masterKeyString;
      if (string.IsNullOrEmpty(baseRegistryPath)) {
        _BaseRegistryPath = _DefaultBaseRegistryPath;
      }
      else {
        _BaseRegistryPath = baseRegistryPath;
      }
    }

    /// <summary>
    /// Encrypts and stores a secret at HKCU\[BasePath]\[Scope] with value name [Key].
    /// </summary>
    /// <param name="scopeDiscriminator">Scope/tenant/app discriminator.</param>
    /// <param name="key">Logical key.</param>
    /// <param name="secret">Plaintext secret.</param>
    public void SaveSecret(string scopeDiscriminator, string key, string secret) {

      if (scopeDiscriminator == null) {
        throw new ArgumentNullException("scopeDiscriminator", "Scope must not be null.");
      }
      if (scopeDiscriminator.Length == 0) {
        throw new ArgumentException("Scope must not be empty.", "scopeDiscriminator");
      }
      if (key == null) {
        throw new ArgumentNullException("key", "Key must not be null.");
      }
      if (key.Length == 0) {
        throw new ArgumentException("Key must not be empty.", "key");
      }
      if (secret == null) {
        throw new ArgumentNullException("secret", "Secret must not be null.");
      }

      string cipherBase64;
      string ivBase64;
      this.EncryptToBase64(secret, _MasterKeyString, out cipherBase64, out ivBase64);

      string stored = ivBase64 + ":" + cipherBase64;

      string subPath = ComposeScopePath(scopeDiscriminator);
      using (RegistryKey subKey = Registry.CurrentUser.CreateSubKey(subPath)) {
        if (subKey == null) {
          throw new InvalidOperationException("Failed to open or create the registry subkey.");
        }
        subKey.SetValue(key, stored, RegistryValueKind.String);
      }

    }

    /// <summary>
    /// Attempts to read and decrypt the secret from HKCU.
    /// </summary>
    /// <param name="scopeDiscriminator">Scope/tenant/app discriminator.</param>
    /// <param name="key">Logical key.</param>
    /// <param name="secret">Output: decrypted plaintext.</param>
    /// <returns>True on success; false if not found or decryption fails.</returns>
    public bool TryLoadSecret(string scopeDiscriminator, string key, out string secret) {

      secret = string.Empty;

      if (scopeDiscriminator == null) {
        return false;
      }
      if (scopeDiscriminator.Length == 0) {
        return false;
      }
      if (key == null) {
        return false;
      }
      if (key.Length == 0) {
        return false;
      }

      try {
        string subPath = ComposeScopePath(scopeDiscriminator);
        using (RegistryKey subKey = Registry.CurrentUser.OpenSubKey(subPath, false)) {
          if (subKey == null) {
            return false;
          }

          object value = subKey.GetValue(key);
          if (value == null) {
            return false;
          }

          string stored = value as string;
          if (stored == null) {
            return false;
          }

          int sepIndex = stored.IndexOf(':');
          if (sepIndex <= 0) {
            return false;
          }

          string ivBase64 = stored.Substring(0, sepIndex);
          string cipherBase64 = stored.Substring(sepIndex + 1);

          string plain = DecryptFromBase64(cipherBase64, ivBase64, _MasterKeyString);
          if (plain == null) {
            return false;
          }

          secret = plain;
          return true;
        }
      }
      catch (Exception ex) {
        return false;
      }
    }

    /// <summary>
    /// Composes a registry subkey path for a given scope.
    /// </summary>
    /// <param name="scopeDiscriminator">Scope discriminator.</param>
    /// <returns>Combined registry subkey path under HKCU.</returns>
    private string ComposeScopePath(string scopeDiscriminator) {
      return _BaseRegistryPath + "\\" + SanitizeScope(scopeDiscriminator);
    }

    /// <summary>
    /// Sanitizes scope name to be a safe registry subkey name (simple approach).
    /// </summary>
    /// <param name="scopeDiscriminator">Raw scope.</param>
    /// <returns>Sanitized scope.</returns>
    private string SanitizeScope(string scopeDiscriminator) {
      // Replace potentially problematic characters with underscores.
      string result = scopeDiscriminator.Replace("/", "_").Replace("\\", "_").Replace(":", "_").Replace("*", "_").Replace("?", "_").Replace("\"", "_").Replace("<", "_").Replace(">", "_").Replace("|", "_");
      return result;
    }

    /// <summary>
    /// Encrypts plaintext to Base64 using 3DES CBC/PKCS7; derives a 24-byte key from SHA-256(masterKeyString).
    /// Generates a random 8-byte IV which is returned as Base64 alongside the ciphertext.
    /// </summary>
    /// <param name="plainText">Plaintext to encrypt.</param>
    /// <param name="masterKeyString">Passphrase used for key derivation.</param>
    /// <param name="cipherBase64">Output: Base64 ciphertext.</param>
    /// <param name="ivBase64">Output: Base64 IV.</param>
    private void EncryptToBase64(string plainText, string masterKeyString, out string cipherBase64, out string ivBase64) {
      cipherBase64 = string.Empty;
      ivBase64 = string.Empty;

      byte[] key;
      Derive3DesKey(masterKeyString, out key);

      byte[] iv = new byte[8];
      FillRandom(iv);

      byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
      byte[] cipherBytes;

      using (TripleDES tdes = TripleDES.Create()) {
        tdes.Mode = CipherMode.CBC;
        tdes.Padding = PaddingMode.PKCS7;
        tdes.Key = key;
        tdes.IV = iv;

        using (ICryptoTransform enc = tdes.CreateEncryptor()) {
          using (MemoryStream ms = new MemoryStream()) {
            using (CryptoStream cs = new CryptoStream(ms, enc, CryptoStreamMode.Write)) {
              cs.Write(plainBytes, 0, plainBytes.Length);
              cs.FlushFinalBlock();
              cipherBytes = ms.ToArray();
            }
          }
        }
      }

      cipherBase64 = Convert.ToBase64String(cipherBytes);
      ivBase64 = Convert.ToBase64String(iv);
    }

    /// <summary>
    /// Decrypts Base64 ciphertext using 3DES CBC/PKCS7 with the provided Base64 IV and passphrase.
    /// Returns null on failure to allow TryLoad pattern.
    /// </summary>
    /// <param name="cipherBase64">Ciphertext in Base64.</param>
    /// <param name="ivBase64">IV in Base64.</param>
    /// <param name="masterKeyString">Passphrase used for key derivation.</param>
    /// <returns>Decrypted plaintext or null if decryption fails.</returns>
    private string DecryptFromBase64(string cipherBase64, string ivBase64, string masterKeyString) {
      try {
        byte[] key;
        Derive3DesKey(masterKeyString, out key);

        byte[] iv = Convert.FromBase64String(ivBase64);
        byte[] cipher = Convert.FromBase64String(cipherBase64);

        byte[] plainBytes;

        using (TripleDES tdes = TripleDES.Create()) {
          tdes.Mode = CipherMode.CBC;
          tdes.Padding = PaddingMode.PKCS7;
          tdes.Key = key;
          tdes.IV = iv;

          using (ICryptoTransform dec = tdes.CreateDecryptor()) {
            using (MemoryStream ms = new MemoryStream(cipher)) {
              using (CryptoStream cs = new CryptoStream(ms, dec, CryptoStreamMode.Read)) {
                using (MemoryStream outMs = new MemoryStream()) {
                  byte[] buffer = new byte[4096];
                  int read = 0;
                  while (true) {
                    read = cs.Read(buffer, 0, buffer.Length);
                    if (read <= 0) {
                      break;
                    }
                    outMs.Write(buffer, 0, read);
                  }
                  plainBytes = outMs.ToArray();
                }
              }
            }
          }
        }

        string plain = Encoding.UTF8.GetString(plainBytes);
        return plain;
      }
      catch (Exception ex) {
        return null;
      }
    }

    /// <summary>
    /// Derives a 24-byte 3DES key from SHA-256(masterKeyString).
    /// </summary>
    /// <param name="masterKeyString">Passphrase.</param>
    /// <param name="key">Output: 24-byte key.</param>
    private void Derive3DesKey(string masterKeyString, out byte[] key) {
      byte[] material = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(masterKeyString));
      key = new byte[24];
      Buffer.BlockCopy(material, 0, key, 0, 24);
    }

    /// <summary>
    /// Fills a byte array with cryptographically strong random bytes.
    /// </summary>
    /// <param name="buffer">Buffer to fill.</param>
    private void FillRandom(byte[] buffer) {
      using (RandomNumberGenerator rng = RandomNumberGenerator.Create()) {
        rng.GetBytes(buffer);
      }
    }

  }

}
