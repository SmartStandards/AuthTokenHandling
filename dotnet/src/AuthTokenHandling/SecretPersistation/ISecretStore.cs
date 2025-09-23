using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Security.AccessTokenHandling.SecretPersistation {

  public interface ISecretStore {

    void SaveSecret(string scopeDiscriminator, string key, string secret);

    bool TryLoadSecret(string scopeDiscriminator, string key, out string secret);

  }

}

