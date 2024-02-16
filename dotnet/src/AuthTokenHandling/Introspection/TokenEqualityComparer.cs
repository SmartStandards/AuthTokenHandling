using Jose;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace Security.AccessTokenHandling {

  public class TokenEqualityComparer : IAccessTokenIntrospector {

    private Func<string> _RequiredTokenGetter;
    private Func<Dictionary<string, object>> _ClaimGetter;

    public TokenEqualityComparer(string requiredStaticToken, Func<Dictionary<string, object>> claimGetter = null) {
      _RequiredTokenGetter = ()=> requiredStaticToken;
      _ClaimGetter = claimGetter;
    }

    public TokenEqualityComparer(Func<string> requiredTokenGetter, Func<Dictionary<string, object>> claimGetter = null) {
      _RequiredTokenGetter = requiredTokenGetter;
      _ClaimGetter = claimGetter;
    }

    public void IntrospectAccessToken(string rawToken, out bool isActive, out Dictionary<string, object> claims) {
      string requiredToken = _RequiredTokenGetter.Invoke();

      if (requiredToken == null || requiredToken.Equals(rawToken)) {
        isActive = true;
        claims = null;
        if(_ClaimGetter != null) {
          claims = _ClaimGetter.Invoke();
        }
        return;
      }

      isActive = false;
      claims = null;

    }
  }

}
