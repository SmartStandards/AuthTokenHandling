using Jose;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace Security.AccessTokenHandling.CommonVendors {

  public class GoogleTokenIntrospector : IAccessTokenIntrospector {

    private string _GoogleApiKey;
    private Func<Dictionary<string, object>,IEnumerable<string>> _ScopeGetter;

    public GoogleTokenIntrospector(string googleApiKey, Func<Dictionary<string, object>, IEnumerable<string>> scopeGetter = null) {
      _GoogleApiKey = googleApiKey;
      _ScopeGetter = scopeGetter;
    }

    public void IntrospectAccessToken(
      string rawToken, out bool isActive, out Dictionary<string, object> claims
    ) {
      claims = new Dictionary<string, object>();
      claims["iss"] = "GOOGLE";

      //TODO: evaluate this via call to GOOGLE specific api, using the _GoogleApiKey
      claims["sub"] = "";
      isActive = false;

      if (_ScopeGetter != null) {
        var scopes = _ScopeGetter.Invoke(claims);
        claims["scope"] = string.Join(" ", scopes);
      }
 
      throw new NotImplementedException();

    }

  }

}
