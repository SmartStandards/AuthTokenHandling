using Jose;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace Security.AccessTokenHandling.CommonVendors {

  public class GithubTokenIntrospector : IAccessTokenIntrospector {

    private string _GithubApiKey;
    private Func<Dictionary<string, object>,IEnumerable<string>> _ScopeGetter;

    public GithubTokenIntrospector(string githubApiKey, Func<Dictionary<string, object>,IEnumerable<string>> scopeGetter = null) {
      _GithubApiKey = githubApiKey;
      _ScopeGetter = scopeGetter;
    }

    public void IntrospectAccessToken(
      string rawToken, out bool isActive, out Dictionary<string, object> claims
    ) {
      claims = new Dictionary<string, object>();
      claims["iss"] = "GITHUB";

      //TODO: evaluate this via call to GITHUB specific api, using the _GithubApiKey
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

