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

      //https://stackoverflow.com/questions/359472/how-can-i-verify-a-google-authentication-api-access-token
      //https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=accessToken

      //https://oauth2.googleapis.com/tokeninfo?id_token=XYZ123
      /*
       *  {
         // These six fields are included in all Google ID Tokens.
         "iss": "https://accounts.google.com",
         "sub": "110169484474386276334",
         "azp": "1008719970978-hb24n2dstb40o45d4feuo2ukqmcc6381.apps.googleusercontent.com",
         "aud": "1008719970978-hb24n2dstb40o45d4feuo2ukqmcc6381.apps.googleusercontent.com",
         "iat": "1433978353",
         "exp": "1433981953",

         // These seven fields are only included when the user has granted the "profile" and
         // "email" OAuth scopes to the application.
         "email": "testuser@gmail.com",
         "email_verified": "true",
         "name" : "Test User",
         "picture": "https://lh4.googleusercontent.com/-kYgzyAWpZzJ/ABCDEFGHI/AAAJKLMNOP/tIXL9Ir44LE/s99-c/photo.jpg",
         "given_name": "Test",
         "family_name": "User",
         "locale": "en"
        }
       */




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
