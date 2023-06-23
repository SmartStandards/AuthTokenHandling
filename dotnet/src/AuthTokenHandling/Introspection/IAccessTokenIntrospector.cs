using System;
using System.Collections.Generic;

namespace Security.AccessTokenHandling {

  public interface IAccessTokenIntrospector {

    void IntrospectAccessToken(
      string rawToken,
      out Boolean isActive,
      out Dictionary<String, object> claims
    );

  }

}
