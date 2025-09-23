using System;

namespace Security.AccessTokenHandling.OAuth.Server {

  internal partial class OAuth2Controller {

    private class StateBag {

      public string SessionId { get; set; }

      public string OriginalRedirectUri { get; set; }
      public string OriginalState { get; set; }
      public string OriginalScope { get; set; }
      public string OriginalResponseType { get; set; }
      public string OriginalClientId { get; set; }

      [Obsolete("Should be refactored to explicit values!")]
      public int ViewMode { get; set; }

    }

  }

}
