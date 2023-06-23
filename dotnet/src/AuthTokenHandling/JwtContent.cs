using System;
using System.Collections.Generic;

namespace Security.AccessTokenHandling {

  public class JwtContent {

    /// <summary> issuer </summary>
    public String iss { get; set; } = string.Empty;

    /// <summary> subject </summary>
    public String sub { get; set; } = string.Empty;

    /// <summary> expires (unix-epoch utc) </summary>
    public long exp { get; set; } = 0;

    /*
    /// <summary> audience </summary>
    public String aud { get; set; } = string.Empty;
    */

    /// <summary> OAUTH Scope(s) in long name </summary>
    public object scope { get; set; } = string.Empty;

  }

}
