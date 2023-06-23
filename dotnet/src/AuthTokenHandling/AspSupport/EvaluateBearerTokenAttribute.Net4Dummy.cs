#if NET46

using System;

namespace Security.AccessTokenHandling {

  /// <summary>
  /// The EvaluateBearerTokenAttribute is only available for ASP.NET Core (>=.NET 5)!
  /// </summary>
  [Obsolete("The EvaluateBearerTokenAttribute is only available for ASP.NET Core (>=.NET 5)!", true)]
  [AttributeUsage(validOn: AttributeTargets.Method)]
  public class EvaluateBearerTokenAttribute : Attribute {
  }

}

#endif