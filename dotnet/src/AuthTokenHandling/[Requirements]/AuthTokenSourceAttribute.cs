using System;
using System.Linq;
using System.Reflection;

namespace Security.AccessTokenHandling {

  /// <summary>
  ///  Defines, which 'TokenSource' (some kind of profile) should be used to retrieve or validate the auth tokens
  /// </summary>
  [AttributeUsage(validOn: AttributeTargets.Interface | AttributeTargets.Class, AllowMultiple = false, Inherited = true)]
  public class AuthTokenSourceAttribute : Attribute {

    /// <summary>
    ///  Defines, which 'TokenSource' (some kind of profile) should be used to retrieve or validate the auth tokens
    /// </summary>
    /// <param name="tokenSourceIdentifier">can be NULL to opt-out default authentication!</param>
    public AuthTokenSourceAttribute(string tokenSourceIdentifier) {
      _TokenSourceIdentifier = tokenSourceIdentifier;
    }

    private string _TokenSourceIdentifier;

    public string TokenSourceIdentifier {
      get {
        return _TokenSourceIdentifier;
      } 
    }

    public static bool TryPickFrom(Type t, out string tokenSourceIdentifier) {
      var attrib = t.GetCustomAttributes<AuthTokenSourceAttribute>(true).SingleOrDefault();
      if (attrib == null) {
        tokenSourceIdentifier = null;
        return false;
      }
      tokenSourceIdentifier = attrib.TokenSourceIdentifier;
      return true;
    }

  }

}
