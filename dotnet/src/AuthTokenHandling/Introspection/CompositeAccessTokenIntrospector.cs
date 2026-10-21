using System;
using System.Collections.Generic;

namespace Security.AccessTokenHandling {

  /// <summary>
  /// Validates a token against the introspectors of SEVERAL token sources (in mapping order).
  /// The token is accepted as soon as ONE of them reports it as active.
  /// </summary>
  /// <remarks>
  /// WHY THIS CLASS EXISTS (deliberate design, not a technical debt):
  /// The 'AccessTokenValidator' selects exactly ONE 'IAccessTokenIntrospector' per call via its
  /// 'IntrospectorLookupMethod'. This single-introspector contract is public and used by existing hosts,
  /// so it must stay unchanged (backward compatibility). When a logical name resolves to several token sources
  /// and the token source cannot be determined 1:1 (for example via a mapped JWT issuer), the AccessTokenManager
  /// returns an instance of this composite, which looks like one introspector to the validator.
  ///
  /// MATCHED SOURCE:
  /// The composite remembers which token source has accepted the token (needed to push the token into the
  /// register of the correct token source). Because one composite instance is shared by concurrent calls,
  /// this information is NOT stored in an instance field, but handed over to the AccessTokenManager
  /// in a thread-static slot, which is read by the validator directly after the (synchronous) introspection.
  ///
  /// TECHNICAL FAILURES:
  /// If no introspector reports the token as active and at least one of them has thrown an exception,
  /// the first exception is rethrown. This makes sure that the validator treats the call as a technical failure
  /// (which is NOT cached) instead of caching a (wrong) inactive outcome.
  /// </remarks>
  internal class CompositeAccessTokenIntrospector : IAccessTokenIntrospector {

    private string[] _TokenSourceIds;
    private IAccessTokenIntrospector[] _Introspectors;

    /// <summary>
    /// Creates the composite.
    /// </summary>
    /// <param name="tokenSourceIds">The token source ids (same order and length as the introspectors).</param>
    /// <param name="introspectors">The introspectors to try (in this order).</param>
    public CompositeAccessTokenIntrospector(string[] tokenSourceIds, IAccessTokenIntrospector[] introspectors) {
      if (tokenSourceIds == null || introspectors == null || tokenSourceIds.Length != introspectors.Length) {
        throw new ArgumentException("The token source ids and the introspectors must have the same length!");
      }
      _TokenSourceIds = tokenSourceIds;
      _Introspectors = introspectors;
    }

    /// <summary>
    /// The token source ids which are covered by this composite (in evaluation order).
    /// </summary>
    public string[] TokenSourceIds {
      get {
        return _TokenSourceIds;
      }
    }

    /// <summary>
    /// Tries all introspectors in order and returns the result of the first one which reports the token as active.
    /// </summary>
    public void IntrospectAccessToken(string rawToken, out bool isActive, out Dictionary<string, object> claims) {

      isActive = false;
      claims = null;
      Exception firstException = null;

      for (int i = 0; i < _Introspectors.Length; i++) {
        bool currentIsActive;
        Dictionary<string, object> currentClaims;
        try {
          _Introspectors[i].IntrospectAccessToken(rawToken, out currentIsActive, out currentClaims);
        }
        catch (Exception ex) {
          if (firstException == null) {
            firstException = ex;
          }
          continue;
        }
        if (currentIsActive) {
          isActive = true;
          claims = currentClaims;
          AccessTokenManager.SetMatchedTokenSourceId(_TokenSourceIds[i]);
          return;
        }
        //keep the claims of the last inactive result (can contain an 'inactive_reason')
        claims = currentClaims;
      }

      AccessTokenManager.SetMatchedTokenSourceId(null);

      if (firstException != null) {
        throw new Exception(
          "At least one of the introspectors of the composite has failed technically (and no other one has accepted the token)!",
          firstException
        );
      }
    }

  }

}
