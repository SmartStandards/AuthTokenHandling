using Security.AccessTokenHandling.OAuth;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
using System.Security.Claims;

namespace Security.AccessTokenHandling {

  public class ClaimApprovalContext {

    [DebuggerBrowsable(DebuggerBrowsableState.Never)]
    private Dictionary<string, object> _RequestedClaims;

    [DebuggerBrowsable(DebuggerBrowsableState.Never)]
    private Dictionary<string, object> _ClaimsToUse = new Dictionary<string, object>();

    public ClaimApprovalContext(
       Dictionary<string, object> requestedClaims
    ) {
      _RequestedClaims = requestedClaims;
    }

    public KeyValuePair<string, object>[] RequestedClaims { get { return _RequestedClaims.ToArray(); } }

    public Dictionary<string, object> ClaimsToUse { get { return _ClaimsToUse; } }


    /// <summary>
    /// Warning: this will override already present values (from previous 'SetValueToUse' operations) within 'ClaimsToUse'!
    /// </summary>
    /// <returns></returns>
    public int TakeOverAllRequestedClaims(bool overwriteExisiting = true) {
      int count = 0;
      foreach (var claim in _RequestedClaims) {
        if (overwriteExisiting || !_ClaimsToUse.ContainsKey(claim.Key)) {
          _ClaimsToUse[claim.Key] = claim.Value;
        }
        count++;
      }
      return count;
    }

    /// <summary>
    /// Warning: this will override already present values (from previous 'SetValueToUse' operations) within 'ClaimsToUse'!
    /// </summary>
    /// <param name="includedClaimNames"></param>
    /// <returns></returns>
    public int TakeOverRequestedClaims(params string[] includedClaimNames) {
      int count = 0;
      foreach (var claim in _RequestedClaims) {
        if (includedClaimNames.Contains(claim.Key)) {
          _ClaimsToUse[claim.Key] = claim.Value;
          count++;
        }
      }
      return count;
    }

    /// <summary>
    /// Warning: this will override already present values (from previous 'SetValueToUse' operations) within 'ClaimsToUse'!
    /// </summary>
    /// <param name="excludedClaimNames"></param>
    public int TakeOverAllRequestedClaimsExcept(params string[] excludedClaimNames) {
      int count = 0;
      foreach (var claim in _RequestedClaims) {
        if (!excludedClaimNames.Contains(claim.Key)) {
          _ClaimsToUse[claim.Key] = claim.Value;
          count++;
        }
      }
      return count;
    }

    /// <summary>
    /// Warning: this will override already present values (from previous 'SetValueToUse' operations) within 'ClaimsToUse'!
    /// </summary>
    /// <param name="requestedClaimName"></param>
    /// <param name="newClaimNameToUse"></param>
    /// <param name="allowNull"></param>
    /// <returns></returns>
    public bool TryMapRequestedClaim(string requestedClaimName, string newClaimNameToUse, bool allowNull = false) {
      foreach (var claim in _RequestedClaims) {
        if (claim.Key == requestedClaimName) {
          if (claim.Value != null || allowNull) {
            _ClaimsToUse[newClaimNameToUse] = claim.Value;
            return true;
          }
          else {
            break;
          }
        }
      }
      return false;
    }

    /// <summary>
    /// Warning: this will override already present values (from previous 'SetValueToUse' operations) within 'ClaimsToUse'!
    /// </summary>
    /// <param name="requestedClaimName"></param>
    /// <param name="newClaimNameToUse"></param>
    /// <param name="valueMapper"></param>
    /// <returns></returns>
    public bool TryMapRequestedClaim(string requestedClaimName, string newClaimNameToUse, Func<object,object> valueMapper) {
      foreach (var claim in _RequestedClaims) {
        if (claim.Key == requestedClaimName) {
          if (valueMapper != null) {
            _ClaimsToUse[newClaimNameToUse] = valueMapper.Invoke(claim.Value);
          }
          else {
            _ClaimsToUse[newClaimNameToUse] = claim.Value;
          }
          return true;
        }
      }
      return false;
    }

    /// <summary>
    /// Warning: this will override already present values (from previous 'TakeOver' operations) within 'ClaimsToUse'!
    /// </summary>
    /// <param name="claimName"></param>
    /// <param name="valueToUse"></param>
    public void SetValueToUse(string claimName, object valueToUse) {
      _ClaimsToUse[claimName] = valueToUse;
    }

    /// <summary>
    /// Very useful for hard deny at the end of cascaded hooks (where some claims might have been added already)
    /// </summary>
    /// <param name="forbiddenClaimNames"></param>
    public void RemoveFromClaimsToUseIfPresent(params string[] forbiddenClaimNames) {
      foreach (string claimName in forbiddenClaimNames) {
        _ClaimsToUse.Remove(claimName);
      }
    }

    /// <summary>
    /// Special convenience for handling the 'scope' claim (which is a space-separaed string)
    /// </summary>
    /// <param name="scopesExpressions"></param>
    public void RemoveFromScopeIfPresent(params string[] scopesExpressions) {
      if (_ClaimsToUse.TryGetValue("scope", out object rawScopeObj) & rawScopeObj != null) {
        List<string> scopes = rawScopeObj.ToString().Split(' ').ToList();
        scopes.RemoveAll((s) => (s == string.Empty || scopesExpressions.Contains(s)));
        _ClaimsToUse["scope"] = string.Join(" ", scopes);
      }
    }

    /// <summary>
    /// Special convenience for handling the 'scope' claim (which is a space-separaed string)
    /// </summary>
    public void AppendToScopeIfNotPresent(params string[] scopeExpressions) {
      if (_ClaimsToUse.TryGetValue("scope", out object rawScopeObj) & rawScopeObj != null) {
        List<string> scopes = rawScopeObj.ToString().Split(' ').ToList();
        scopes.RemoveAll((s) => (s == string.Empty));
        foreach (string scopeToAdd in scopeExpressions) {
          if (!scopes.Contains(scopeToAdd)) {
            scopes.Add(scopeToAdd);
          }
        }
        _ClaimsToUse["scope"] = string.Join(" ", scopes);
      }
    }

    public bool RequestedClaimsContainsScopeExpression(string scopeExpression) {
      foreach (var claim in _RequestedClaims) {
        if (claim.Key == "scope" && claim.Value != null) {
          var scopes = claim.Value.ToString().Split(' ');
          if (scopes.Contains(scopeExpression)) {
            return true;
          }
        }
      }
      return false;
    }

    public bool TryGetRequestedScopeExpressionsAsArray(out string[] scopeExpressions) {
      foreach (var claim in _RequestedClaims) {
        if (claim.Key == "scope" ) {
          string scopeClaim = (claim.Value as string);
          if (!string.IsNullOrWhiteSpace(scopeClaim)) {
            scopeExpressions = scopeClaim.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
          }
          else {
            scopeExpressions = Array.Empty<string>();
          }
          return true;
        }
      }
      scopeExpressions = null;
      return false;
    }

    public bool TryGetScopeExpressionsToUseAsArray(out string[] scopeExpressions) {
      foreach (var claim in _RequestedClaims) {
        if (claim.Key == "scope") {
          string scopeClaim = (claim.Value as string);
          if (!string.IsNullOrWhiteSpace(scopeClaim)) {
            scopeExpressions = scopeClaim.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
          }
          else {
            scopeExpressions = Array.Empty<string>();
          }
          return true;
        }
      }
      scopeExpressions = null;
      return false;
    }

    /// <summary>
    /// Creates a new ClaimApprovalContext, passes it to the given customizing-hooks (aka. visitor(s)),
    /// and returns the resulting 'ClaimsToUse' dictionary.
    /// </summary>
    /// <param name="requestedClaims"></param>
    /// <param name="visitors"> set of hooks to be invoked (robust against null-handles)</param>
    /// <returns></returns>
    internal static Dictionary<string, object> ProcessRequestedClaims(
      Dictionary<string, object> requestedClaims, params Action<ClaimApprovalContext>[] visitors
    ) {

      ClaimApprovalContext context = new ClaimApprovalContext(requestedClaims ?? new Dictionary<string, object>());

      foreach (var visitor in visitors) {
        if(visitor != null) {
          visitor.Invoke(context);
        }
      }
      return context.ClaimsToUse;
    }

  }

}
