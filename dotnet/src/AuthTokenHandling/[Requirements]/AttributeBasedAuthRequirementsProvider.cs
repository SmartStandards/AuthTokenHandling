using System;
using System.Linq;
using System.Reflection;

namespace Security.AccessTokenHandling {

  public class AttributeBasedAuthRequirementsProvider : IAuthRequirementsProvider {

    private string _FallbackTokenSourceIdentifier = null;
    private string[] _RequiredApiPermissionsOnFallback = null;


    /// <summary>
    /// Use this overload for OPT-IN
    /// </summary>
    public AttributeBasedAuthRequirementsProvider() {
    }

    /// <summary>
    /// Use this overload for OPT-OUT
    /// </summary>
    /// <param name="fallbackTokenSourceIdentifier">...if there is no AuthTokenSourceAttribute on the contract</param>
    /// <param name="requiredApiPermissionsOnFallback"></param>
    public AttributeBasedAuthRequirementsProvider(
      string fallbackTokenSourceIdentifier, params string[] requiredApiPermissionsOnFallback
    ) {
      _FallbackTokenSourceIdentifier = fallbackTokenSourceIdentifier;
      if (requiredApiPermissionsOnFallback == null) {
        _RequiredApiPermissionsOnFallback = new string[] { };
      }
      else {
        _RequiredApiPermissionsOnFallback = requiredApiPermissionsOnFallback;
      }
    }

    public bool IsAuthtokenRequired(
      Type contractType,
      MethodInfo method,
      out string tokenSourceIdentifier,
      out string[] explicitelyRequiredApiPermissions
    ) {
      explicitelyRequiredApiPermissions = null;
      if (AuthTokenSourceAttribute.TryPickFrom(contractType, out tokenSourceIdentifier)) {
        if(tokenSourceIdentifier == null) {
          return false;
        }
        if (!RequiredApiPermissionAttribute.TryPickFrom(contractType, out explicitelyRequiredApiPermissions)) {
          explicitelyRequiredApiPermissions = new string[] { };
        }
        return true;
      }
      else if(_FallbackTokenSourceIdentifier != null) {
        tokenSourceIdentifier = _FallbackTokenSourceIdentifier;
        explicitelyRequiredApiPermissions = _RequiredApiPermissionsOnFallback;
        return true;
      }
     else {
        tokenSourceIdentifier = null;
        return false;
      }
    }

  }

}
