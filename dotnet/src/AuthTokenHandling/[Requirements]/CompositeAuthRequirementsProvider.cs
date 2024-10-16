using System;
using System.Diagnostics;
using System.Linq;
using System.Reflection;

namespace Security.AccessTokenHandling {

  [DebuggerDisplay("CompositeAuthRequirementsProvider ({_Providers.Length} providers)")]
  public class CompositeAuthRequirementsProvider : IAuthRequirementsProvider {

    [DebuggerBrowsable(DebuggerBrowsableState.RootHidden)]
    private IAuthRequirementsProvider[] _Providers;

    /// <summary></summary>
    /// <param name="providers">oredered by priority (first winns)</param>
    public CompositeAuthRequirementsProvider(params IAuthRequirementsProvider[] providers) {
      if(providers != null) {
        _Providers = providers;
      }
      else {
        _Providers = new IAuthRequirementsProvider[] { };
      }
    }

    public void ClearProviders() {
      _Providers = new IAuthRequirementsProvider[] { };
    }

    public void AddProvider(IAuthRequirementsProvider provider) {
      _Providers = _Providers.Union(new IAuthRequirementsProvider[] { provider }).ToArray();
    }

    public bool IsAuthtokenRequired(
        Type contractType,
        MethodInfo method,
        out string tokenSourceIdentifier,
        out string[] explicitelyRequiredApiPermissions
     ) {

      foreach ( IAuthRequirementsProvider provider in _Providers ) {
        if (provider.IsAuthtokenRequired(contractType, method, out tokenSourceIdentifier, out explicitelyRequiredApiPermissions)) {
          return true;
        }
      }

      tokenSourceIdentifier = null;
      explicitelyRequiredApiPermissions = null;
      return false;

    }

  }

}
