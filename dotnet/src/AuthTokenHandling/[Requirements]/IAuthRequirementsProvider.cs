using System;
using System.Linq;
using System.Reflection;

namespace Security.AccessTokenHandling {

  public interface IAuthRequirementsProvider {

    bool IsAuthtokenRequired(
      Type contractType,
      MethodInfo method,
      out string tokenSourceIdentifier,
      out string[] explicitelyRequiredApiPermissions
    );

  }

}
