using System;
using System.Linq;
using System.Reflection;

namespace Security.AccessTokenHandling {

  /// <summary>
  ///  Defines, which ApiPermission should be required (to be present for a used auth token)
  ///  when calling a service endpoint which is compliant to this contract.
  ///  Usually a api permission named 'Foo' should be present within the "scope"-claim (inside of a JWT)
  ///  in the form "API:Foo"
  /// </summary>
  [AttributeUsage(validOn: AttributeTargets.Interface | AttributeTargets.Class, AllowMultiple = false, Inherited = true)]
  public class RequiredApiPermissionAttribute : Attribute {

    /// <summary>
    ///  Defines, which ApiPermission should be required (to be present for a used auth token)
    ///  when calling a service endpoint which is compliant to this contract.
    ///  Usually a api permission named 'Foo' should be present within the "scope"-claim (inside of a JWT)
    ///  in the form "API:Foo"
    /// </summary>
    /// <param name="apiPermissionNames">Multiple entries are AND-related, which means that ALL of them must be present!</param>
    public RequiredApiPermissionAttribute(params string[] apiPermissionNames) {
      _ApiPermissionNames = apiPermissionNames;
    }

    private string[] _ApiPermissionNames;

    public string[] ApiPermissionNames {
      get {
        return _ApiPermissionNames;
      } 
    }

    public static bool TryPickFrom(Type t, out string[] apiPermissionNames) {
      var attrib = t.GetCustomAttributes<RequiredApiPermissionAttribute>(true).SingleOrDefault();
      if (attrib == null) {
        apiPermissionNames = null;
        return false;
      }
      apiPermissionNames = attrib.ApiPermissionNames;
      return true;
    }

  }

}
