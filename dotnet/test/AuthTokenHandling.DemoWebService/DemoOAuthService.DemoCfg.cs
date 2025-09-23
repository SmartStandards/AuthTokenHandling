
using System.Text;

namespace Security.AccessTokenHandling.OAuth.Server {

  public partial class DemoOAuthService {

    internal static readonly string _OurDemoOAuthClientId = "11aa22bb33cc";

    internal static readonly string _OurDemoOAuthClientSecret = "wow!";

    internal static readonly byte[] _OutTotallySecretDemoJwtKey = Encoding.ASCII.GetBytes("TheBigAndMightyFoo");

  }

}
