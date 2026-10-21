#if !NET46

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Security.AccessTokenHandling.OAuth.Server;

namespace Security.AccessTokenHandling {

	/// <summary>
	/// RFC 8414 authorization server metadata of the 'OAuth2Controller'. The endpoint URLs are built here
	/// (from the routes of the 'OAuth2Controller'), the capabilities are delegated to 'IOAuthService'.
	/// Registered together with the 'OAuth2Controller' (see 'AddOAuthServerController').
	/// </summary>
	[ApiController]
	[ApiExplorerSettings(GroupName = ".well-known")]
	internal sealed class WellKnownOAuthDiscoverController : ControllerBase {

		private readonly IOAuthService _AuthService;

		public WellKnownOAuthDiscoverController(IOAuthService authService) {
			_AuthService = authService;
		}

		/// <summary>
		/// RFC 8414 authorization server metadata (the issuer is the base url of the request).
		/// Also published as 'openid-configuration', because some clients only probe this path.
		/// </summary>
		[HttpGet]
		[AllowAnonymous]
		[Route(".well-known/oauth-authorization-server")]
		[Route(".well-known/openid-configuration")]
		public ContentResult GetAuthorizationServerMetadata() {

			AuthorizationServerCapabilities capabilities = _AuthService.GetAuthorizationServerCapabilities();
			if (capabilities == null) {
				capabilities = new AuthorizationServerCapabilities();
			}

			string issuer = GetRequestBaseUrl(this.Request);
			JObject document = new JObject();
			document["issuer"] = issuer;
			document["authorization_endpoint"] = issuer + "/oauth2/authorize";
			document["token_endpoint"] = issuer + "/oauth2/token";
			document["introspection_endpoint"] = issuer + "/oauth2/introspect";
			if (capabilities.SupportsDynamicClientRegistration) {
				document["registration_endpoint"] = issuer + "/oauth2/register";
			}
			AddArrayIfNotEmpty(document, "response_types_supported", capabilities.ResponseTypesSupported);
			AddArrayIfNotEmpty(document, "grant_types_supported", capabilities.GrantTypesSupported);
			AddArrayIfNotEmpty(document, "code_challenge_methods_supported", capabilities.CodeChallengeMethodsSupported);
			AddArrayIfNotEmpty(document, "token_endpoint_auth_methods_supported", capabilities.TokenEndpointAuthMethodsSupported);
			AddArrayIfNotEmpty(document, "scopes_supported", capabilities.ScopesSupported);

			ContentResult result = new ContentResult();
			result.StatusCode = 200;
			result.ContentType = "application/json";
			result.Content = document.ToString(Formatting.None);
			return result;
		}

		/// <summary>
		/// Adds the given values as JSON array, if there is at least one value.
		/// </summary>
		private static void AddArrayIfNotEmpty(JObject document, string propertyName, string[] values) {
			if (values == null || values.Length == 0) {
				return;
			}
			document[propertyName] = JArray.FromObject(values);
		}

		/// <summary>
		/// Builds '{scheme}://{host}{pathBase}' from the incoming request
		/// (or uses 'AccessTokenManager.PublicBaseUrl' if configured).
		/// </summary>
		internal static string GetRequestBaseUrl(HttpRequest request) {
			string publicBaseUrl = AccessTokenManager.PublicBaseUrl;
			if (!string.IsNullOrWhiteSpace(publicBaseUrl)) {
				return publicBaseUrl.TrimEnd('/');
			}
			return (request.Scheme + "://" + request.Host.ToUriComponent() + request.PathBase.ToUriComponent()).TrimEnd('/');
		}

	}

}

#endif
