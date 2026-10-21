#if !NET46

using Logging.SmartStandards;
using Logging.SmartStandards.CopyForAuthTokenHandling;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Security.AccessTokenHandling.OAuth.Server {

  /// <summary>
  /// Endpoints of the Cheap OAuth Server beside the 'OAuth2Controller':
  /// RFC 8414 authorization server metadata and RFC 7591 dynamic client registration (public clients only).
  /// Hidden from automatic controller discovery - exposed only via 'AddCheapOAuthServer'.
  /// </summary>
  [ApiController]
  [ApiExplorerSettings(GroupName = "OAuth")]
  internal sealed class CheapOAuthController : ControllerBase {

    private readonly CheapOAuthService _Service;
    private readonly CheapOAuthOptions _Options;

    public CheapOAuthController(CheapOAuthService service, CheapOAuthOptions options) {
      _Service = service;
      _Options = options;
    }

    /// <summary>
    /// RFC 8414 authorization server metadata (the issuer is the base url of the request).
    /// </summary>
    [HttpGet]
    [AllowAnonymous]
    [Route(".well-known/oauth-authorization-server")]
    [Route(".well-known/openid-configuration")]
    public ContentResult GetAuthorizationServerMetadata() {
      string issuer = GetRequestBaseUrl(this.Request);
      JObject document = new JObject();
      document["issuer"] = issuer;
      document["authorization_endpoint"] = issuer + "/oauth2/authorize";
      document["token_endpoint"] = issuer + "/oauth2/token";
      document["introspection_endpoint"] = issuer + "/oauth2/introspect";
      document["registration_endpoint"] = issuer + "/oauth2/register";
      document["response_types_supported"] = new JArray("code");
      document["grant_types_supported"] = new JArray("authorization_code", "refresh_token");
      document["code_challenge_methods_supported"] = new JArray("S256");
      document["token_endpoint_auth_methods_supported"] = new JArray("none");
      if (_Options.ScopesSupported.Length > 0) {
        JArray.FromObject(AccessTokenManager.ApplyApiPermissionPrefix(_Options.ScopesSupported));
      }
      return CreateJsonResult(200, document);
    }

    /// <summary>
    /// RFC 7591 dynamic client registration (public clients with PKCE only).
    /// </summary>
    [HttpPost]
    [AllowAnonymous]
    [Route("oauth2/register")]
    public ContentResult RegisterClient() {
      JObject request;
      try {
        string body;
        using (StreamReader reader = new StreamReader(this.Request.Body, Encoding.UTF8)) {
          body = reader.ReadToEndAsync().GetAwaiter().GetResult();
        }
        request = JObject.Parse(body);
      }
      catch (JsonException ex) {
        DevLogger.LogError(ex);
        return CreateError("invalid_client_metadata", "The request body must be a JSON object.");
      }

      List<string> redirectUris = new List<string>();
      JArray redirectUriArray = request["redirect_uris"] as JArray;
      if (redirectUriArray != null) {
        foreach (JToken redirectUri in redirectUriArray) {
          redirectUris.Add(redirectUri.ToString());
        }
      }

      string authMethod = request.Value<string>("token_endpoint_auth_method");
      if (!string.IsNullOrWhiteSpace(authMethod) && !string.Equals(authMethod, "none", StringComparison.Ordinal)) {
        return CreateError("invalid_client_metadata", "Only public clients ('token_endpoint_auth_method' = 'none') are supported.");
      }

      string clientName = request.Value<string>("client_name");
      string clientId;
      try {
        clientId = _Service.ClientRegistry.RegisterClient(clientName, redirectUris.ToArray());
      }
      catch (ArgumentException ex) {
        DevLogger.LogError(ex);
        return CreateError("invalid_redirect_uri", ex.Message);
      }
      catch (InvalidOperationException ex) {
        DevLogger.LogError(ex);
        return CreateError("invalid_client_metadata", ex.Message);
      }

      JObject response = new JObject();
      response["client_id"] = clientId;
      response["client_id_issued_at"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
      if (!string.IsNullOrWhiteSpace(clientName)) {
        response["client_name"] = clientName;
      }
      response["redirect_uris"] = JArray.FromObject(redirectUris);
      response["token_endpoint_auth_method"] = "none";
      response["grant_types"] = new JArray("authorization_code", "refresh_token");
      response["response_types"] = new JArray("code");
      return CreateJsonResult(201, response);
    }

    private static ContentResult CreateError(string error, string description) {
      JObject document = new JObject();
      document["error"] = error;
      document["error_description"] = description;
      return CreateJsonResult(400, document);
    }

    private static ContentResult CreateJsonResult(int statusCode, JObject document) {
      ContentResult result = new ContentResult();
      result.StatusCode = statusCode;
      result.ContentType = "application/json";
      result.Content = document.ToString(Formatting.None);
      return result;
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
