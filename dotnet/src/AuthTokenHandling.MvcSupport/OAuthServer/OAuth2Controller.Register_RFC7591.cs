using Logging.SmartStandards;
using Logging.SmartStandards.CopyForAuthTokenHandling;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Security.AccessTokenHandling.OAuth.Server {

  internal partial class OAuth2Controller {

    // https://www.rfc-editor.org/rfc/rfc7591

    /// <summary>
    /// RFC 7591 dynamic client registration. The request is parsed here, the decision whether and how
    /// the client is registered is delegated to 'IOAuthService.TryRegisterClient'.
    /// </summary>
    [HttpPost(), Produces("application/json")]
    [Route("register")]
    [AllowAnonymous]
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
        return CreateJsonResult(400, CreateErrorDocument("invalid_client_metadata", "The request body must be a JSON object."));
      }

      List<string> redirectUris = new List<string>();
      JArray redirectUriArray = request["redirect_uris"] as JArray;
      if (redirectUriArray != null) {
        foreach (JToken redirectUri in redirectUriArray) {
          redirectUris.Add(redirectUri.ToString());
        }
      }

      string clientName = request.Value<string>("client_name");
      string authMethod = request.Value<string>("token_endpoint_auth_method");

      string clientId;
      string error;
      string errorDescription;
      bool registered = _AuthService.TryRegisterClient(
        clientName, redirectUris.ToArray(), authMethod, out clientId, out error, out errorDescription
      );
      if (!registered) {
        if (string.IsNullOrWhiteSpace(error)) {
          error = "invalid_client_metadata";
        }
        return CreateJsonResult(400, CreateErrorDocument(error, errorDescription));
      }

      if (string.IsNullOrWhiteSpace(authMethod)) {
        authMethod = "none";
      }

      JObject response = new JObject();
      response["client_id"] = clientId;
      response["client_id_issued_at"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
      if (!string.IsNullOrWhiteSpace(clientName)) {
        response["client_name"] = clientName;
      }
      response["redirect_uris"] = JArray.FromObject(redirectUris);
      response["token_endpoint_auth_method"] = authMethod;
      response["grant_types"] = new JArray("authorization_code", "refresh_token");
      response["response_types"] = new JArray("code");
      return CreateJsonResult(201, response);
    }

    /// <summary>
    /// Creates an RFC 7591 error document.
    /// </summary>
    private static JObject CreateErrorDocument(string error, string description) {
      JObject document = new JObject();
      document["error"] = error;
      if (!string.IsNullOrWhiteSpace(description)) {
        document["error_description"] = description;
      }
      return document;
    }

    /// <summary>
    /// Creates a JSON content result with the given status code.
    /// </summary>
    private static ContentResult CreateJsonResult(int statusCode, JObject document) {
      ContentResult result = new ContentResult();
      result.StatusCode = statusCode;
      result.ContentType = "application/json";
      result.Content = document.ToString(Formatting.None);
      return result;
    }

  }

}
