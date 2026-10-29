using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Security.AccessTokenHandling;
using Security.AccessTokenHandling.OAuth;
using System;
using System.Collections.Generic;

namespace AuthTokenHandling.TestApp.Services {

  /// <summary>
  /// Initializes issuers and introspectors via 'IssuerFactory' / 'IntrospectorFactory' and executes them.
  /// The factories always receive a deep copy of the config, because they may mutate it (e.g. default values).
  /// </summary>
  internal static class FactoryRunner {

    /// <summary>
    /// Creates an issuer via 'IssuerFactory.CreateFromConfig' and returns a description of the created instance.
    /// </summary>
    public static JObject DescribeIssuer(AuthTokenConfig config) {

      IAccessTokenIssuer issuer = IssuerFactory.CreateFromConfig(Clone(config));
      return DescribeInstance(issuer, "IssuerFactory", config.IssueMode);

    }

    /// <summary>
    /// Creates an introspector via 'IntrospectorFactory.CreateFromConfig' and returns a description of the created instance.
    /// </summary>
    public static JObject DescribeIntrospector(AuthTokenConfig config) {

      AuthTokenConfig clone = Clone(config);
      IAccessTokenIntrospector introspector = IntrospectorFactory.CreateFromConfig(clone);
      return DescribeInstance(introspector, "IntrospectorFactory", clone.ValidationMode);

    }

    /// <summary>
    /// Creates an issuer via the factory and requests a token with the given claims.
    /// </summary>
    public static JObject IssueToken(
      AuthTokenConfig config, string subject, string audience, string scopes, string additionalClaimsJson
    ) {

      IAccessTokenIssuer issuer = IssuerFactory.CreateFromConfig(Clone(config));

      Dictionary<string, object> claimsToRequest = ParseClaims(additionalClaimsJson);

      if (!string.IsNullOrWhiteSpace(subject)) {
        claimsToRequest["sub"] = subject.Trim();
      }

      if (!string.IsNullOrWhiteSpace(audience)) {
        claimsToRequest["aud"] = audience.Trim();
      }

      if (!string.IsNullOrWhiteSpace(scopes)) {
        claimsToRequest["scope"] = NormalizeScopes(scopes);
      }

      TokenIssuingResult result;
      bool success = issuer.TryRequestAccessToken(claimsToRequest, out result);

      JObject reply = TokenResultToJson(success, result);
      reply["issuerType"] = issuer.GetType().FullName;
      return reply;
    }

    /// <summary>
    /// Creates an introspector via the factory and introspects the given token.
    /// </summary>
    public static JObject IntrospectToken(AuthTokenConfig config, string rawToken) {

      AuthTokenConfig clone = Clone(config);
      IAccessTokenIntrospector introspector = IntrospectorFactory.CreateFromConfig(clone);

      bool isActive;
      Dictionary<string, object> claims;
      introspector.IntrospectAccessToken(StripBearer(rawToken), out isActive, out claims);

      JObject reply = new JObject();
      reply["introspectorType"] = introspector.GetType().FullName;
      reply["isActive"] = isActive;

      if (claims == null) {
        reply["claims"] = JValue.CreateNull();
      } else {
        reply["claims"] = JObject.FromObject(claims);
      }

      return reply;
    }

    /// <summary>
    /// Converts a 'TokenIssuingResult' into the JSON shape used by the UI.
    /// </summary>
    public static JObject TokenResultToJson(bool success, TokenIssuingResult result) {

      JObject reply = new JObject();
      reply["success"] = success;

      if (result == null) {
        reply["result"] = JValue.CreateNull();
      } else {
        reply["result"] = JObject.FromObject(result);
      }

      return reply;
    }

    /// <summary>
    /// Creates a deep copy of the config (via JSON roundtrip).
    /// </summary>
    public static AuthTokenConfig Clone(AuthTokenConfig config) {

      if (config == null) {
        throw new ArgumentException("No AuthTokenConfig given!");
      }

      string json = JsonConvert.SerializeObject(config);
      return JsonConvert.DeserializeObject<AuthTokenConfig>(json);
    }

    /// <summary>
    /// Removes a leading 'Bearer ' and surrounding whitespace.
    /// </summary>
    public static string StripBearer(string rawToken) {

      if (rawToken == null) {
        return string.Empty;
      }

      string token = rawToken.Trim();
      if (token.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) {
        token = token.Substring(7).Trim();
      }

      return token;
    }

    /// <summary>
    /// Joins whitespace/comma separated scopes into a single space separated string.
    /// </summary>
    public static string NormalizeScopes(string scopes) {

      string[] parts = scopes.Split(new char[] { ' ', ',', ';', '\r', '\n', '\t' }, StringSplitOptions.RemoveEmptyEntries);
      return string.Join(" ", parts);

    }

    /// <summary>
    /// Parses an optional JSON object into a claim dictionary.
    /// </summary>
    private static Dictionary<string, object> ParseClaims(string additionalClaimsJson) {

      Dictionary<string, object> claims = new Dictionary<string, object>();

      if (string.IsNullOrWhiteSpace(additionalClaimsJson)) {
        return claims;
      }

      JObject parsed;
      try {
        parsed = JObject.Parse(additionalClaimsJson);
      } catch (JsonReaderException ex) {
        throw new InvalidOperationException("The additional claims are no valid JSON object: " + ex.Message);
      }

      foreach (JProperty property in parsed.Properties()) {
        if (property.Value is JValue) {
          claims[property.Name] = ((JValue)property.Value).Value;
        } else {
          claims[property.Name] = property.Value.ToObject<object>();
        }
      }

      return claims;
    }

    /// <summary>
    /// Describes a created instance (type and implemented interfaces).
    /// </summary>
    private static JObject DescribeInstance(object instance, string factoryName, string mode) {

      JObject reply = new JObject();
      reply["factory"] = factoryName;
      reply["mode"] = mode;

      if (instance == null) {
        reply["type"] = JValue.CreateNull();
        return reply;
      }

      Type type = instance.GetType();
      reply["type"] = type.FullName;
      reply["assembly"] = type.Assembly.GetName().Name;

      JArray interfaces = new JArray();
      foreach (Type interfaceType in type.GetInterfaces()) {
        interfaces.Add(interfaceType.FullName);
      }
      reply["interfaces"] = interfaces;

      return reply;
    }

  }

}
