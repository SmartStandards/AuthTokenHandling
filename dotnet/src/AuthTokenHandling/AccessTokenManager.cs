using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading;
using Logging.SmartStandards;
using Logging.SmartStandards.CopyForAuthTokenHandling;
using Security.AccessTokenHandling.OAuth;
using Security.AccessTokenHandling.OAuth.OobProviders;

namespace Security.AccessTokenHandling {

	/// <summary>
	/// Central manager for token sources: resolution of logical names (API groups, contracts, schemes) to token
	/// source ids, registration of the per-source configuration (issuer + introspector), the per-interaction
	/// current-token register, outgoing token supply (incl. refresh and opt-in persistence) and the wire-up
	/// hooks for the AccessTokenValidator and the UJMW client.
	/// </summary>
	public static partial class AccessTokenManager {

		/// <summary>
		/// The magic id of the default token source (see 'empty string vs. default').
		/// </summary>
		public const string DefaultTokenSourceId = "default";

		/// <summary>
		/// Legacy alias for 'default' (from the time when token source ids were GUIDs).
		/// </summary>
		public const string LegacyDefaultTokenSourceId = "00000000-0000-0000-0000-000000000000";

		/// <summary>
		/// OFFICIAL CONVENTION (binding for all HTTP adapters): header values and URL fields of an 'AuthTokenConfig'
		/// may contain this literal placeholder. Every adapter which writes such values to the outside MUST replace it
		/// with the base URL of its own request ('scheme://host[:port]' plus path base, without trailing slash)
		/// using a plain, case-sensitive replacement of every occurrence.
		/// </summary>
		public const string RequestBaseUrlPlaceholder = "{RequestBaseUrl}";

		private const int _RefreshSkewSeconds = 30;

		private static readonly object _SyncRoot = new object();

		#region " State "

		private static Dictionary<string, List<string>> _MappingsByLogicalName = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
		private static HashSet<string> _AnonymousLogicalNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
		private static List<RequiredScopeEntry> _ScopesRequiredForAll = new List<RequiredScopeEntry>();
		private static Dictionary<string, List<RequiredScopeEntry>> _ScopesRequiredByLogicalName = new Dictionary<string, List<RequiredScopeEntry>>(StringComparer.OrdinalIgnoreCase);
		private static Dictionary<string, string> _TokenSourceIdsByIssuer = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

		private static Dictionary<string, TokenSourceRegistration> _Registrations = new Dictionary<string, TokenSourceRegistration>(StringComparer.OrdinalIgnoreCase);
		private static HashSet<string> _NonRelayableTokenSourceIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

		private static Dictionary<string, AsyncLocal<RegisterEntry>> _Register = new Dictionary<string, AsyncLocal<RegisterEntry>>(StringComparer.OrdinalIgnoreCase);
		private static Dictionary<string, RegisterEntry> _SuppliedTokens = new Dictionary<string, RegisterEntry>(StringComparer.OrdinalIgnoreCase);

		private static string _PublicBaseUrl = null;

		[ThreadStatic]
		private static string _MatchedTokenSourceId;

		[ThreadStatic]
		private static string _CurrentApiGroupName;

		[ThreadStatic]
		private static string[] _CurrentAdditionalLogicalNames;

		/// <summary>
		/// Everything which is known about one registered token source.
		/// </summary>
		private class TokenSourceRegistration {
			public AuthTokenConfig Config;
			public bool IssuerCreated;
			public IAccessTokenIssuer Issuer;
			public bool IntrospectorCreated;
			public IAccessTokenIntrospector Introspector;
			public bool OAuthOperationsProviderCreated;
			public IOAuthOperationsProvider OAuthOperationsProvider;
		}

		/// <summary>
		/// One scope registered via 'RequireScope' (the prefix is applied lazily, so that a later change of the
		/// configured API permission prefix is respected).
		/// </summary>
		private class RequiredScopeEntry {
			public string Scope;
			public bool PrependConfiguredScopePrefix;
		}

		/// <summary>
		/// Immutable snapshot of the tokens of one token source.
		/// </summary>
		private class RegisterEntry {
			public string AccessToken = string.Empty;
			public string RefreshToken = string.Empty;
			public string IdToken = string.Empty;
			public string Subject = string.Empty;
			public string[] Scopes = new string[] { };
			public DateTime ExpiresUtc = DateTime.MaxValue;

			/// <summary>
			/// false for incoming tokens (pushed by the validator): they are only relayed, never refreshed.
			/// </summary>
			public bool Refreshable;
		}

		#endregion

		#region " Resolution (logical names -> token source ids) "

		/// <summary>
		/// Maps one or more logical names (API group, contract, scheme or policy name) to a token source id.
		/// Several calls for the same logical name append further token sources (in call order).
		/// </summary>
		public static void MapTokenSourceId(string tokenSourceId, params string[] logicalGroupOrSchemaNames) {
			string normalizedTokenSourceId = NormalizeId(tokenSourceId);
			if (logicalGroupOrSchemaNames == null) {
				return;
			}
			lock (_SyncRoot) {
				foreach (string logicalName in logicalGroupOrSchemaNames) {
					string normalizedName = NormalizeId(logicalName);
					List<string> targets;
					if (!_MappingsByLogicalName.TryGetValue(normalizedName, out targets)) {
						targets = new List<string>();
						_MappingsByLogicalName[normalizedName] = targets;
					}
					if (!targets.Contains(normalizedTokenSourceId, StringComparer.OrdinalIgnoreCase)) {
						targets.Add(normalizedTokenSourceId);
					}
				}
			}
		}

		/// <summary>
		/// Equivalent to 'MapTokenSourceId(tokenSourceId, "default")'.
		/// </summary>
		public static void SetDefaultTokenSourceId(string tokenSourceId) {
			MapTokenSourceId(tokenSourceId, DefaultTokenSourceId);
		}

		/// <summary>
		/// Marks ONE logical name as anonymous (no token and no scope required).
		/// Anonymous access is dangerous, so every name must be written down explicitly.
		/// </summary>
		public static void MapAnonymous(string logicalGroupOrSchemaName) {
			if (string.IsNullOrWhiteSpace(logicalGroupOrSchemaName)) {
				throw new ArgumentException($"'{nameof(logicalGroupOrSchemaName)}' must not be empty!");
			}
			lock (_SyncRoot) {
				_AnonymousLogicalNames.Add(logicalGroupOrSchemaName);
			}
		}

		/// <summary>
		/// Requires a scope for ONE logical name, or for all calls if the name is null.
		/// The configured API permission prefix is applied (unless already present).
		/// </summary>
		public static void RequireScope(string scope, string logicalGroupOrSchemaName = null) {
			RequireScope(scope, logicalGroupOrSchemaName, true);
		}

		/// <summary>
		/// Requires a scope for ONE logical name, or for all calls if the name is null.
		/// </summary>
		/// <param name="scope">The scope.</param>
		/// <param name="logicalGroupOrSchemaName">The logical name, or null for all calls.</param>
		/// <param name="prependConfiguredScopePrefix">
		/// true (default of the other overload): the configured API permission prefix is applied (unless already present).
		/// false: the scope is required literally (escape hatch for scopes outside the API permission namespace).
		/// </param>
		public static void RequireScope(string scope, string logicalGroupOrSchemaName, bool prependConfiguredScopePrefix) {
			if (string.IsNullOrWhiteSpace(scope)) {
				throw new ArgumentException($"'{nameof(scope)}' must not be empty!");
			}
			RequiredScopeEntry entry = new RequiredScopeEntry();
			entry.Scope = scope;
			entry.PrependConfiguredScopePrefix = prependConfiguredScopePrefix;
			lock (_SyncRoot) {
				if (logicalGroupOrSchemaName == null) {
					_ScopesRequiredForAll.Add(entry);
					return;
				}
				List<RequiredScopeEntry> scopes;
				if (!_ScopesRequiredByLogicalName.TryGetValue(logicalGroupOrSchemaName, out scopes)) {
					scopes = new List<RequiredScopeEntry>();
					_ScopesRequiredByLogicalName[logicalGroupOrSchemaName] = scopes;
				}
				scopes.Add(entry);
			}
		}

		/// <summary>
		/// Routes tokens whose pre-read 'iss' claim equals one of the issuers (OrdinalIgnoreCase) to this token source.
		/// The issuer is routing information only (never trust) - the selected introspector still validates the token.
		/// </summary>
		public static void MapIssuer(string tokenSourceId, params string[] issuers) {
			string normalizedTokenSourceId = NormalizeId(tokenSourceId);
			if (issuers == null) {
				return;
			}
			lock (_SyncRoot) {
				foreach (string issuer in issuers) {
					if (!string.IsNullOrWhiteSpace(issuer)) {
						_TokenSourceIdsByIssuer[issuer] = normalizedTokenSourceId;
					}
				}
			}
		}

		/// <summary>
		/// Resolves a logical name to the token source ids (in mapping order, the first one is the primary).
		/// Without a mapping, the logical name itself is returned as token source id.
		/// An empty string (= 'not known') is resolved as 'default' (final lookup).
		/// </summary>
		public static string[] ResolveTokenSourceIds(string logicalGroupOrSchemaName) {
			string normalizedName = NormalizeId(logicalGroupOrSchemaName);
			lock (_SyncRoot) {
				List<string> targets;
				if (_MappingsByLogicalName.TryGetValue(normalizedName, out targets)) {
					return targets.ToArray();
				}
			}
			return new string[] { normalizedName };
		}

		/// <summary>
		/// Returns true, if any of the given logical names was registered via 'MapAnonymous'.
		/// </summary>
		public static bool IsAnonymous(params string[] logicalGroupOrSchemaNames) {
			if (logicalGroupOrSchemaNames == null) {
				return false;
			}
			lock (_SyncRoot) {
				foreach (string logicalName in logicalGroupOrSchemaNames) {
					if (logicalName != null && _AnonymousLogicalNames.Contains(logicalName)) {
						return true;
					}
				}
			}
			return false;
		}

		/// <summary>
		/// Returns the accumulated (AND) required scopes for the given logical names: all 'RequireScope' entries for
		/// all calls plus those of every given logical name - already prefixed with the configured API permission prefix.
		/// </summary>
		public static string[] GetRequiredScopes(params string[] logicalGroupOrSchemaNames) {
			List<string> result = new List<string>();
			lock (_SyncRoot) {
				foreach (RequiredScopeEntry entry in _ScopesRequiredForAll) {
					AddDistinct(result, GetEffectiveScope(entry));
				}
				if (logicalGroupOrSchemaNames != null) {
					foreach (string logicalName in logicalGroupOrSchemaNames) {
						List<RequiredScopeEntry> scopes;
						if (logicalName != null && _ScopesRequiredByLogicalName.TryGetValue(logicalName, out scopes)) {
							foreach (RequiredScopeEntry entry in scopes) {
								AddDistinct(result, GetEffectiveScope(entry));
							}
						}
					}
				}
			}
			return result.ToArray();
		}

		/// <summary>
		/// Returns the scope of a 'RequireScope' entry as it must be present in the token.
		/// </summary>
		private static string GetEffectiveScope(RequiredScopeEntry entry) {
			if (entry.PrependConfiguredScopePrefix) {
				return ApplyApiPermissionPrefix(entry.Scope);
			}
			return entry.Scope;
		}

		/// <summary>
		/// Applies the configured API permission prefix (unless already present) to all given scopes
		/// (blank entries are skipped, duplicates removed case-insensitively). Never returns null.
		/// </summary>
		public static string[] ApplyApiPermissionPrefix(string[] scopes) {
			List<string> result = new List<string>();
			if (scopes == null) {
				return result.ToArray();
			}
			foreach (string scope in scopes) {
				if (string.IsNullOrWhiteSpace(scope)) {
					continue;
				}
				AddDistinct(result, ApplyApiPermissionPrefix(scope.Trim()));
			}
			return result.ToArray();
		}

		/// <summary>
		/// Applies the configured API permission prefix (unless already present).
		/// </summary>
		public static string ApplyApiPermissionPrefix(string scope) {
			string prefix = AccessTokenValidator.ApiPermissionPrefix;
			if (string.IsNullOrEmpty(prefix) || scope.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) {
				return scope;
			}
			return prefix + scope;
		}

		/// <summary>
		/// Evaluates the given logical names in order (resolution chain) and returns the registered token source ids
		/// of the first name which resolves to at least one registered token source. If no name matches,
		/// the 'default' token source is used (fail closed: empty array if 'default' is not registered either).
		/// </summary>
		private static string[] ResolveRegisteredTokenSourceIds(IEnumerable<string> logicalNamesInChainOrder) {
			foreach (string logicalName in logicalNamesInChainOrder) {
				if (string.IsNullOrEmpty(logicalName)) {
					continue; //empty = 'not known' -> continue with the next step
				}
				string[] registered = FilterRegistered(ResolveTokenSourceIds(logicalName));
				if (registered.Length > 0) {
					return registered;
				}
			}
			return FilterRegistered(ResolveTokenSourceIds(string.Empty));
		}

		/// <summary>
		/// Returns only those token source ids which have a registration.
		/// </summary>
		private static string[] FilterRegistered(string[] tokenSourceIds) {
			List<string> result = new List<string>();
			lock (_SyncRoot) {
				foreach (string tokenSourceId in tokenSourceIds) {
					if (_Registrations.ContainsKey(tokenSourceId)) {
						AddDistinct(result, tokenSourceId);
					}
				}
			}
			return result.ToArray();
		}

		/// <summary>
		/// Builds the logical names of a contract in chain order (UC-2):
		/// AuthTokenSourceAttribute (if not empty), then the plain interface name.
		/// Returns false, if the contract is explicitly anonymous (AuthTokenSourceAttribute(null)).
		/// </summary>
		internal static bool TryGetLogicalNamesForContract(Type contractType, string apiGroupName, out string[] logicalNames) {
			List<string> names = new List<string>();
			if (contractType != null) {
				string attributeValue;
				if (AuthTokenSourceAttribute.TryPickFrom(contractType, out attributeValue)) {
					if (attributeValue == null) {
						logicalNames = new string[] { };
						return false;
					}
					if (attributeValue.Length > 0) {
						names.Add(attributeValue);
					}
				}
			}
			if (!string.IsNullOrEmpty(apiGroupName)) {
				names.Add(apiGroupName);
			}
			//additional logical names of the current call (e.g. authentication scheme names, handed over by MvcSupport)
			string[] additionalNames = _CurrentAdditionalLogicalNames;
			if (additionalNames != null) {
				foreach (string additionalName in additionalNames) {
					if (!string.IsNullOrEmpty(additionalName)) {
						AddDistinct(names, additionalName);
					}
				}
			}
			if (contractType != null) {
				names.Add(contractType.Name);
			}
			logicalNames = names.ToArray();
			return true;
		}

		/// <summary>
		/// Resolves the registered token sources for the given logical names in chain order (first name which resolves
		/// to at least one registered token source wins, otherwise 'default'; empty array = fail closed).
		/// </summary>
		public static string[] ResolveRegisteredTokenSourceIdsForChain(string[] logicalNamesInChainOrder) {
			if (logicalNamesInChainOrder == null) {
				logicalNamesInChainOrder = new string[] { };
			}
			return ResolveRegisteredTokenSourceIds(logicalNamesInChainOrder);
		}

		/// <summary>
		/// Converts null / legacy GUID into the normalized form ('' stays '' until the final lookup, null becomes '').
		/// The final lookup ('' -> 'default') is done here as well, because this is only used for the final keys.
		/// </summary>
		private static string NormalizeId(string id) {
			if (string.IsNullOrEmpty(id)) {
				return DefaultTokenSourceId;
			}
			if (id.Equals(LegacyDefaultTokenSourceId, StringComparison.OrdinalIgnoreCase)) {
				return DefaultTokenSourceId;
			}
			return id;
		}

		private static void AddDistinct(List<string> list, string value) {
			if (!list.Contains(value, StringComparer.OrdinalIgnoreCase)) {
				list.Add(value);
			}
		}

		#endregion

		#region " Information functions "

		/// <summary>
		/// Returns the ids of all registered token sources.
		/// </summary>
		public static string[] GetRegisteredTokenSourceIds() {
			lock (_SyncRoot) {
				return _Registrations.Keys.ToArray();
			}
		}

		/// <summary>
		/// Returns the registered configuration of a token source (the registered instance - do not modify it!).
		/// </summary>
		public static bool TryGetTokenSourceConfig(string tokenSourceId, out AuthTokenConfig config) {
			TokenSourceRegistration registration;
			if (TryGetRegistration(tokenSourceId, out registration) && registration.Config != null) {
				config = registration.Config;
				return true;
			}
			config = null;
			return false;
		}

		/// <summary>
		/// Swagger bridge: returns per token source of the API group a COPY of the registered configuration,
		/// whose 'Claims["scope"]' additionally contains the required scopes of the group (already prefixed).
		/// Returns an empty array for anonymous groups.
		/// </summary>
		public static KeyValuePair<string, AuthTokenConfig>[] GetTokenSourceConfigsForApiGroup(string apiGroupName) {
			List<KeyValuePair<string, AuthTokenConfig>> result = new List<KeyValuePair<string, AuthTokenConfig>>();
			if (IsAnonymous(apiGroupName)) {
				return result.ToArray();
			}
			string[] requiredScopes = GetRequiredScopes(apiGroupName);
			string[] tokenSourceIds = ResolveRegisteredTokenSourceIds(new string[] { apiGroupName });
			foreach (string tokenSourceId in tokenSourceIds) {
				AuthTokenConfig config;
				if (!TryGetTokenSourceConfig(tokenSourceId, out config)) {
					continue;
				}
				AuthTokenConfig copy = CopyConfig(config);
				List<string> scopes = new List<string>();
				string existingScopes;
				if (copy.Claims == null) {
					copy.Claims = new Dictionary<string, string>();
				}
				if (copy.Claims.TryGetValue("scope", out existingScopes) && existingScopes != null) {
					foreach (string existingScope in existingScopes.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries)) {
						AddDistinct(scopes, existingScope);
					}
				}
				foreach (string requiredScope in requiredScopes) {
					AddDistinct(scopes, requiredScope);
				}
				if (scopes.Count > 0) {
					copy.Claims["scope"] = string.Join(" ", scopes);
				}
				result.Add(new KeyValuePair<string, AuthTokenConfig>(tokenSourceId, copy));
			}
			return result.ToArray();
		}

		/// <summary>
		/// Creates a copy of a configuration (dictionaries are copied as well).
		/// </summary>
		private static AuthTokenConfig CopyConfig(AuthTokenConfig source) {
			AuthTokenConfig copy = new AuthTokenConfig();
			foreach (PropertyInfo property in typeof(AuthTokenConfig).GetProperties(BindingFlags.Instance | BindingFlags.Public)) {
				if (property.CanRead && property.CanWrite && property.GetIndexParameters().Length == 0) {
					property.SetValue(copy, property.GetValue(source, null), null);
				}
			}
			copy.Claims = CopyDictionary(source.Claims);
			if (source.AdditionalAuthArgs != null) {
				copy.AdditionalAuthArgs = CopyDictionary(source.AdditionalAuthArgs);
			}
			if (source.AdditionalRetrieveArgs != null) {
				copy.AdditionalRetrieveArgs = CopyDictionary(source.AdditionalRetrieveArgs);
			}
			return copy;
		}

		private static Dictionary<string, string> CopyDictionary(Dictionary<string, string> source) {
			Dictionary<string, string> copy = new Dictionary<string, string>();
			if (source != null) {
				foreach (KeyValuePair<string, string> entry in source) {
					copy[entry.Key] = entry.Value;
				}
			}
			return copy;
		}

		/// <summary>
		/// OFFICIAL CONVENTION: replaces every occurrence of the literal placeholder '{RequestBaseUrl}' (plain,
		/// case-sensitive) with the base URL of the current request ('scheme://host[:port]' plus path base, without
		/// trailing slash). Every HTTP adapter writing header values or configuration URLs to the outside MUST call this
		/// (or implement the identical rule).
		/// </summary>
		/// <param name="headerValue">The value which may contain the placeholder (null is returned unchanged).</param>
		/// <param name="requestBaseUrl">The base URL of the own request (a trailing slash is removed).</param>
		public static string ResolveRequestBaseUrlPlaceholder(string headerValue, string requestBaseUrl) {
			if (headerValue == null || headerValue.IndexOf(RequestBaseUrlPlaceholder, StringComparison.Ordinal) < 0) {
				return headerValue;
			}
			if (requestBaseUrl == null) {
				requestBaseUrl = string.Empty;
			}
			return headerValue.Replace(RequestBaseUrlPlaceholder, requestBaseUrl.TrimEnd('/'));
		}

		/// <summary>
		/// The optional public base URL (configured via 'ConfigureTokenSupply'), which is written directly instead of the
		/// '{RequestBaseUrl}' placeholder (for proxies without forwarded headers). Empty string if not configured.
		/// </summary>
		public static string PublicBaseUrl {
			get {
				if (_PublicBaseUrl == null) {
					return string.Empty;
				}
				return _PublicBaseUrl;
			}
		}

		/// <summary>
		/// Resolves the placeholder for usages WITHOUT a request (for example outgoing calls by an in-process issuer).
		/// Throws a clear exception, if the placeholder is present and no public base url is configured.
		/// </summary>
		private static string ResolvePlaceholderWithoutRequest(string url) {
			if (url == null || url.IndexOf(RequestBaseUrlPlaceholder, StringComparison.Ordinal) < 0) {
				return url;
			}
			if (string.IsNullOrWhiteSpace(_PublicBaseUrl)) {
				throw new InvalidOperationException(
					$"The url '{url}' contains the placeholder '{RequestBaseUrlPlaceholder}', which cannot be resolved without an http request. Please configure a public base url via 'ConfigureTokenSupply'!"
				);
			}
			return ResolveRequestBaseUrlPlaceholder(url, _PublicBaseUrl);
		}

		#endregion

		#region " Current-token register (per interaction) "

		/// <summary>
		/// Registers tokens as current for the interaction. The access token is checked ONLY with the introspector of the
		/// token source (no validator: no requirements, no auditing, no caching).
		/// An inactive token throws an ArgumentException; a null/empty access token clears the entry.
		/// </summary>
		public static void SetCurrentToken(string tokenSourceId, string accessToken, string refreshToken = null, string idToken = null) {
			string resolvedId = NormalizeId(tokenSourceId);

			if (string.IsNullOrEmpty(accessToken)) {
				GetRegisterSlot(resolvedId).Value = null;
				return;
			}

			IAccessTokenIntrospector introspector = GetIntrospector(resolvedId);
			if (introspector == null) {
				throw new InvalidOperationException($"There is no introspector available for token source '{resolvedId}'!");
			}

			bool isActive;
			Dictionary<string, object> claims;
			introspector.IntrospectAccessToken(accessToken, out isActive, out claims);
			if (!isActive) {
				throw new ArgumentException($"The given access token is not active for token source '{resolvedId}'!");
			}

			RegisterEntry entry = new RegisterEntry();
			entry.AccessToken = accessToken;
			entry.RefreshToken = EmptyIfNull(refreshToken);
			entry.IdToken = EmptyIfNull(idToken);
			entry.Subject = ReadSubject(claims);
			entry.Scopes = ReadScopes(claims);
			entry.ExpiresUtc = ReadExpiry(claims);
			entry.Refreshable = true;
			GetRegisterSlot(resolvedId).Value = entry;
		}

		/// <summary>Returns the current access token of the interaction (empty string if none).</summary>
		public static string GetCurrentAccessToken(string tokenSourceId) {
			return GetCurrentEntry(tokenSourceId).AccessToken;
		}

		/// <summary>Returns the current refresh token of the interaction (empty string if none).</summary>
		public static string GetCurrentRefreshToken(string tokenSourceId) {
			return GetCurrentEntry(tokenSourceId).RefreshToken;
		}

		/// <summary>Returns the current id token of the interaction (empty string if none).</summary>
		public static string GetCurrentIdToken(string tokenSourceId) {
			return GetCurrentEntry(tokenSourceId).IdToken;
		}

		/// <summary>Returns true, if there is a current access token for the interaction.</summary>
		public static bool HasCurrentAccessToken(string tokenSourceId) {
			return GetCurrentEntry(tokenSourceId).AccessToken.Length > 0;
		}

		/// <summary>Returns the subject of the current token ("" if unknown).</summary>
		public static string GetCurrentSubject(string tokenSourceId) {
			return GetCurrentEntry(tokenSourceId).Subject;
		}

		/// <summary>Returns the scopes of the current token (never null; as in the token, with prefix).</summary>
		public static string[] GetCurrentScopes(string tokenSourceId) {
			return GetCurrentEntry(tokenSourceId).Scopes.ToArray();
		}

		private static RegisterEntry GetCurrentEntry(string tokenSourceId) {
			RegisterEntry entry = GetRegisterSlot(NormalizeId(tokenSourceId)).Value;
			if (entry == null) {
				return new RegisterEntry();
			}
			return entry;
		}

		private static AsyncLocal<RegisterEntry> GetRegisterSlot(string resolvedId) {
			lock (_SyncRoot) {
				AsyncLocal<RegisterEntry> slot;
				if (!_Register.TryGetValue(resolvedId, out slot)) {
					slot = new AsyncLocal<RegisterEntry>();
					_Register[resolvedId] = slot;
				}
				return slot;
			}
		}

		/// <summary>
		/// Returns true, if tokens of this token source must not be relayed ('DisableTokenRelay').
		/// </summary>
		public static bool IsTokenRelayDisabled(string tokenSourceId) {
			lock (_SyncRoot) {
				return _NonRelayableTokenSourceIds.Contains(NormalizeId(tokenSourceId));
			}
		}

		/// <summary>
		/// Pushes an incoming (validated) token into the register. Such tokens are only relayed, never refreshed.
		/// Ignored for non-relayable token sources.
		/// </summary>
		internal static void PushValidatedToken(string tokenSourceId, string accessToken, string subject, string[] scopes) {
			if (string.IsNullOrEmpty(tokenSourceId) || string.IsNullOrEmpty(accessToken) || IsTokenRelayDisabled(tokenSourceId)) {
				return;
			}
			RegisterEntry entry = new RegisterEntry();
			entry.AccessToken = accessToken;
			entry.Subject = EmptyIfNull(subject);
			if (scopes != null) {
				entry.Scopes = scopes.ToArray();
			}
			entry.Refreshable = false;
			GetRegisterSlot(NormalizeId(tokenSourceId)).Value = entry;
		}

		#endregion

		#region " Matched token source (handover from the introspection to the validator) "

		/// <summary>
		/// Called by the introspector lookup / the composite introspector to hand over the token source
		/// which has accepted the token (thread-static, because introspection is synchronous).
		/// </summary>
		internal static void SetMatchedTokenSourceId(string tokenSourceId) {
			_MatchedTokenSourceId = tokenSourceId;
		}

		/// <summary>
		/// Returns (without clearing) the token source which has accepted the last introspected token on this thread.
		/// </summary>
		internal static string PeekMatchedTokenSourceId() {
			return _MatchedTokenSourceId;
		}

		/// <summary>
		/// Returns and clears the token source which has accepted the last introspected token on this thread.
		/// </summary>
		internal static string TakeMatchedTokenSourceId() {
			string result = _MatchedTokenSourceId;
			_MatchedTokenSourceId = null;
			return result;
		}

		/// <summary>
		/// Called by the validator to hand over the API group name of the current call to the introspector lookup
		/// (the 'IntrospectorLookupMethod' delegate has no parameter for it; thread-static, because the lookup is
		/// synchronous). null clears the value.
		/// </summary>
		internal static void SetCurrentApiGroupName(string apiGroupName) {
			_CurrentApiGroupName = apiGroupName;
		}

		/// <summary>
		/// Hands over additional logical names of the current call (e.g. authentication scheme names resolved by
		/// MvcSupport) to the resolution chain (thread-static, because validation is synchronous). null clears the value.
		/// </summary>
		internal static void SetCurrentAdditionalLogicalNames(string[] logicalNames) {
			_CurrentAdditionalLogicalNames = logicalNames;
		}

		/// <summary>
		/// Returns the additional logical names of the current call (null if none).
		/// </summary>
		internal static string[] GetCurrentAdditionalLogicalNames() {
			return _CurrentAdditionalLogicalNames;
		}

		#endregion

		#region " Outgoing token supply (issuing, refresh, persistence) "

		/// <summary>
		/// Returns an active access token for outgoing calls to the given token source. Order: current token of the
		/// interaction (if relayable), the token obtained by the manager itself (refreshed if expiring), the persistence
		/// (if enabled), and finally the configured issuer.
		/// </summary>
		/// <param name="tokenSourceId">The token source id ('' -> 'default').</param>
		/// <param name="forceRefresh">true: ignore the currently known self-obtained token and refresh/issue a new one.</param>
		/// <param name="accessToken">The token (empty string if false is returned).</param>
		public static bool TryGetActiveTokenForTokenSource(string tokenSourceId, bool forceRefresh, out string accessToken) {
			string resolvedId = NormalizeId(tokenSourceId);
			accessToken = string.Empty;

			if (IsTokenRelayDisabled(resolvedId)) {
				return false;
			}

			//1. current token of the interaction
			RegisterEntry current = GetRegisterSlot(resolvedId).Value;
			if (!forceRefresh && current != null && current.AccessToken.Length > 0) {
				if (!current.Refreshable || !IsExpiring(current)) {
					accessToken = current.AccessToken;
					return true;
				}
				RegisterEntry refreshedCurrent;
				if (current.RefreshToken.Length > 0 && TryRefresh(resolvedId, current.RefreshToken, out refreshedCurrent)) {
					GetRegisterSlot(resolvedId).Value = refreshedCurrent;
					StoreSuppliedTokens(resolvedId, refreshedCurrent);
					accessToken = refreshedCurrent.AccessToken;
					return true;
				}
			}

			//2. self-obtained token (process-wide)
			RegisterEntry supplied;
			lock (_SyncRoot) {
				_SuppliedTokens.TryGetValue(resolvedId, out supplied);
			}

			//3. persistence
			if (supplied == null) {
				supplied = LoadPersistedTokens(resolvedId);
			}

			if (supplied != null) {
				if (!forceRefresh && supplied.AccessToken.Length > 0 && !IsExpiring(supplied)) {
					accessToken = supplied.AccessToken;
					return true;
				}
				RegisterEntry refreshed;
				if (supplied.RefreshToken.Length > 0 && TryRefresh(resolvedId, supplied.RefreshToken, out refreshed)) {
					StoreSuppliedTokens(resolvedId, refreshed);
					accessToken = refreshed.AccessToken;
					return true;
				}
			}

			//4. issuer
			RegisterEntry issued;
			if (TryIssue(resolvedId, out issued)) {
				StoreSuppliedTokens(resolvedId, issued);
				accessToken = issued.AccessToken;
				return true;
			}

			return false;
		}

		/// <summary>
		/// Removes the self-obtained tokens of a token source (memory and persistence), for example after a logout.
		/// </summary>
		public static void DiscardSuppliedTokens(string tokenSourceId) {
			string resolvedId = NormalizeId(tokenSourceId);
			lock (_SyncRoot) {
				_SuppliedTokens.Remove(resolvedId);
			}
			foreach (PersistenceTarget target in GetPersistenceTargets(resolvedId)) {
				target.Provider.DeleteTokens(resolvedId, target.UserScope, target.CustomScope);
			}
		}

		private static bool IsExpiring(RegisterEntry entry) {
			if (entry.ExpiresUtc == DateTime.MaxValue) {
				return false;
			}
			return DateTime.UtcNow.AddSeconds(_RefreshSkewSeconds) >= entry.ExpiresUtc;
		}

		private static void StoreSuppliedTokens(string resolvedId, RegisterEntry entry) {
			lock (_SyncRoot) {
				_SuppliedTokens[resolvedId] = entry;
			}
			SavePersistedTokens(resolvedId, entry);
		}

		private static bool TryIssue(string resolvedId, out RegisterEntry entry) {
			entry = null;
			IAccessTokenIssuer issuer = GetIssuer(resolvedId);
			if (issuer == null) {
				return false;
			}
			TokenIssuingResult result;
			if (!issuer.TryRequestAccessToken(out result) || result == null || string.IsNullOrWhiteSpace(result.access_token)) {
				return false;
			}
			entry = CreateEntryFromResult(result, string.Empty);
			return true;
		}

		private static bool TryRefresh(string resolvedId, string refreshToken, out RegisterEntry entry) {
			entry = null;
			TokenSourceRegistration registration;
			if (!TryGetRegistration(resolvedId, out registration) || registration.Config == null) {
				return false;
			}
			IOAuthOperationsProvider provider = GetOAuthOperationsProvider(registration);
			if (provider == null) {
				return false;
			}
			TokenIssuingResult result;
			if (!provider.TryGetAccessTokenViaOAuthRefreshToken(refreshToken, registration.Config.ClientId, registration.Config.ClientSecret, out result)) {
				return false;
			}
			if (result == null || string.IsNullOrWhiteSpace(result.access_token)) {
				return false;
			}
			//if the server does not rotate the refresh token, the old one stays valid
			entry = CreateEntryFromResult(result, refreshToken);
			return true;
		}

		private static RegisterEntry CreateEntryFromResult(TokenIssuingResult result, string fallbackRefreshToken) {
			RegisterEntry entry = new RegisterEntry();
			entry.AccessToken = result.access_token;
			if (string.IsNullOrWhiteSpace(result.refresh_token)) {
				entry.RefreshToken = EmptyIfNull(fallbackRefreshToken);
			}
			else {
				entry.RefreshToken = result.refresh_token;
			}
			entry.IdToken = EmptyIfNull(result.id_token);
			if (result.expires_in > 0) {
				entry.ExpiresUtc = DateTime.UtcNow.AddSeconds(result.expires_in);
			}
			entry.Refreshable = true;
			return entry;
		}

		private static RegisterEntry LoadPersistedTokens(string resolvedId) {
			RegisterEntry entry = null;
			foreach (PersistenceTarget target in GetPersistenceTargets(resolvedId)) {
				PersistedTokenSet tokens;
				if (!target.Provider.TryLoadTokens(resolvedId, target.UserScope, target.CustomScope, out tokens)) {
					continue;
				}
				if (entry == null) {
					entry = new RegisterEntry();
					entry.Refreshable = true;
				}
				if (target.AccessToken && tokens.AccessToken.Length > 0) {
					entry.AccessToken = tokens.AccessToken;
					entry.ExpiresUtc = tokens.AccessTokenExpiresUtc;
				}
				if (target.RefreshToken && tokens.RefreshToken.Length > 0) {
					entry.RefreshToken = tokens.RefreshToken;
				}
				if (target.IdToken && tokens.IdToken.Length > 0) {
					entry.IdToken = tokens.IdToken;
				}
			}
			if (entry != null) {
				lock (_SyncRoot) {
					_SuppliedTokens[resolvedId] = entry;
				}
			}
			return entry;
		}

		private static void SavePersistedTokens(string resolvedId, RegisterEntry entry) {
			foreach (PersistenceTarget target in GetPersistenceTargets(resolvedId)) {
				PersistedTokenSet tokens = new PersistedTokenSet();
				if (target.AccessToken) {
					tokens.AccessToken = entry.AccessToken;
					tokens.AccessTokenExpiresUtc = entry.ExpiresUtc;
				}
				if (target.RefreshToken) {
					tokens.RefreshToken = entry.RefreshToken;
				}
				if (target.IdToken) {
					tokens.IdToken = entry.IdToken;
				}
				target.Provider.SaveTokens(resolvedId, target.UserScope, target.CustomScope, tokens);
			}
		}

		#endregion

		#region " Lazy creation of issuer / introspector / OAuth operations provider "

		private static bool TryGetRegistration(string tokenSourceId, out TokenSourceRegistration registration) {
			lock (_SyncRoot) {
				return _Registrations.TryGetValue(NormalizeId(tokenSourceId), out registration);
			}
		}

		private static IAccessTokenIssuer GetIssuer(string resolvedId) {
			TokenSourceRegistration registration;
			if (!TryGetRegistration(resolvedId, out registration)) {
				return null;
			}
			lock (registration) {
				if (!registration.IssuerCreated) {
					registration.IssuerCreated = true;
					if (registration.Config != null) {
						try {
							registration.Issuer = IssuerFactory.CreateFromConfig(registration.Config);
						}
						catch (NotImplementedException ex) {
							//the issue mode is not supported (yet) -> this token source can only be used for validation
							DevLogger.LogError(ex);
							registration.Issuer = null;
						}
					}
				}
				return registration.Issuer;
			}
		}

		private static IAccessTokenIntrospector GetIntrospector(string resolvedId) {
			TokenSourceRegistration registration;
			if (!TryGetRegistration(resolvedId, out registration)) {
				return null;
			}
			lock (registration) {
				if (!registration.IntrospectorCreated) {
					registration.IntrospectorCreated = true;
					if (registration.Config != null) {
						try {
							registration.Introspector = IntrospectorFactory.CreateFromConfig(registration.Config);
						}
						catch (NotImplementedException ex) {
							//the validation mode is not supported (yet) -> fail closed (no introspector)
							DevLogger.LogError(ex);
							registration.Introspector = null;
						}
					}
				}
				return registration.Introspector;
			}
		}

		private static IOAuthOperationsProvider GetOAuthOperationsProvider(TokenSourceRegistration registration) {
			lock (registration) {
				if (!registration.OAuthOperationsProviderCreated) {
					registration.OAuthOperationsProviderCreated = true;
					AuthTokenConfig config = registration.Config;
					if (config != null && !string.IsNullOrWhiteSpace(config.ClientId) && !string.IsNullOrWhiteSpace(config.RetrieveEndpointUrl)) {
						GenericOAuthOperationsProvider provider = new GenericOAuthOperationsProvider();
						provider.SetConfigurationValue("token_endpoint", ResolvePlaceholderWithoutRequest(config.RetrieveEndpointUrl));
						registration.OAuthOperationsProvider = provider;
					}
				}
				return registration.OAuthOperationsProvider;
			}
		}

		#endregion

		#region " Hooks (wire-up) "

		/// <summary>
		/// Compatible 'DefaultAuthHeaderGetter' for the wire-up with 'UjmwClientConfiguration' (UJMW framework):
		/// 'UjmwClientConfiguration.DefaultAuthHeaderGetter = AccessTokenManager.GetAuthHeaderByContractType;'
		/// Returns 'Bearer ...' or null, if no token is required/available.
		/// </summary>
		public static string GetAuthHeaderByContractType(Type contractType) {
			string[] tokenSourceIds;
			if (!TryResolveTokenSourceIdsForContract(contractType, string.Empty, out tokenSourceIds) || tokenSourceIds.Length == 0) {
				return null;
			}
			string accessToken;
			if (TryGetActiveTokenForTokenSource(tokenSourceIds[0], false, out accessToken)) {
				return "Bearer " + accessToken;
			}
			return null;
		}

		/// <summary>
		/// Resolves the registered token sources for a contract (UC-2): legacy IAuthRequirementsProvider (if configured),
		/// AuthTokenSourceAttribute, API group name, plain interface name, 'default'.
		/// Returns false, if no token is required (anonymous).
		/// </summary>
		internal static bool TryResolveTokenSourceIdsForContract(Type contractType, string apiGroupName, out string[] tokenSourceIds) {
			List<string> chain = new List<string>();

			IAuthRequirementsProvider requirementsProvider = AccessTokenValidator.ConfiguredRequirementsProvider;
			if (requirementsProvider != null && contractType != null) {
				string providedTokenSourceId;
				string[] ignoredPermissions;
				if (!requirementsProvider.IsAuthtokenRequired(contractType, null, out providedTokenSourceId, out ignoredPermissions)) {
					tokenSourceIds = new string[] { };
					return false;
				}
				if (!string.IsNullOrEmpty(providedTokenSourceId)) {
					chain.Add(providedTokenSourceId);
				}
			}

			string[] logicalNames;
			if (!TryGetLogicalNamesForContract(contractType, apiGroupName, out logicalNames) || IsAnonymous(logicalNames)) {
				tokenSourceIds = new string[] { };
				return false;
			}
			chain.AddRange(logicalNames);

			tokenSourceIds = ResolveRegisteredTokenSourceIds(chain);
			return true;
		}

		/// <summary>
		/// Compatible 'RawTokenExposalMethod' for the wire-up via 'AccessTokenValidator.ConfigureTokenValidation'
		/// ('UseRawTokenExposal'). Pushes the validated incoming token into the register of the token source which has
		/// accepted it (never for non-relayable token sources).
		/// </summary>
		public static void PreserveIncommingToken(string token, MethodInfo targetContractMethod, string subject, string[] permittedScopes) {
			string tokenSourceId = TakeMatchedTokenSourceId();
			if (string.IsNullOrEmpty(tokenSourceId)) {
				return;
			}
			PushValidatedToken(tokenSourceId, token, subject, permittedScopes);
		}

		/// <summary>
		/// Compatible 'IntrospectorLookupMethod' for the wire-up via 'AccessTokenValidator.ConfigureTokenValidation'.
		/// A mapped JWT issuer (routing only, never trust) selects its token source 1:1; otherwise the token source is
		/// resolved via the chain. Several resolved token sources are combined into a composite introspector.
		/// Returns null (= unknown/untrusted origin), if no registered token source can be resolved.
		/// </summary>
		public static IAccessTokenIntrospector LookupForIntrospector(
			string tokenSourceIdentifier,
			Type contractType,
			MethodInfo targetContractMethod,
			string callingMachine,
			Func<string> tryReadJwtIssuerMethod
		) {
			SetMatchedTokenSourceId(null);

			//1. issuer routing (1:1)
			if (tryReadJwtIssuerMethod != null) {
				string issuer = tryReadJwtIssuerMethod.Invoke();
				if (!string.IsNullOrWhiteSpace(issuer)) {
					string mappedTokenSourceId = null;
					lock (_SyncRoot) {
						_TokenSourceIdsByIssuer.TryGetValue(issuer, out mappedTokenSourceId);
					}
					if (mappedTokenSourceId != null) {
						return CreateLookupResult(FilterRegistered(new string[] { mappedTokenSourceId }));
					}
				}
			}

			//2. resolution chain
			string[] tokenSourceIds;
			if (!string.IsNullOrEmpty(tokenSourceIdentifier)) {
				tokenSourceIds = ResolveRegisteredTokenSourceIds(new string[] { tokenSourceIdentifier });
			}
			else {
				string[] logicalNames;
				string apiGroupName = _CurrentApiGroupName;
				if (apiGroupName == null) {
					apiGroupName = string.Empty;
				}
				TryGetLogicalNamesForContract(contractType, apiGroupName, out logicalNames);
				tokenSourceIds = ResolveRegisteredTokenSourceIds(logicalNames);
			}
			return CreateLookupResult(tokenSourceIds);
		}

		/// <summary>
		/// Wraps the introspectors of the given token sources into a composite, which also reports the matched source.
		/// </summary>
		private static IAccessTokenIntrospector CreateLookupResult(string[] tokenSourceIds) {
			List<string> ids = new List<string>();
			List<IAccessTokenIntrospector> introspectors = new List<IAccessTokenIntrospector>();
			foreach (string tokenSourceId in tokenSourceIds) {
				IAccessTokenIntrospector introspector = GetIntrospector(tokenSourceId);
				if (introspector != null) {
					ids.Add(tokenSourceId);
					introspectors.Add(introspector);
				}
			}
			if (introspectors.Count == 0) {
				return null; //fail closed
			}
			return new CompositeAccessTokenIntrospector(ids.ToArray(), introspectors.ToArray());
		}

		#endregion

		#region " Claim helpers "

		private static string ReadSubject(Dictionary<string, object> claims) {
			object value;
			if (claims != null && claims.TryGetValue("sub", out value) && value != null) {
				return value.ToString();
			}
			return string.Empty;
		}

		private static string[] ReadScopes(Dictionary<string, object> claims) {
			object value;
			if (claims != null && claims.TryGetValue("scope", out value) && value != null) {
				return value.ToString().Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
			}
			return new string[] { };
		}

		private static DateTime ReadExpiry(Dictionary<string, object> claims) {
			object value;
			if (claims != null && claims.TryGetValue("exp", out value) && value != null) {
				long exp;
				if (long.TryParse(value.ToString(), out exp) && exp > 0) {
					return new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(exp);
				}
			}
			return DateTime.MaxValue;
		}

		private static string EmptyIfNull(string value) {
			if (value == null) {
				return string.Empty;
			}
			return value;
		}

		#endregion

	}

}
