# AccessTokenManager Refactoring

Status: plan, agreed direction (2026-10-20). Not implemented yet.
Owner: SmartStandards/AuthTokenHandling. Affected repositories: AuthTokenHandling, UnifiedJsonMessageWrapper (UJMW),
SmartStandards.AspNetCoreTemplate, AiSupport, UniversalBFF.

## 1. Motivation

AccessTokenHandling is complete on the validation side: `AccessTokenValidator` selects an `IAccessTokenIntrospector`
per call via an introspector lookup. On the issuing side there is no counterpart yet: the former `AccessTokenManager`
is commented out, and `IssuerFactory` exists without a component that uses it per token source.

New use cases need this counterpart:

- A Swagger UI should know, per API group, which authentication it offers, without manual `securitySchemes` setup.
- An upstream instance such as the generic MCP facade (SmartStandards/AiSupport) needs to find out how the endpoints
  behind it want to be authenticated, and where a token can be obtained.
- Outgoing UJMW calls need tokens, taken from the current interaction, from a persistent store, or newly issued.

All of this must work without forcing any layer (business contracts, controllers, UJMW) to carry the proprietary
token source id. The only shared key is a plain string: a logical name (API group, contract, scheme or policy name)
that is resolved into token source ids.

## 2. Goals

- One central counterpart to the validator: the new `AccessTokenManager`.
- One configuration model per token source: `AuthTokenConfig` (as already used in UShell), covering issuing and
  validation. The manager creates issuers and introspectors through `IssuerFactory` and `IntrospectorFactory`.
- Resolution of token source ids works on strings only. No dependency on ASP.NET Core in the core resolution.
- Fail closed: anything that cannot be resolved and has no default is rejected.
- Existing wire-ups (`ConfigureTokenValidation`, UJMW `AuthHeaderEvaluator`, `EvaluateBearerTokenAttribute`) keep
  working.
- Long-term best practice: authentication runs through the regular ASP.NET Core pipeline (see 4.3), UJMW no longer
  breaks out of it.

## 3. Shared concepts (binding for all repositories)

### 3.1 Terms

| Term | Meaning |
| --- | --- |
| Token source id | Identifier of a token profile (one `AuthTokenConfig`). |
| Logical name | Any string that describes a group of endpoints: API group name, contract (interface) name, authentication scheme name, policy name. |
| Mapping | Explicit assignment of logical names to token source ids. Without a mapping, a logical name is used as token source id directly. |

### 3.2 Resolution

```csharp
// the heart: works with strings only
string[] AccessTokenManager.ResolveTokenSourceIds(string logicalGroupOrSchemaName);

// explicit mapping; without a mapping, the logical name itself is used as token source id
AccessTokenManager.MapTokenSourceId(string tokenSourceId, params string[] logicalGroupOrSchemaNames);

// equivalent to MapTokenSourceId(tokenSourceId, "default")
AccessTokenManager.SetDefaultTokenSourceId(string tokenSourceId);

// marks ONE logical name as anonymous (no token required); mandatory parameter, no params array:
// anonymous access is dangerous, every name must be written down explicitly (call it once per name)
AccessTokenManager.MapAnonymous(string logicalGroupOrSchemaName);

// requires a scope for ONE logical name, or for all calls if null; no params array (call it once per name)
AccessTokenManager.RequireScope(string scope, string logicalGroupOrSchemaName = null);
```

`MapTokenSourceId` keeps its `params` array (convenience needed frequently, not security-critical).

**Scope prefix symmetry (decided):** the configurable API permission prefix (default `API:`, changeable via
`ChangeScopePrefixForApiPermissions`, e.g. `ABL:` for abilities) must apply transparently and symmetrically
everywhere, as soon as it is configured:

- `RequireScope` applies it like `RequiredApiPermissionAttribute` does today (prefix added unless already present).
  Token scopes are compared literally (case-insensitive), as today.
- Everything that grants or advertises scopes derived from these requirements applies the same prefix: the Cheap
  OAuth Server (scopes returned by the login lambda or the account list get the prefix unless already present; the
  consent page shows them), `scopes_supported` in RFC 8414 / RFC 9728 metadata, the scope parameter of the
  `WWW-Authenticate` challenge, the Swagger security requirements.
- Example: prefix `API:`, `RequireScope("mcp")` -> the token must contain `API:mcp`; the Cheap OAuth Server grants
  `API:mcp` for a user configured with scope `mcp`.

**Token required? Which scopes? (decided, applies when the validator is wired via the manager):**

- If an `IAuthRequirementsProvider` is configured, it alone decides as before (no change for existing hosts).
- Otherwise a token is ALWAYS required (fail closed). Exceptions: `AuthTokenSourceAttribute(null)` or a logical name
  of the call registered via `MapAnonymous`.
- Logical names of a call: all names the resolution chain knows for it (API group name, contract name, scheme names),
  not only the one that resolved the token source.
- Anonymous wins: if any logical name of the call is anonymous, no token and no scope is required.
- Required scopes accumulate (AND): all `RequireScope` entries for "all" plus those for every logical name of the
  call, plus scopes from `RequiredApiPermissionAttribute` (legacy, still evaluated).

`IAuthRequirementsProvider` becomes a legacy technology. It stays for backward compatibility; new setups use mappings.

### 3.3 Empty string vs. `default`

- Empty string: "not known (yet) which token source applies". Wherever an empty value is allowed, it is passed on
  unchanged.
- `default`: an explicit decision "use the default token source". It is a magic id that can be used directly as key
  in the configuration (the token source defined under `default` is the default), so the default does not have to be
  declared everywhere. It replaces the former `00000000-0000-0000-0000-000000000000` (from the time ids were GUIDs);
  the GUID stays accepted as legacy alias.
- The empty string is turned into `default` as late as possible, only at the final lookup. `default` is resolved like
  any other logical name. The register and the configuration lookup use the resolved id, so all paths meet under the
  same key. If nothing is configured for `default`, the call is rejected (fail closed).

### 3.4 Several token sources per name

- Offering/issuing: a channel that can offer several authentication options (Swagger UI, UShell, interactive
  selection) offers all of them. Otherwise the first entry is the primary one.
- Validation: the token source is resolved 1:1 where possible (e.g. via the pre-read JWT issuer). If that is not
  possible, the introspectors of all resolved sources are called in mapping order; the token is accepted as soon as
  one of them reports it active. The matching source is remembered (claims, push into the register).
- Fail closed: if no introspector reports the token active, the call is rejected. A technical failure of one
  introspector must not be cached as an inactive result (existing rule).

### 3.5 `AuthTokenSourceAttribute` states

| Attribute | Meaning | Resolution chain |
| --- | --- | --- |
| missing | no statement | continues with the next step |
| `null` | explicitly anonymous (unchanged meaning: opt-out) | stops, no authentication |
| `""` | "not known" | continues (like missing) |

### 3.6 Use cases and resolution order

- **UC-1 Swagger UI:** `ResolveTokenSourceIds(apiGroupName)`.
- **UC-2 Validation via UJMW hook** (`TryValidateHttpAuthHeader` with contract type):
  1. `IAuthRequirementsProvider`, if configured.
  2. `AuthTokenSourceAttribute` on the contract type, if present (see 3.5).
  3. API group name passed by the new UJMW hook -> `ResolveTokenSourceIds(apiGroupName)`.
  4. Simple fallback for the legacy hook: plain interface name (`contractType.Name`) -> `ResolveTokenSourceIds(...)`.
     No duplication of UJMW's group-name conversion rule; anything else is done via `MapTokenSourceId`.
- **UC-3 Validation via `EvaluateBearerTokenAttribute`** (legacy): keeps determining the contract via the
  "ContractType" convention populated by UJMW; resolves the token source like UC-4.
- **UC-4 Upstream instance (MCP facade)**, per controller action:
  1. `AuthTokenSourceAttribute` on the controller, if present.
  2. API group name of the controller.
  3. Authentication scheme(s) from `[Authorize]` (`[Policy ->] AuthenticationScheme`, falling back to the default
     scheme); `ResolveTokenSourceIds(schemeName)` per scheme.
  Endpoint metadata is only read, never intercepted (the ASP.NET Core auth pipeline is a moving target).

## 4. Tasks: AuthTokenHandling

### 4.1 Core (`AuthTokenHandling`)

1. **New `AccessTokenManager`** (replaces the commented-out class).
   - Current-token register: internal-only `static Dictionary<string, AsyncLocal<string>>` per resolved token source
     id; two more registers for id token and refresh token.
   - Resolution API (3.2) including mappings and `default` handling (3.3).
   - Information functions: access to the `AuthTokenConfig` per token source id.
   - Static method usable as `IntrospectorLookupMethod` in `AccessTokenValidator.ConfigureTokenValidation`.
   - Static method for the Swagger bridge (see 6): `apiGroupName -> KeyValuePair<string, AuthTokenConfig>[]`.
   - UJMW client wire-up, keeping the established shape:
     `UjmwClientConfiguration.DefaultAuthHeaderGetter = AccessTokenManager.GetAuthHeaderByContractType;`
     For a contract, the token source id is derived first (thin step, using the validator's
     `IAuthRequirementsProvider`); the token comes from the register or the persistent store, otherwise from the
     configured issuer.
   - **Token refresh (outgoing side):** the manager keeps the expiry of every token it obtained itself (from
     `TokenIssuingResult.expires_in`). Before handing out a token for an outgoing call, it refreshes it if it is
     expired or expires within a short skew (e.g. 30 seconds) and a refresh token is available, using the refresh
     flow of the token source (`IOAuthOperationsProvider`). If the refresh fails, it falls back to the issuer. New
     tokens replace the old ones in the register and, if enabled, in the persistence. Tokens pushed by the validator
     (incoming tokens of a caller) are never refreshed by the manager; they are only relayed.
   - **Public register API** (known use case: UI entry points such as a desktop shell register tokens after an
     interactive login; services read subject and scopes of the current interaction):

     ```csharp
     // registers tokens as current for the interaction; the access token is checked ONLY with the introspector of the
     // token source (no validator: no requirements, no auditing, no caching); inactive token -> ArgumentException;
     // null/empty access token clears the entry (subject and scopes too)
     AccessTokenManager.SetCurrentToken(string tokenSourceId, string accessToken, string refreshToken = null, string idToken = null);

     string   AccessTokenManager.GetCurrentAccessToken(string tokenSourceId);
     string   AccessTokenManager.GetCurrentRefreshToken(string tokenSourceId);
     string   AccessTokenManager.GetCurrentIdToken(string tokenSourceId);
     bool     AccessTokenManager.HasCurrentAccessToken(string tokenSourceId);
     string   AccessTokenManager.GetCurrentSubject(string tokenSourceId);   // "" if unknown
     string[] AccessTokenManager.GetCurrentScopes(string tokenSourceId);    // never null; scopes as in the token (with prefix)
     ```

     `tokenSourceId` follows 3.3 (`""` is resolved to `default` at the final lookup). The register therefore keeps,
     per token source, access token, refresh token, id token, subject and scopes (`AsyncLocal`). The validator push
     fills subject and scopes from the validation result. Domain-specific helpers on top (e.g. reading scope
     dimensions like `Tenant:` or `Role:`) stay outside the framework and build on `GetCurrentScopes`.
   - **Issuer mapping** (known use case: several token generations with different issuers in one host):

     ```csharp
     // routes tokens whose pre-read 'iss' claim equals one of the issuers (OrdinalIgnoreCase) to this token source
     AccessTokenManager.MapIssuer(string tokenSourceId, params string[] issuers);
     ```

     In the manager's introspector lookup the pre-read issuer (routing information only, never trust) is checked
     first: a mapped issuer selects its token source 1:1, before the logical-name resolution. The selected
     introspector still performs the real validation. Unmapped or unreadable issuers continue with the normal chain
     (3.4, 3.6). Issuers are a separate namespace, not logical names (no collision with group names).
   - **Non-relayable token sources** (known use case: short-lived tokens issued on demand for one specific target must
     not become the "current" token of the interaction):

     ```csharp
     opt.DisableTokenRelay(string tokenSourceId);   // inside ConfigureTokenSupply
     ```

     For such a source, the validator does not push incoming tokens into the register, and the manager never relays
     them to outgoing calls. The external `RawTokenExposal` hook is not affected.
   - **Known use case, not part of the first iteration:** issuing a token per outgoing call whose requested scopes are
     derived from the requirements of the target (plus additional claims from a hook, e.g. a tenant). Such tokens must
     not be stored in the register. To be specified later.
2. **Setup `ConfigureTokenSupply`:**

   ```csharp
   AccessTokenManager.ConfigureTokenSupply((opt) => {
     // each call: "*" (all token sources) or one token source id
     opt.EnableAuthTokenPersistence(
       "*",
       userScope: true,          // true: per application runtime user, false: machine wide
       customScope: null,        // Func<string>, combinable with userScope; subfolder evaluated at runtime
       persistenceProvider: null // ITokenPersistenceProvider; null -> file based default
     );
     opt.EnableIdTokenPersistence(/* same parameters */);
     opt.EnableRefreshTokenPersistence(/* same parameters */);
     // uses IssuerFactory and IntrospectorFactory internally
     opt.ApplyFromConfiguration("my-token-source", authTokenConfig);
     opt.ApplyFromConfiguration(authTokenConfigsByTokenSourceId);
   });
   ```

3. **Token persistence (opt-in):** strategy interface `ITokenPersistenceProvider`; default implementation file based
   and encrypted under `%LOCALAPPDATA%/<ApplicationName>/ATH/[<customScope>/]<tokenSourceId>.json` (one file, all
   three tokens). Isolation is the responsibility of the setup caller: single-user applications use
   `userScope: true` without `customScope`; multi-user hosts return a caller-specific identifier from `customScope`
   and may use `userScope: false`.
   - `customScope` stays a parameterless `Func<string>`; the caller determines the identifier itself (e.g. from its
     own user model).
   - Helper: `AccessTokenManager.GetCurrentSubject(string tokenSourceId)` returns the subject of the validated token
     from the register (the register therefore also keeps the subject per token source, `AsyncLocal` like the tokens).
   - Safety rule: if `customScope` is set and returns `null` or `""`, nothing is persisted for this call. There is no
     fallback to a shared folder.
4. **Validator changes:**
   - `RawTokenExposal` stays as it is; additionally the validator always pushes the validated token into the
     manager's register (under the resolved / matching token source id).
   - Multi-source validation according to 3.4, implemented via a **composite introspector** (decided): when several
     token sources apply, the manager's introspector lookup returns a composite `IAccessTokenIntrospector` that tries
     the single introspectors in mapping order and remembers which source matched (used for the register push).
     The validator's signatures stay unchanged. The composite must carry thorough code comments explaining that it
     exists for backward compatibility of the single-introspector lookup and is a deliberate design, not a debt.
   - Logical names reach the validator through a new internal overload with an additional `apiGroupName`; the public
     methods stay unchanged and pass `""`.
   - The validation-outcome cache stays keyed by token; the required-scope comparison runs per call after the cache
     lookup, so that different requirements per logical name apply correctly (verify against the current code path
     before implementing).
   - Resolution chain UC-2 (3.6), including the new input "API group name" and the empty-string semantics.
   - Accept the new UJMW hook form (API group name in, response headers out). The existing
     `ExtendedAuthRequiredResponse` delivers the headers (e.g. `WWW-Authenticate`).
5. **New `TryValidateHttpAuthHeader` overload** with exactly the signature of UJMW's `AuthHeaderValidationMethod`
   (see 5.1). It calls the existing logic and appends `ExtendedAuthRequiredResponse.Headers` as
   `KeyValuePair<string, string>` to `responseHeaders`; headers preset by the caller are kept. On 403 no challenge
   headers are added (unchanged behavior).
6. **Auto-wiring of the challenge (EXT-01 of `oauth-discovery-implementation-handoff.md`, so far missing):**
   `AddWellKnownOAuthProtectedResourceEndpoint` automatically configures the `ExtendedAuthRequiredResponse` builder,
   so that a 401 carries `WWW-Authenticate: Bearer resource_metadata="..."`.
7. **Placeholder convention `{RequestBaseUrl}` (binding for both sides):**
   - The core cannot know the public base URL (static builder, no request, also built for net48). It therefore writes
     the literal placeholder `{RequestBaseUrl}` into header values, e.g.
     `Bearer resource_metadata="{RequestBaseUrl}/.well-known/oauth-protected-resource/mcp"`.
   - Every HTTP adapter that writes such headers MUST replace it with the base URL of its own request
     (`scheme://host[:port]` plus path base, without trailing slash): UJMW `AuthHeaderInterceptorAttribute`, UJMW WCF
     `DispatchMessageInspector`, `EvaluateBearerTokenAttribute`.
   - The core provides `ResolveRequestBaseUrlPlaceholder(string headerValue, string requestBaseUrl)` for the adapters
     of AuthTokenHandling. UJMW must not reference AuthTokenHandling and implements the identical rule itself
     (plain, case-sensitive replacement of every occurrence of `{RequestBaseUrl}`).
   - If an optional `PublicBaseUrl` is configured, the core writes it directly instead of the placeholder (proxies
     without forwarded headers).
   - No waiting for a first request, no static or ambient storage of base URLs.
   - The same placeholder is allowed in the URL fields of `AuthTokenConfig` (e.g. `AuthEndpointUrl`,
     `RetrieveEndpointUrl`, `ValidationEndpointUrl`), e.g. for the self-describing config of the Cheap OAuth Server.
     Everyone who hands a config to the outside replaces it with its own request: Swagger in
     `UseSwagger(c => c.PreSerializeFilters...)`, MCP facade / discovery per request, the endpoint delivering configs
     to UShell. Without a request (outgoing calls by an in-process issuer) and without `PublicBaseUrl`, a clear
     exception is thrown instead of using a broken URL. The documentation duty applies to these fields as well.
   - Documentation duty: the convention MUST be stated in the XML comments of every visible wire-up member involved
     (the `responseHeaders` parameter of the new delegate in all UJMW hosts, `SetAuthHeaderEvaluator`, the new
     `TryValidateHttpAuthHeader` overload, `ExtendedAuthRequiredResponse.Headers`, `ResolveRequestBaseUrlPlaceholder`,
     `PublicBaseUrl`), worded as an official convention both sides must comply with.

### 4.2 `AuthTokenHandling.MvcSupport`

1. `EvaluateBearerTokenAttribute`: resolve the token source like UC-4 (UC-3).
2. Endpoint-metadata resolver for UC-4 (reads `AuthTokenSourceAttribute`, API group, `[Authorize]` with policy and
   scheme via `IAuthorizationPolicyProvider` / `IAuthenticationSchemeProvider`). Used by the MCP facade.

### 4.3 `AuthTokenHandling.MvcSupport`: ASP.NET Core authentication handler (future best practice)

Target picture: hosts no longer populate UJMW's `AuthHeaderEvaluator` hook. UJMW controllers then go through the
regular ASP.NET Core authentication and authorization pipeline like any other controller.

- Extension method that plugs `AccessTokenValidator` into the ASP.NET Core authentication pipeline as an
  authentication scheme: as default scheme or as a selectable, named scheme.
- The handler validates the token (introspection via the manager) and builds the `ClaimsPrincipal` (subject, scopes).
- ASP.NET Core only enforces authentication where `[Authorize]` applies or a `FallbackPolicy` requires an
  authenticated user. The best practice must therefore include a `FallbackPolicy` (or UJMW's `AuthAttribute` option
  emitting `[Authorize]`).
- Scheme names become usable as token source ids (UC-4, step 3) without extra mapping.
- Scopes (decided):
  1. The handler puts the permitted scopes into the `ClaimsPrincipal`, one claim `scope` per value.
  2. The extension method additionally registers an `IAuthorizationHandler` that determines the logical names of the
     endpoint (as in UC-4), takes the required scopes from the manager (`RequireScope`, `RequiredApiPermissionAttribute`)
     and checks them against the claims, with the configured prefix (symmetry rule).
  3. It hooks into the endpoint's existing policy (e.g. the `FallbackPolicy`); no custom policy per scope is needed.
  4. Missing scope -> 403; missing or invalid token -> 401 with challenge (same semantics as today).

### 4.4 `AuthTokenHandling.MvcSupport`: Cheap OAuth Server

The mini OAuth server built in AiSupport (`MiniOAuth`) moves into AuthTokenHandling as a further `IOAuthService`
implementation, named **Cheap OAuth Server**.

**Positioning.** It is deliberately the small solution that works out of the box. It is NOT a competitor to the full
OAuth server of the UniversalBFF user-management module, which supports profiles and delegation (see 8). Design
assumption: exactly one credential source behind it, given as a simple lambda at initialization.

**Setup (sketch, names open):**

```csharp
services.AddCheapOAuthServer((o) => {

  // the one and only credential source - one of:
  o.ValidateLogin = (userName, password) => {
    // e.g. delegate to a backend check (CalDAV login in the AiSupport demo)
    return CheapOAuthLoginResult.Valid(scopes: new[] { "mcp" }, retainedSecret: password);
    // or CheapOAuthLoginResult.Invalid() / CheapOAuthLoginResult.BackendUnavailable()
  };
  o.UseFixedAccounts(("alice", "secret", new[] { "mcp" }), ("bob", "secret2", new[] { "mcp", "admin" }));
  o.UseAccountsFromConfiguration(config.GetSection("CheapOAuth:Accounts"));

  o.TokenSourceId = "default";   // id under which it registers itself in the AccessTokenManager
  o.PersistToDir = null;         // optional encrypted persistence (logins survive a restart)
  o.LoginPageTitle = "Login";
  o.AccessTokenLifetime = TimeSpan.FromMinutes(15);
  o.RefreshTokenLifetime = TimeSpan.FromDays(30);

});
```

**Capabilities (must be kept from the AiSupport sample):**

- Authorization code flow with mandatory PKCE (S256), one-time codes, rotating refresh tokens with reuse detection.
- Grant store with hashed tokens only; optional encrypted persistence (pluggable store, file based default).
- Login delegated to the lambda; result: valid (with scopes per user and an optional retained secret), invalid, or
  backend unavailable. The retained secret stays server-side (encrypted when persisted) and is available to the
  application through the grant of the current token, e.g. to pass credentials through to a backend
  ("wrapper token", CalDAV case). Access path: the current token from the manager's register -> grant lookup.
- Fixed account list (code or configuration) as the alternative to the lambda.
- RFC 8414 authorization-server metadata, RFC 7591 dynamic client registration (public clients), RFC 9728 protected
  resource metadata (registered automatically).
- Implicit flow, client credentials and Windows pass-through are not supported.

**Open dynamic client registration: protection (decided, first iteration):**

1. The consent page clearly shows the client name and the host of the redirect URI ("grant access for *Claude* ->
   *claude.ai*?"). No breaking change: `IAuthPageBuilder` already receives `clientId` and `redirectUri`. The Cheap OAuth
   Server registers its own `IAuthPageBuilder` (based on `DefaultAuthPageBuilder`) that looks up the client name in
   its client registry. If that turns out not to be possible without changing `IAuthPageBuilder`, showing the client
   name becomes a to-do and only the redirect host is shown.
2. Limit: at most N registrations (option, default 1000); unused registrations expire after 30 days, so that the
   persistence does not grow unbounded.
3. Option `AllowedRedirectHosts` (default empty = all allowed), e.g. `claude.ai`, `chatgpt.com`, `localhost`.

**Audience binding (RFC 8707, decided: minimal now):** the Cheap OAuth Server stores the `resource` parameter of the
authorize request in the grant, and its in-process introspector returns it as claim `aud`. No check yet (a later step
lets the validator reject tokens whose `aud` does not match the own resource). No optional additional interfaces
(not a preferred pattern). Instead, `resource` is added to `IOAuthService` within the same, not yet released major
version 6.0 as the PKCE change: `TryValidateSessionIdAndCreateRetrievalCode` gets `string resource` next to
`codeChallenge` (stored opaque with the code), and `RetrieveTokenByCode` returns it via `out string resource`. The
`OAuth2Controller` carries it through forms, redirects and the delegation `StateBag` exactly like the code challenge.
One breaking change instead of two; all implementations (including UniversalBFF) adapt once.

**Self-registration ("one line, everything works"):** on startup the server

1. registers itself as `IOAuthService` plus the OAuth controller,
2. registers an `AuthTokenConfig` describing itself in the `AccessTokenManager` under `TokenSourceId`
   (code flow, own authorize and token endpoints; how its introspection is expressed in the config is open detail 4
   in section 10),
3. with `TokenSourceId = "default"`, every endpoint without another resolution automatically uses it, so Swagger
   (via the delegate in 6), the MCP facade (UC-4) and validation work without further wire-ups,
4. pre-registers a built-in public client for the Swagger UI (Swagger cannot do dynamic client registration):
   client id `swagger-ui`, no secret, PKCE mandatory, redirect URI `{RequestBaseUrl}/docs/oauth2-redirect.html`
   (matches `RoutePrefix = "docs"` of the template; the placeholder is resolved with the base of the authorize
   request when validating). Option `SwaggerRedirectPath` (default `/docs/oauth2-redirect.html`, `null` disables the
   built-in client). The self-describing `AuthTokenConfig` carries `ClientId = "swagger-ui"`; the template passes it to
   `c.OAuthClientId(...)` and calls `c.OAuthUsePkce()`, but only on the new delegate path (the fallback stays
   unchanged).

All endpoints are provided as controllers that stay hidden from automatic discovery and are exposed only through the
extension method (`asp-net-core-development-guidelines`). `MapControllers()` is then the only mapping a host needs.

### 4.5 Scope limit: discovery stays global (decided)

The RFC 9728 discovery keeps its single, static, application-wide configuration (one set of authorization servers),
as documented in EXT-05 of `oauth-discovery-implementation-handoff.md`. This covers the Cheap OAuth Server and the
"one external IdP" case. Not excluded for the future: discovery per token source (metadata path and
`authorization_servers` derived from the `AuthTokenConfig` of the resolved source, including how an endpoint with
several sources is represented in one challenge). Not part of this plan.

## 5. Tasks: UJMW (UnifiedJsonMessageWrapper)

1. **`UjmwHostConfiguration.SetAuthHeaderEvaluator(...)`** with two overloads: new delegate (API group name in,
   response headers out) and legacy delegate.
   - Exact signature of the new delegate (decided):

     ```csharp
     public delegate bool AuthHeaderValidationMethod(
       string rawAuthHeader,
       Type contractType,
       MethodInfo targetContractMethod,
       string apiGroupName,                                // "" if no logical name can be determined
       string callingMachine,
       ref int httpReturnCode,
       ref string failedReason,
       ref KeyValuePair<string, string>[] responseHeaders  // initialized with an empty array, never null
     );
     ```

     `ref` (like the legacy delegate) so that a hook can see and pass on preset values (chaining).
   - The new delegate uses BCL types only (headers as `KeyValuePair<string, string>[]`, no header classes bound to a
     concrete technology). This keeps the established wiring without dependency:
     `UjmwHostConfiguration.SetAuthHeaderEvaluator(AccessTokenValidator.TryValidateHttpAuthHeader)` works because
     AuthTokenHandling provides a method with a matching signature, without referencing UJMW.
   - Internally exactly one field holds the evaluator, always in the new form; the legacy overload stores the legacy
     delegate wrapped.
   - The property `AuthHeaderEvaluator` becomes `[Obsolete]` (warning, not error) with the hint to use
     `SetAuthHeaderEvaluator`; its setter redirects to the legacy overload.
   - Its getter returns a reverse wrapper when a new-form evaluator was set (drops group name and headers), so that
     chained hooks keep working. Low priority, because the hook is no longer the recommended path (4.3).
   - No `...Ex` naming.
   - Applies to all hosts that carry their own `UjmwHostConfiguration`: `UJMW.DynamicController`,
     `UJMW.CommandLineFacade`, `UJMW.DynamicWcfHost`. All of them are wired up the same way. Where no API group exists,
     the hosts emulate the new form and derive a logical name instead:
     - WCF (`UJMW.DynamicWcfHost`): from the relative endpoint path of the service activation: trim leading and
       trailing `/`, remove a trailing `.svc` (case-insensitive), replace `/` with `-`; casing is preserved.
       Example: `/api/v1/Calendar.svc` -> `api-v1-Calendar`.
     - If no name can be derived, an empty string is passed ("not known", see 3.3).
     - `UJMW.CommandLineFacade`: defines the hook but never invokes it. Only the API surface is updated (new
       delegate, `SetAuthHeaderEvaluator`, `[Obsolete]` property), with an XML comment "currently without effect in
       this host". No evaluation is added.
2. **`AuthHeaderInterceptorAttribute`:** pass the API group name (known from `[ApiExplorerSettings(GroupName)]` of the
   emitted controller) and write the returned response headers, after replacing the placeholder `{RequestBaseUrl}`
   (see 4.1.7). The WCF `DispatchMessageInspector` does the same.
3. **Option (open):** emit `[AllowAnonymous]` on dynamic controllers whose authentication is done by the UJMW hook, so
   that a host-wide `FallbackPolicy` does not double-check them. Default must stay off (see 8).

Facts for reference: by default UJMW emits neither `[Authorize]` nor `[AllowAnonymous]`. `AuthAttribute` plus
`AuthAttributeConstructorParams` (default `null`) emit an attribute on every action. `EnableAuthHeaderEvaluatorHook`
(default `true`) adds the interceptor filter. The info site (GET) is always reachable without authentication.

## 6. Tasks: SmartStandards.AspNetCoreTemplate (`WebApiDependencies.CheapInitializer`)

1. New overload of `AddSwaggerGenSmartStandardsFlavored` accepting
   `Func<string apiGroupName, KeyValuePair<string, AuthTokenConfig>[]>` (token source id + resolved config).
   `AccessTokenManager` provides a matching static implementation. The package already references AuthTokenHandling.
   Keep the existing signature `(IServiceCollection, Func<string, string> oAuthUrlResolver = null)` unchanged and add
   the new one as a separate overload without optional parameters, to avoid ambiguous calls.
2. In the existing loop over API groups: one security definition per token source (scheme name = token source id)
   plus a document-specific requirement per group.
3. Mapping of `IssueMode`: OAuth code flow -> `authorizationCode` (`AuthEndpointUrl`, `RetrieveEndpointUrl` as token
   URL, PKCE); implicit flow -> `implicit` (legacy only); other modes -> Bearer input.
4. Fallback: without the delegate, the existing behavior stays (global `Bearer` definition plus OAuth from the config
   keys `OAuthClientIdForSwaggerUi`, `OAuthAuthorizeUrlForSwaggerUi`, `OAuthScopeExpressionForSwaggerUi`).
5. Known limit: Swagger UI supports only one global `OAuthClientId`; differing client ids per token source cannot be
   pre-filled.

## 7. Tasks: SmartStandards/AiSupport

Starting point of this whole plan: the MCP facade over UJMW and regular controllers, plus the CalDAV demo with its
own OAuth server. Details of the facade-side changes are discussed separately; agreed so far:

1. **Remove `MiniOAuth`** from `SmartStandards.AiSupport.AspNetCore` (uncommitted, never released) and the duplicated
   OAuth code of the demo (`Sample/OAuth`). Both are replaced by the Cheap OAuth Server (4.4).
2. **Rebuild the demo on the Cheap OAuth Server** so that it works exactly as before:
   - `ValidateLogin` delegates to the CalDAV credential check (real server or local mock) and retains the password as
     secret.
   - The CalDAV credential source reads the credentials from the grant of the current token (via the manager's
     register) instead of the demo's own grant store.
   - Login, PKCE, refresh, persistence and the MCP client onboarding (discovery, dynamic client registration) behave
     as today.
3. **MCP facade:** uses the UC-4 resolver (4.2) to find out how the published operations want to be authenticated,
   and the manager's information functions for discovery. The `RequestAuthenticator` seam stays.
4. The browser login (`McpBrowserLoginHandler`, a development tool acting as MCP client) stays in AiSupport.
4a. Use of the UC-4 resolver (decided):
   - Resolver API in `AuthTokenHandling.MvcSupport`:
     `Task<EndpointAuthInfo> ResolveEndpointAuthAsync(ActionDescriptor action, IServiceProvider services)` (async because
     ASP.NET Core policy resolution is async). `EndpointAuthInfo`: `IsAnonymous`, `LogicalNames[]`, `TokenSourceIds[]`,
     `RequiredScopes[]` (already prefixed).
   - The facade calls it once while building the tool catalog and caches the result.
   - Gate without a custom `RequestAuthenticator`: if all published tools are anonymous, there is no gate. Otherwise a
     token valid for at least one of the involved token sources is required; else 401 with challenge, whose `scope`
     contains the union of the required scopes. The exact scope check per tool stays with the target (the header is
     forwarded).
   - Way back: if a target rejects a tool call with 401, the facade returns a real HTTP 401 with `WWW-Authenticate` on
     the MCP request instead of `isError`. A 403 stays an `isError` result with a short message.
   - A custom `RequestAuthenticator` keeps precedence.
5. Package dependency (decided): `SmartStandards.AiSupport.AspNetCore` keeps its direct dependency on
   `SmartStandards.AuthTokenHandling` and `SmartStandards.AuthTokenHandling.MvcSupport` (needed for the UC-4 resolver
   and the manager's information functions). No add-on package. A stable AiSupport release follows the stable
   AuthTokenHandling 6.0 release (phase order, 8a).

## 8. Tasks: UniversalBFF

The full OAuth server ("the big solution") lives in the user-management module (`BffUserService` in
`UniversalBFF.OobModules.UserManagement`, implementing `IOAuthService` and `IOAuthServiceWithDelegation`).

1. Adapt to the breaking change of `IOAuthService` already made for PKCE (AuthTokenHandling commit `db5c0aa`, see
   `oauth-server-pkce.md`): new parameter `codeChallenge` in `TryValidateSessionIdAndCreateRetrievalCode`, new
   `out string codeChallenge` in `RetrieveTokenByCode`, plus `resource` / `out string resource` in the same methods
   (RFC 8707, see 4.4). Both values must be persisted with the code and returned unchanged, also across the
   delegation flow.
2. Later: register its token sources in the `AccessTokenManager` like the Cheap OAuth Server does.

## 8a. Implementation order and versioning

| Phase | Repository | Content | Depends on |
| --- | --- | --- | --- |
| 1 | UJMW | new delegate, `SetAuthHeaderEvaluator`, API group name, headers, placeholder (5) | - |
| 1 | AuthTokenHandling | manager, validator, EXT-01, placeholder, resolver, Cheap OAuth Server, `resource` (4.1, 4.2, 4.4) | - (parallel to UJMW) |
| 2 | AspNetCoreTemplate | Swagger delegate (6) | phase 1 (both) |
| 2 | UniversalBFF | `IOAuthService` adaptation (8) | AuthTokenHandling 6.0 |
| 3 | AiSupport | remove `MiniOAuth`, demo on the Cheap OAuth Server (7) | phases 1 and 2 |
| 4 | AuthTokenHandling | ASP.NET Core authentication handler (4.3) | later |

Versioning: version bumps are done exclusively and manually by the maintainer. Agents never edit `versioninfo.json`
or `changelog.md`; at the end of each phase they report which bump the repository needs (AuthTokenHandling: major,
already `6.0.0-develop`; UJMW and AspNetCoreTemplate: minor, additive only).

## 8b. Acceptance criteria

Always: all existing tests stay green; all target frameworks build (net48 / net8 / net10 where applicable).

- **UJMW:** legacy setter ends up wrapped in the single field; getter returns the reverse wrapper; the new delegate
  receives the API group name; response headers are written with `{RequestBaseUrl}` replaced; WCF name rule
  (`/api/v1/Calendar.svc` -> `api-v1-Calendar`).
- **AuthTokenHandling:** resolution with and without mapping, `default`, `""`, zero-GUID alias; `MapAnonymous` /
  `RequireScope` with prefixes `API:` and `ABL:`; composite introspector (order, fail closed, technical failure not
  cached); register push under the matching source; `SetCurrentToken` (introspector only, no auditing; inactive token
  throws; empty clears) and the getters for subject and scopes; `MapIssuer` routes before the logical-name chain and
  unmapped issuers fall through; `DisableTokenRelay` suppresses the register push and outgoing relay; persistence only on opt-in and isolated per scope; challenge on
  401, none on 403; the new `TryValidateHttpAuthHeader` overload is assignable to a delegate with identical signature
  (compile test with a local copy of the delegate); Cheap OAuth Server: PKCE mandatory, refresh rotation with reuse
  detection, DCR limits, Swagger client, `resource` -> `aud`, persistence survives a restart.
- **AspNetCoreTemplate:** one security scheme per token source per group; without the delegate the output is
  identical to today.
- **AiSupport:** demo end-to-end: discovery -> DCR -> login (CalDAV mock) -> token -> `tools/call` -> refresh; the
  facade's browser login keeps working.
- Interoperability tests with real MCP clients (Claude, ChatGPT) are done manually by the maintainer, not by agents.

## 9. Backward compatibility

| Change | Assessment |
| --- | --- |
| New `AccessTokenManager` | Additive; the old class is fully commented out, no name clash. |
| Validator push into the register | Additive, internal only. `RawTokenExposal` unchanged. |
| Multi-source validation, resolution chains | Only active when the manager's lookup is wired; existing `ConfigureTokenValidation` setups with their own lookup behave as before. |
| `AuthTokenSourceAttribute("")` = "not known" | No change for the legacy `AttributeBasedAuthRequirementsProvider` (it still returns `""` as id); the new semantics only apply in the manager's chain. |
| `default` instead of the zero GUID | The GUID stays accepted as alias. |
| `EvaluateBearerTokenAttribute` resolving like UC-4 | Behavior change risk: must keep `IAuthRequirementsProvider` as first step when configured, otherwise existing hosts could resolve differently. |
| UJMW `[Obsolete]` on `AuthHeaderEvaluator` | Binary compatible. Source level: new compiler warning; breaks builds only with `TreatWarningsAsErrors`. |
| UJMW single internal field with wrapping | Behavior of legacy delegates unchanged. |
| UJMW `[AllowAnonymous]` option | Non-breaking only if the default stays off. |
| Template: new Swagger overload | Additive; the existing method stays. Fallback keeps the config-key behavior. |
| ASP.NET Core authentication handler | Additive, opt-in. |
| Cheap OAuth Server | Additive, opt-in. |
| Removal of `MiniOAuth` in AiSupport | No break: never committed or released. |
| `IOAuthService` (PKCE + `resource`) | Breaking. PKCE was made before this plan (commit `db5c0aa`); `resource` is added in the same unreleased major version 6.0. All implementations, including UniversalBFF's `BffUserService`, adapt once (8.1). |

Result: the plan itself can be implemented without breaking changes, provided the three conditions above are kept
(requirements provider first in `EvaluateBearerTokenAttribute`, `[Obsolete]` as warning, `[AllowAnonymous]` option
off by default). The only breaking change in the landscape is the earlier PKCE change of `IOAuthService`.

## 10. Open details

1. (decided, see 4.1.3)
2. (decided, see 4.3)
3. Default of the UJMW `[AllowAnonymous]` option (5.3).
4. No setup overloads with explicit issuer or introspector instances (decided): token sources are always created from
   `AuthTokenConfig` through the factories; whatever is missing must be added to the configuration model and the
   factories later. Open consequence for the Cheap OAuth Server (4.4): its in-process introspection must then also be
   expressible via `AuthTokenConfig` / `IntrospectorFactory` (e.g. `OAUTH_INTROSPECTION_ENDPOINT` against its own
   `/oauth2/introspect`, or a factory-side shortcut for an in-process `IOAuthService`). To be decided before phase 1
   implements 4.4.
5. URLs in a self-describing `AuthTokenConfig`: the Cheap OAuth Server knows its public URL only per request (or via
   an optional `PublicBaseUrl`). Relative URLs in `AuthTokenConfig` would need to be resolved per request by the
   consumers (Swagger, MCP discovery).
6. Scopes of the Cheap OAuth Server: granted scopes = scopes returned for the user, intersected with the requested
   scopes (all of them if none were requested).
