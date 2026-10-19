---
name: auth-token-handling
description: Normative desired-state reference for SmartStandards AccessTokenHandling. Use when generating, reviewing, integrating or porting code that issues, obtains, caches, validates or forwards access tokens within the SmartStandards ecosystem.
---

# AccessTokenHandling – Agent Skill & Interoperability Guide

**Version:** 1.0  
**Status:** Desired State / Normative Skill Reference  
**Primary audience:** AI agents and developers generating, reviewing, integrating, or porting SmartStandards AccessTokenHandling usage  
**Maintenance model:** Incremental, Git-managed; keep structure stable after this initial V1

---

## 1. Purpose and Required Agent Capabilities

This document defines the desired-state understanding of **SmartStandards AccessTokenHandling** required for AI agents and developers to use the framework correctly inside the SmartStandards ecosystem and to reproduce its semantics in other technology stacks where useful.

AccessTokenHandling is not intended to be presented as a universal replacement for all authentication frameworks. Its particular value is its role as a **lightweight authentication and authorization bridge inside a broader SmartStandards ecosystem**, especially where communication, persistence, UI, self-contained microservice hosting, legacy integration, or cross-stack interoperability need to compose without introducing a large external authentication infrastructure.

An agent trained from this document MUST be able to operate at three usage levels.

### 1.1 Level A – Native .NET framework usage

The agent MUST be able to generate correct .NET integration code using the existing AccessTokenHandling framework, including:

- configuring incoming access-token validation,
- selecting and configuring `IAccessTokenIntrospector` implementations,
- selecting and configuring `IAccessTokenIssuer` implementations,
- using `AuthTokenConfig`,
- using `IssuerFactory` and `IntrospectorFactory`,
- configuring requirements/policy providers,
- configuring scope-prefix evaluation,
- configuring caching,
- configuring anonymous access when explicitly required,
- configuring auditing,
- using `RawTokenExposal` for its intended purpose,
- integrating with UJMW for incoming and outgoing authorization handling,
- understanding optional OAuth server capabilities,
- understanding the separation between token acquisition, validation, authorization, and propagation.

For native .NET usage, the agent SHOULD use the framework abstractions rather than replacing them with ad-hoc token parsing or duplicated OAuth/JWT logic.

### 1.2 Level B – Vendor and integration code

The agent MUST be able to extend the framework for external identity systems and heterogeneous environments.

Typical tasks include:

- implementing a new `IAccessTokenIntrospector`,
- implementing a new `IAccessTokenIssuer`,
- implementing or configuring an `IOAuthOperationsProvider`,
- implementing an `IAuthRequirementsProvider`,
- mapping foreign or legacy token claims to trusted local semantics,
- routing different token origins to different introspectors,
- integrating new OAuth providers,
- creating environment-specific adapters while preserving the framework's core semantic boundaries.

At this level, source implementations are evidence of supported patterns, but the agent MUST distinguish stable framework concepts from incidental or legacy implementation details.

### 1.3 Level C – Lightweight implementation in another stack

If another stack such as PHP, JavaScript, TypeScript, Java, Python, Go, or WordPress must interoperate with a SmartStandards solution, the agent SHOULD be able to build a **smaller, idiomatic runtime** that reproduces the relevant AccessTokenHandling semantics.

The foreign implementation does **not** need to reproduce the .NET class hierarchy.

It SHOULD, however, preserve compatibility at the `AuthTokenConfig` level as far as practical:

- same configuration field names,
- same mode names,
- same field semantics,
- same distinction between issuing and validation,
- same relevant OAuth/JWT behavior,
- same token-result semantics,
- same fail-closed expectations.

The agent SHOULD implement only the modes actually required by the target scenario, but structure the implementation so additional modes can be added later without redefining the configuration language.

### 1.4 Scope boundary

This is primarily a **usage, integration, interoperability, and desired-architecture skill**.

It is not:

- a general OAuth textbook,
- a complete ASP.NET Core authentication manual,
- a replacement for standards such as OAuth 2.0, OIDC, JWT, or RFC 7662,
- a full SmartAmbience guide,
- a full UJMW guide,
- a framework-maintainer manual for every legacy branch.

Implementation details are included only where they clarify observable semantics, extension points, interoperability, or desired behavior.

---

## 2. Executive Mental Model

AccessTokenHandling should be understood as a small set of cooperating responsibilities rather than one monolithic authentication component.

```text
                         AuthTokenConfig
                              │
                ┌─────────────┴─────────────┐
                │                           │
                ▼                           ▼
         IssuerFactory               IntrospectorFactory
                │                           │
                ▼                           ▼
      IAccessTokenIssuer        IAccessTokenIntrospector
                │                           │
                │                           │
                └──────────┬────────────────┘
                           │
                           ▼
                 token / claims / scopes
                           │
            ┌──────────────┴──────────────┐
            │                             │
            ▼                             ▼
  IAuthRequirementsProvider       AccessTokenValidator
            │                             │
            └──────────────┬──────────────┘
                           │
                           ▼
                   access decision
```

A useful high-level decomposition is:

```text
Acquisition / Issuing
    "How do I obtain or create a token?"

Validation / Introspection
    "Is this token active and what claims does it represent?"

Requirements / Policy
    "Does this call require authentication and which abilities/scopes are required?"

Authorization
    "Do the token's effective scopes satisfy the call requirements?"

Current interaction context
    "Which already validated token/subject/scopes represent the current interaction?"

Transport integration
    "How is the token received or sent, e.g. Authorization: Bearer ...?"
```

The framework deliberately separates these concerns.

---

## 3. Architectural Positioning

### 3.1 Role inside the SmartStandards ecosystem

AccessTokenHandling fills an architectural gap between other SmartStandards layers.

Typical neighboring problem domains include:

- RPC / communication, especially UJMW,
- persistence,
- UI layers,
- service discovery,
- microservice hosting,
- self-contained microservice + micro-UI solutions,
- infrastructure context,
- interoperability with old and new enterprise identity mechanisms.

Authentication and authorization are cross-cutting concerns that need to bridge these layers without leaking token mechanics into business contracts.

### 3.2 Not a universal authentication framework recommendation

Agents MUST NOT infer the rule:

> "Whenever authentication is needed, use AccessTokenHandling."

The framework's strongest justification is its integration with the surrounding SmartStandards ecosystem, its lightweight configuration model, its extension points, and its ability to bridge heterogeneous token mechanisms.

For a standalone project with no SmartStandards context, another standard platform solution may be more appropriate.

### 3.3 Lightweight control is intentional

A core motivation is the ability to retain direct control over:

- token sources,
- token issuing,
- token validation,
- introspector routing,
- claims,
- scopes,
- caching,
- auditing,
- cross-stack configuration,
- host integration.

This is especially useful for:

- prototypes,
- transitional architectures,
- small deployable services,
- microservices with embedded/micro UI,
- environments where multiple authentication generations coexist,
- systems that must bridge legacy and modern token sources.

### 3.4 Desired evolution

The framework SHOULD increasingly isolate environment-specific decisions behind inversion-of-control and policy abstractions rather than hard-coding them into contract attributes or static enterprise-specific branches.

---

## 4. Core Abstractions

### 4.1 `IAccessTokenIssuer`

Conceptual contract:

```csharp
public interface IAccessTokenIssuer {

  bool TryRequestAccessToken(out TokenIssuingResult result);

  bool TryRequestAccessToken(
    Dictionary<string, object> claimsToRequest,
    out TokenIssuingResult result
  );

}
```

Its responsibility is:

> Obtain or create a token.

It does not decide whether an incoming API call is authorized.

Possible implementations include:

- local JWT generation,
- OAuth client-credentials flow,
- browser-based OAuth code flow,
- other provider-specific or environment-specific acquisition strategies.

### 4.2 `IAccessTokenIntrospector`

Conceptual contract:

```csharp
public interface IAccessTokenIntrospector {

  void IntrospectAccessToken(
    string rawToken,
    out bool isActive,
    out Dictionary<string, object> claims
  );

}
```

Its responsibility is deliberately minimal:

```text
raw token
   ↓
active / inactive
   +
claims
```

An introspector SHOULD answer token semantics.

It SHOULD NOT become the place where request-specific auditing, endpoint requirements, current-call policy, or business invocation concerns are implemented.

### 4.3 `IAuthRequirementsProvider`

Conceptual contract:

```csharp
public interface IAuthRequirementsProvider {

  bool IsAuthtokenRequired(
    Type contractType,
    MethodInfo method,
    out string tokenSourceIdentifier,
    out string[] explicitelyRequiredApiPermissions
  );

}
```

Its responsibility is:

> Determine what the target invocation requires.

It answers:

- is a token required?
- which token source semantics apply?
- which explicit API permissions/abilities are required?

### 4.4 `AccessTokenValidator`

The validator is the **request-oriented orchestrator**.

It combines:

- requirements lookup,
- introspector selection,
- token validation,
- subject extraction,
- scope extraction,
- scope normalization,
- required-scope evaluation,
- optional anonymous access,
- result caching,
- raw-token exposure after success,
- auditing,
- HTTP-oriented result mapping.

### 4.5 `AccessTokenManager`

The manager is conceptually responsible for higher-level token lifecycle and current-interaction concerns, such as:

- current token context,
- token retrieval,
- token-source routing,
- outgoing auth-header production,
- potentially token storage and refresh behavior,
- connecting incoming validated token context to outgoing calls.

The exact implementation is still evolving.

Agents MUST therefore distinguish the **manager role** from historical implementation details.

### 4.6 `IOAuthOperationsProvider`

`IOAuthOperationsProvider` abstracts provider-facing OAuth behavior.

Conceptually:

```text
IAccessTokenIssuer
    = which issuing use case / flow?

IOAuthOperationsProvider
    = how do I talk to this OAuth provider?
```

This separation allows an issuer such as `ClientCredentialOAuthIssuer` to express the flow while the operations provider handles provider/HTTP specifics.

---

## 5. Authentication vs. Authorization

AccessTokenHandling touches both layers and agents MUST distinguish them.

### 5.1 Authentication / token validity

Questions include:

- Was a token supplied?
- Is it syntactically and cryptographically valid?
- Is it active?
- Has it expired?
- Is it not-yet-valid?
- Does the issuer/origin belong to a trusted token source?
- Which subject does it identify?

### 5.2 Authorization

Questions include:

- Which API permissions are required by the target operation?
- Which scopes are effectively permitted?
- Are all required scopes present?
- Are additional request-context permissions required?

### 5.3 Separation

The framework may orchestrate both, but an agent SHOULD retain the conceptual distinction.

Token validity alone does not imply permission to invoke every endpoint.

---

## 6. `AuthTokenConfig` as Portable Strategy Description

`AuthTokenConfig` is a central part of this skill.

It MUST initially be treated as a **stable cross-stack semantic contract**.

Future improvements to this configuration model SHOULD be maintained leadingly in this skill.

A critical design principle is:

> `AuthTokenConfig` is more than a .NET DTO. It is a portable description of how tokens may be issued and validated.

Foreign implementations SHOULD understand the same fields and mode names wherever practical.

### 6.1 Current issuing modes

Current well-known mode names:

```text
RAW_INPUT
HTTP_GET
LOCAL_BASICAUTH_GENERATION
LOCAL_JWT_GENERATION
OAUTH_IMPLICIT_FLOW
OAUTH_CIBA_CODEGRAND
OAUTH_CIBA_CODEGRAND_HTTPGETONLY
```

Not every named mode is equally mature or fully implemented in all current components.

Agents MUST NOT assume that the presence of a constant implies complete desired-state support.

### 6.2 Current validation modes

```text
IMPLICIT_WHEN_USED
LOCAL_JWT_VALIDATION
OAUTH_INTROSPECTION_ENDPOINT
OAUTH_INTROSPECTION_ENDPOINT_HTTPGETONLY
GITHUB_VALIDATION_ENDPOINT
```

Again, mode existence and current implementation maturity are distinct concerns.

### 6.3 Current `AuthTokenConfig` fields

#### Presentation metadata

```text
DisplayLabel
DisplayIconUrl
```

These describe UI-facing metadata and are not security decisions themselves.

#### Issuing

```text
IssueMode
RetrieveEndpointUrl
RetrieveEndpointAuthorization
LocalLogonNameToLower
LocalLogonNamePersistation
LocalLogonNameSyntax
LocalLogonNameInputLabel
LocalLogonPassInputLabel
LocalLogonSaltDisplayLabel
JwtExpMinutes
JwtSelfSignKey
JwtSelfSignAlg
ClientId
ClientSecret
AuthEndpointUrl
AdditionalAuthArgs
AdditionalRetrieveArgs
AuthEndpointRejectsIframe
```

#### Validation

```text
ValidationMode
ValidationOutcomeCacheMins
JwtValidationKey
ClaimValidationIgnoresCasing
ValidationEndpointUrl
validationEndpointAuthorization
```

#### Claims

```text
Claims : Dictionary<string,string>
```

Claims may participate in local issuing and validation-related adaptation depending on mode and runtime implementation.

### 6.4 Cross-stack rule

A PHP, JavaScript, or other foreign implementation MAY support only a subset of modes.

It SHOULD still:

- parse the shared config shape,
- reject unsupported modes explicitly,
- preserve names and semantics,
- keep extension points open for additional modes,
- avoid silently reinterpreting a known mode.

---

## 7. Factories as Reference Pattern

`IssuerFactory` and `IntrospectorFactory` are reference patterns for translating configuration into runtime strategy.

### 7.1 Issuer selection

Conceptually:

```text
AuthTokenConfig.IssueMode
        ↓
   IssuerFactory
        ↓
appropriate IAccessTokenIssuer
```

### 7.2 Introspector selection

```text
AuthTokenConfig.ValidationMode
        ↓
 IntrospectorFactory
        ↓
appropriate IAccessTokenIntrospector
```

### 7.3 Foreign-stack equivalent

A foreign implementation does not need classes literally named `IssuerFactory` or `IntrospectorFactory`.

It SHOULD preserve the deterministic idea:

```text
config mode
   → strategy resolution
      → initialized behavior
```

### 7.4 Agent rule

Agents SHOULD treat the factories as **reference architecture**, not as a requirement to reproduce all current source branches or current implementation quirks.

---

## 8. Token Issuing

### 8.1 `TokenIssuingResult`

A token acquisition or issuing operation returns a structure conceptually aligned with OAuth token responses.

Important fields include:

```text
access_token
scope
token_type
expires_in
id_token
refresh_token
error
error_description
```

`expires_in` is a duration in seconds, not a Unix timestamp.

### 8.2 Access token

The `access_token` is the token intended for API authorization.

When an HTTP bearer token is required, the normal transport form is:

```http
Authorization: Bearer <access_token>
```

### 8.3 ID token

`id_token` belongs to OIDC identity semantics.

Agents SHOULD treat it as optional identity-related information.

It is not the normal token to propagate in the API `Authorization: Bearer ...` header.

### 8.4 Refresh token

Refresh-token handling exists in the current model but is an area that still requires refinement.

V1 documents the status quo only.

Agents MUST NOT invent broader refresh-token propagation semantics from the presence of a `refresh_token` field.

### 8.5 Claim approval

Requested claims are not automatically trusted claims.

An issuer SHOULD apply a policy deciding which requested claims are:

- accepted,
- ignored,
- transformed,
- overridden,
- enforced locally.

Conceptually:

```text
requested claims
      ↓
claim approval / trusted policy
      ↓
claims to issue
      ↓
token creation / provider call
```

This is important for local JWT generation and for provider-facing flows.

---

## 9. Local JWT Issuing

A local JWT issuer demonstrates one issuing strategy.

Desired semantic steps:

```text
requested claims
   ↓
claim approval
   ↓
iat
exp
default/enforced claims
   ↓
sign JWT
   ↓
TokenIssuingResult
```

Typical claims include:

```text
iss
sub
aud
scope
iat
exp
jti
```

### 9.1 Defaults are implementation policy

Current implementations may provide defaults such as anonymous subject, self-signed issuer, empty audience, or generated `jti`.

Agents MUST distinguish these concrete defaults from universal JWT requirements.

### 9.2 Security rule

A client-provided requested claim MUST NOT gain authority merely because it was requested.

Authorization-relevant claims require trusted issuer-side policy.

---

## 10. OAuth Issuing

### 10.1 Client Credentials

`ClientCredentialOAuthIssuer` represents the headless OAuth client-credentials use case.

Conceptually:

```text
client id
client secret
requested scopes/claims
        ↓
ClientCredentialOAuthIssuer
        ↓
IOAuthOperationsProvider
        ↓
OAuth token endpoint
        ↓
TokenIssuingResult
```

This is appropriate for non-user-related service access when the authorization server supports the flow.

### 10.2 Authorization Code / browser flows

The framework contains support and design intent around browser-based OAuth authorization-code flows.

The exact runtime may differ by environment:

- embedded browser,
- external browser,
- server-hosted auth pages,
- delegated authorization,
- other interactive mechanisms.

Agents SHOULD think in terms of the standard OAuth flow rather than a particular UI implementation.

### 10.3 PKCE

PKCE is a **known required evolution area** and SHOULD be added for modern authorization-code scenarios, especially public clients.

V1 does not pretend that current code already provides a complete PKCE implementation.

### 10.4 Implicit flow

Implicit flow appears in historical/current interfaces but is deprecated in modern OAuth practice.

Agents SHOULD NOT select it for new development unless a compatibility requirement explicitly forces it.

---

## 11. Token Introspection and Validation

### 11.1 Minimal introspector semantics

An introspector returns:

```text
isActive
claims
```

Typical claims may include:

```text
scope
client_id
username
token_type
exp
iat
nbf
sub
aud
iss
jti
```

The framework should not require every introspector to return every claim.

### 11.2 Local JWT introspection

Desired semantic behavior:

```text
raw JWT
   ↓
signature validation
   ↓
exp check
   ↓
nbf check
   ↓
claims extraction
   ↓
optional trusted claim normalization
```

An invalid signature, expired token, or not-yet-valid token must result in inactive semantics.

### 11.3 Remote OAuth introspection

A remote introspector may call an RFC-7662-style endpoint.

Desired behavior:

```text
POST introspection endpoint
Content-Type: application/x-www-form-urlencoded

token=<access-token>
```

The standard response centers around:

```json
{
  "active": true
}
```

with optional claims.

### 11.4 Non-standard HTTP GET mode

A GET-based introspection mode exists for special compatibility cases.

It is not the preferred OAuth-standard mechanism and SHOULD NOT be selected for new implementations unless required by a specific environment.

---

## 12. Fail-Closed Principle

The desired default is **fail closed**.

If the system cannot establish a trusted positive validation result, access SHOULD be denied.

Examples:

- unknown token issuer/origin,
- no matching introspector,
- introspector selection failure,
- validation exception,
- technically failed remote introspection,
- missing required scopes,
- malformed token.

Anonymous access is the exception and must be configured deliberately.

### 12.1 Unknown origin

Returning no introspector for an unknown or untrusted origin is a valid way to express:

> This token source is not trusted for this request.

### 12.2 Technical failure vs. negative result

Agents MUST distinguish:

```text
successful introspection:
  active = false
```

from:

```text
introspection could not be performed reliably
```

These are not the same semantic result.

---

## 13. Validation Outcome and HTTP Mapping

The validator distinguishes multiple failure classes, including conceptually:

```text
token invalid
token from bad/unknown origin
token required but missing
required privileges missing
access granted
```

HTTP-facing integration commonly maps these to:

```text
401 Unauthorized
403 Forbidden
```

Exact host mapping may depend on context, but agents SHOULD preserve the distinction between:

- missing/expired authentication material,
- known token that lacks authorization,
- untrusted token origin,
- malformed/invalid token.

Externally returned reason phrases SHOULD avoid exposing excessive internal detail.

---

## 14. Scope Evaluation

### 14.1 Required scopes

After token introspection, the validator can compare permitted scopes with required API permissions.

Conceptually:

```text
required scopes ⊆ permitted scopes
```

All explicitly required scopes must be satisfied.

### 14.2 Scope prefix

The framework supports a configurable prefix for API permission scopes.

Current default behavior may use:

```text
API:
```

Real deployments may configure another prefix.

### 14.3 `ABL:` as inspiration

A real ecosystem pattern uses:

```text
ABL:SomeAbility
```

This is useful inspiration for capability-oriented scope naming.

It is **not** a universal desired-state requirement.

### 14.4 Dimensioned scopes

The framework can support patterns such as:

```text
ABL:PeopleManagement
Tenant:4711
Role:Admin
Zone:SYSTEM
```

This demonstrates that OAuth scope strings can also encode locally meaningful dimensions.

This is an optional pattern, not a mandatory universal schema.

### 14.5 Scope normalization

A trusted introspector adapter may normalize or enrich claims/scopes from foreign or legacy tokens.

This is legitimate only when the added authority is derived from a trusted local policy.

Agents MUST NOT grant privileges based merely on untrusted client-controlled values.

---

## 15. Requirements Discovery

### 15.1 Current .NET attribute-based model

Current .NET integrations can derive requirements from contract attributes.

Conceptually:

```text
contract metadata
    ↓
required?
token source?
required abilities?
```

This is a convenient .NET integration mechanism.

### 15.2 Desired architecture

For new development, the desired direction is broader inversion of control:

```text
IAuthRequirementsProvider
    ↑
attribute-based provider
configuration-based provider
environment policy provider
composite provider
custom provider
```

Attributes are therefore one possible policy source, not the fundamental framework model.

### 15.3 Opt-in and opt-out

An attribute-based provider may support both:

- opt-in authentication,
- opt-out authentication using a fallback token source.

Agents SHOULD preserve the intended default policy of the project rather than silently changing opt-in into opt-out or vice versa.

### 15.4 Composite requirements

A composite provider demonstrates that requirements can be combined from multiple sources.

The desired semantics of composition MUST be explicit.

Agents MUST NOT trust a misleading comment or incidental current implementation if provider-priority and aggregation semantics have not been defined by the target architecture.

---

## 16. `AccessTokenValidator.ConfigureTokenValidation`

This is the central native .NET setup pattern for incoming token validation.

Conceptually:

```csharp
AccessTokenValidator.ConfigureTokenValidation(
  requirementsProvider,
  introspectorLookupMethod,
  options => {
    // validator behavior
  }
);
```

The two required strategic inputs answer different questions:

```text
requirementsProvider
    = WHEN and WHAT authentication/authorization is required

introspectorLookupMethod
    = HOW the incoming token should be validated
```

This separation is a core design rule.

---

## 17. Validator Configuration Capabilities

### 17.1 Caching

The validator can cache introspection outcomes for a configurable lifetime.

This is especially useful when remote introspection would otherwise produce an additional network call for every incoming service invocation.

### 17.2 Negative-result caching

A negative result MAY be cached when:

- the introspection operation was technically successful, and
- the authoritative response says the token is inactive.

A technical failure SHOULD NOT be treated as an equivalent negative validation result for caching purposes.

Examples that should not be casually cached as "inactive":

- timeout,
- endpoint unavailable,
- transport exception,
- malformed response,
- introspector execution exception.

### 17.3 Scope-prefix configuration

The API permission prefix can be changed centrally.

This allows an ecosystem-specific scope namespace without changing the validator core.

### 17.4 Anonymous subject

Anonymous access can be enabled explicitly.

When configured, a synthetic subject may be used and a scope visitor can optionally supply scopes for that anonymous context.

Anonymous access MUST be a deliberate policy decision.

### 17.5 Scope visitor

The permitted-scope visitor can:

- inspect scopes,
- normalize them,
- add trusted local scopes,
- clear scopes,
- implement subject-specific black/white lists,
- project validated semantics into another security context.

It MUST NOT be used to turn untrusted input into authority without trusted policy.

### 17.6 Auditing hook

The auditing hook receives request/security context such as:

- target method,
- calling machine,
- validation outcome,
- subject,
- permitted scopes,
- required scopes,
- cache status,
- detailed reason.

Auditing is separate from token validation itself.

### 17.7 Raw token exposure

`UseRawTokenExposal` has a narrow intended purpose:

> After successful validation, expose the already validated raw token to the local interaction context so it can be reused by the surrounding application infrastructure.

It is NOT recommended as:

- a generic token logger,
- a debugging callback,
- a token inspection hook,
- a place to perform primary validation,
- a place to expose secrets to unrelated components.

The hook runs only after successful validation.

---

## 18. Introspector Routing

A system may support several token generations and origins simultaneously.

The introspector-selection delegate may use information such as:

- token-source identifier,
- contract type,
- target method,
- caller,
- JWT issuer read before full validation.

Conceptually:

```text
incoming token
    ↓
identify likely origin / required source
    ↓
select trusted introspector
    ↓
validate with source-specific semantics
```

This supports enterprise transition scenarios where old and new token technologies coexist.

### 18.1 Pre-reading JWT issuer

The validator may offer a callback that reads the unvalidated JWT issuer only to help select the introspector.

Agents MUST understand:

> Reading `iss` before signature validation is routing information, not trust.

The selected introspector must still perform the real validation.

### 18.2 Unknown issuer

If no trusted introspector can be selected, the result must fail closed.

---

## 19. Current Interaction Context

An already validated token may be stored in an ambient/current-call context.

Typical context values include:

- current access token,
- current subject,
- current effective scopes,
- potentially refresh token where explicitly managed.

The local storage mechanism may be AsyncLocal-like.

The semantic purpose is:

> represent the authentication context of the current interaction without polluting business method signatures.

### 19.1 Setting a current token

When a token is explicitly registered as current, it may be introspected directly first.

This SHOULD use the introspector when the intent is only:

- validate the token itself,
- extract subject,
- extract claims/scopes.

It SHOULD NOT invoke the full request-oriented validator if that would incorrectly trigger:

- request auditing,
- endpoint requirements,
- host-specific effects.

This distinction reinforces:

```text
Introspector = token analysis
Validator    = request/policy orchestration
Manager      = current token lifecycle/context
```

---

## 20. UJMW Integration

UJMW is an adjacent SmartStandards framework and is not fully documented here.

The important separation is:

```text
UJMW
  → receives/routes HTTP Authorization information

AccessTokenHandling
  → validates/interprets token semantics
```

### 20.1 Incoming calls

Canonical integration:

```csharp
UjmwHostConfiguration.AuthHeaderEvaluator =
  AccessTokenValidator.TryValidateHttpAuthHeader;
```

This lets UJMW supply:

- raw Authorization header,
- contract type,
- target method,
- caller information,

while AccessTokenHandling decides whether the call is authenticated and authorized.

### 20.2 Outgoing calls

Canonical integration:

```csharp
UjmwClientConfiguration.DefaultAuthHeaderGetter =
  AccessTokenManager.GetAuthHeaderByContractType;
```

The UJMW client can then obtain an outgoing auth header from AccessTokenHandling.

### 20.3 Business-layer rule

Authorization tokens SHOULD NOT become ordinary business method parameters.

### 20.4 No ad-hoc parsing

When UJMW and AccessTokenHandling are both present, agents SHOULD NOT add token parsing to each UJMW service method.

---

## 21. Multi-Hop Token Propagation

Multi-hop propagation is an optional/inspirational capability, not a deeply normative core feature of this V1.

Conceptually:

```text
Service A receives token
    ↓
validate
    ↓
store as current interaction token
    ↓
Service A calls Service B
    ↓
outgoing auth-header getter uses current token
    ↓
Authorization: Bearer ...
    ↓
Service B validates again
```

The idea resembles ambient context flow, but the transport channel is deliberately different.

### 21.1 Dedicated auth transport

The token is transported via:

```http
Authorization: Bearer ...
```

It SHOULD NOT be duplicated into a generic SmartAmbience/UJMW sidechannel merely because other ambient values use sidechannels.

### 21.2 Local ambient storage vs. network transport

An AsyncLocal-like field may hold the token locally.

Cross-boundary transport still occurs through the authorization header.

---

## 22. Optional Second-Stage Authorization

Some authorization decisions require request context that is only available after initial transport/context processing.

Conceptually:

```text
Stage 1
  token validity + general API ability

Stage 2
  context-sensitive / argument-sensitive authorization
```

Examples may include:

- tenant context,
- arguments marked as requiring a scope dimension,
- values derived from a request sidechannel.

This capability may use a pre-invocation hook such as UJMW's argument pre-evaluator.

It is an advanced extension pattern, not mandatory baseline behavior.

---

## 23. OAuth Operations Provider

`IOAuthOperationsProvider` provides a provider-facing abstraction for OAuth/OIDC operations.

Important categories include:

- authorization-code entry URL generation,
- code extraction,
- code exchange,
- client-credentials flow,
- refresh-token flow,
- subject/scope resolution,
- token validation,
- capability discovery.

### 23.1 Generic provider

A generic provider can be configured with URLs and behavior.

Typical configuration concerns include:

```text
authorization_endpoint
token_endpoint
introspection_endpoint
userinfo_endpoint
introspection_auth
iframe_allowed
auto_add_offline_access
provider_display_title
```

### 23.2 Provider-specific implementation

A provider-specific implementation may encapsulate provider quirks and fixed endpoints.

Agents SHOULD use provider-specific behavior where necessary but keep the shared interface semantics intact.

### 23.3 Foreign-stack rule

A foreign implementation MAY collapse issuer and operations-provider objects into simpler functions.

It SHOULD still preserve the conceptual separation between:

- which OAuth flow is being executed,
- provider-specific HTTP behavior.

---

## 24. Optional ASP.NET Core OAuth Server

The framework includes an optional ASP.NET Core OAuth-server capability.

This is an additional feature, not the primary core of AccessTokenHandling.

### 24.1 Architectural value

The most important design feature is the separation:

```text
ASP.NET Core OAuth controller
          ↓
       IOAuthService
          ↓
custom environment/domain implementation
```

The controller can implement generic protocol/HTTP behavior while the actual authentication and token policy remain behind `IOAuthService`.

### 24.2 Typical endpoints

The server capability may provide endpoints such as:

```text
/oauth2/authorize
/oauth2/token
/oauth2/introspect
```

### 24.3 `IOAuthService`

The application-specific service can provide responsibilities such as:

- authenticate credentials,
- create/manage session identifiers,
- determine available scopes,
- validate client applications,
- create tokens,
- create authorization codes,
- redeem authorization codes,
- create follow-up tokens,
- introspect access tokens.

### 24.4 Authentication and consent phases

The authorization flow can separate:

```text
Authentication phase
    → establish identity/session

Authorization/consent phase
    → select/grant scopes
```

### 24.5 Supported token endpoint grants

Current server behavior includes support for:

```text
authorization_code
client_credentials
refresh_token
```

### 24.6 Delegation

An extended server interface may support delegation to another OAuth authorization server.

This is an advanced optional capability.

### 24.7 Non-standard compatibility features

Historical/current implementations may include non-standard features such as:

- GET token retrieval,
- proprietary view modes,
- display response modes,
- older OTP naming,
- embedded presentation variants.

Agents MUST NOT generalize these into OAuth standards.

---

## 25. Cross-Stack Implementation Guide

### 25.1 Goal

A foreign runtime should reproduce the **semantics**, not the .NET class structure.

### 25.2 Minimum useful runtime

A small PHP/JavaScript implementation may consist of:

```text
read AuthTokenConfig
       │
       ├─ resolve issuing strategy
       │
       ├─ resolve validation strategy
       │
       ├─ obtain token on demand
       │
       ├─ validate/introspect token
       │
       └─ provide Authorization header
```

### 25.3 On-demand OAuth example

Given a config that describes an OAuth authorization-code setup, the foreign runtime should be able to derive:

- authorization endpoint,
- client ID,
- redirect behavior,
- requested scopes,
- token endpoint,
- provider-specific additional arguments,
- token-result fields.

It may then launch the appropriate interactive OAuth flow and preserve the resulting access token.

### 25.4 Local JWT validation example

Given:

```text
ValidationMode = LOCAL_JWT_VALIDATION
JwtValidationKey = ...
```

the runtime should be able to:

- parse the key representation,
- validate signature,
- validate relevant time claims,
- extract claims,
- report active/inactive.

### 25.5 Remote introspection example

Given:

```text
ValidationMode = OAUTH_INTROSPECTION_ENDPOINT
ValidationEndpointUrl = ...
validationEndpointAuthorization = ...
```

the runtime should be able to:

- call the configured endpoint,
- pass the token,
- evaluate `active`,
- consume returned claims,
- fail closed on technical inability to establish a valid result.

### 25.6 Unsupported modes

If a foreign runtime only implements a subset, it MUST clearly reject unsupported configured modes.

It MUST NOT silently fall back to a different security strategy.

---

## 26. Deterministic Agent Reasoning

When an agent encounters AccessTokenHandling configuration or usage, it SHOULD reason in this order.

### 26.1 Incoming request

```text
1. Determine whether authentication is required.
2. Determine token-source semantics.
3. Obtain raw token from host transport.
4. Select trusted introspector.
5. Validate token.
6. Extract subject and scopes.
7. Apply trusted scope normalization.
8. Compare required permissions.
9. Fail closed if unresolved.
10. Audit if configured.
11. Only after success, optionally expose raw token to current interaction context.
```

### 26.2 Outgoing request

```text
1. Determine target contract/token-source requirements.
2. Prefer an already appropriate current access token if policy permits.
3. Otherwise obtain/issue a token using the configured strategy.
4. Build the Authorization header.
5. Send access token through the dedicated auth channel.
```

### 26.3 Config-driven runtime

```text
1. Read AuthTokenConfig.
2. Resolve IssueMode.
3. Resolve ValidationMode.
4. Initialize only required strategies.
5. Preserve config semantics.
6. Reject unsupported modes explicitly.
```

---

## 27. Security Rules for Agents

### 27.1 MUST

An agent MUST:

- fail closed by default,
- distinguish access-token validation from authorization,
- distinguish introspection failure from `active=false`,
- treat pre-read JWT claims as untrusted until validation,
- treat requested claims as untrusted until approved,
- preserve `AuthTokenConfig` semantics,
- use access tokens for API bearer authorization,
- keep token mechanics out of business method signatures,
- avoid leaking full tokens into logs,
- use trusted local policy when enriching scopes/claims,
- use the framework's extension points instead of ad-hoc token parsing when available.

### 27.2 SHOULD

An agent SHOULD:

- use `ConfigureTokenValidation` as the native incoming-validation baseline,
- use factories/config strategy resolution,
- use a dedicated `IAuthRequirementsProvider`,
- keep attribute-based requirements replaceable by IoC/policy mechanisms,
- cache remote introspection results carefully,
- use short caching lifetimes where revocation sensitivity matters,
- keep OAuth provider peculiarities behind `IOAuthOperationsProvider`,
- keep raw-token exposure narrowly scoped to current-interaction propagation.

### 27.3 MUST NOT

An agent MUST NOT:

- treat every active token as authorized for every API,
- trust an issuer claim before signature/authority validation,
- add scopes merely because a caller requested them,
- cache technical introspection failures as authoritative inactive results,
- use `RawTokenExposal` as a token logging hook,
- propagate access tokens through generic sidechannels when the Authorization header is the appropriate transport,
- propagate `id_token` as if it were an API access token,
- silently reinterpret unknown `AuthTokenConfig` modes,
- reproduce historical enterprise hacks as desired-state architecture.

---

## 28. Common Failure Modes

### 28.1 Monolithic authentication logic

Wrong:

> Parse JWT, inspect scopes, log, cache, and mutate current context inside one service method.

Correct:

> Use introspector, validator, requirements provider, hooks, and manager responsibilities separately.

### 28.2 Treating the introspector as the whole security system

Wrong:

> `isActive == true` therefore access is granted.

Correct:

> Token validity is only one input; endpoint requirements and scopes must still be evaluated.

### 28.3 Trusting unvalidated JWT issuer

Wrong:

> `iss == "trusted"` therefore select privileges immediately.

Correct:

> `iss` may help select an introspector; trust only after real validation.

### 28.4 Caching outages as inactive tokens

Wrong:

> Introspection endpoint timed out → cache token as inactive.

Correct:

> Technical inability is not an authoritative token-state response.

### 28.5 Foreign implementation copies .NET structure

Wrong:

> Recreate every C# class, delegate, static field, and factory in PHP.

Correct:

> Preserve `AuthTokenConfig` and security semantics with an idiomatic minimal runtime.

### 28.6 Attribute lock-in

Wrong:

> Authentication requirements fundamentally belong to .NET attributes.

Correct:

> Attributes are one current policy source; desired architecture favors replaceable `IAuthRequirementsProvider` semantics.

### 28.7 Logging raw tokens

Wrong:

> Use raw-token exposure or auditing to log complete bearer tokens.

Correct:

> Keep secrets out of logs; use minimal masked probes only where operationally necessary.

---

## 29. Canonical Native .NET Examples

### 29.1 Minimal incoming validation setup

```csharp
AccessTokenValidator.ConfigureTokenValidation(
  requirementsProvider,
  SelectIntrospector,
  options => {
    options.ChangeCachingLifetime(2);
    options.UseAuditingHook(Audit);
  }
);
```

### 29.2 UJMW host integration

```csharp
UjmwHostConfiguration.AuthHeaderEvaluator =
  AccessTokenValidator.TryValidateHttpAuthHeader;
```

### 29.3 UJMW client integration

```csharp
UjmwClientConfiguration.DefaultAuthHeaderGetter =
  AccessTokenManager.GetAuthHeaderByContractType;
```

### 29.4 Scope prefix

```csharp
AccessTokenValidator.ConfigureTokenValidation(
  requirementsProvider,
  SelectIntrospector,
  options => {
    options.ChangeScopePrefixForApiPermissions("ABL:");
  }
);
```

`ABL:` is shown as an ecosystem example, not a universal requirement.

### 29.5 Remote introspection strategy

```csharp
IAccessTokenIntrospector introspector =
  new OAuthTokenIntrospectionEndpointCaller(
    introspectionUrl,
    introspectionAuthorizationHeader
  );
```

### 29.6 Local JWT validation strategy

```csharp
IAccessTokenIntrospector introspector =
  new LocalJwtIntrospector(validationKey);
```

### 29.7 Client-credentials issuing

```csharp
IOAuthOperationsProvider provider =
  new GenericOAuthOperationsProvider();

IAccessTokenIssuer issuer =
  new ClientCredentialOAuthIssuer(
    clientId,
    clientSecret,
    provider
  );

Dictionary<string, object> requestedClaims =
  new Dictionary<string, object>();

requestedClaims["scope"] = "SomeScope AnotherScope";

issuer.TryRequestAccessToken(
  requestedClaims,
  out TokenIssuingResult result
);
```

---

## 30. Canonical Foreign-Stack Pseudocode

### 30.1 Strategy resolution

```text
function createRuntime(config):
    issuer = resolveIssuer(config.IssueMode, config)
    introspector = resolveIntrospector(config.ValidationMode, config)

    return {
        issuer,
        introspector
    }
```

### 30.2 Local JWT validation

```text
function introspectLocalJwt(rawToken, config):
    if rawToken is empty:
        return inactive("missing token")

    if signature invalid using config.JwtValidationKey:
        return inactive("signature verification failed")

    claims = decode jwt

    if exp exists and now > exp:
        return inactive("expired")

    if nbf exists and now < nbf:
        return inactive("not yet valid")

    return active(claims)
```

### 30.3 Remote introspection

```text
function introspectRemote(rawToken, config):
    response = POST_FORM(
        config.ValidationEndpointUrl,
        {
            token: rawToken
        },
        authorization = config.validationEndpointAuthorization
    )

    if transport failed:
        return technical_failure

    body = parse_json(response)

    if body.active != true:
        return inactive(body)

    remove body.active
    return active(body)
```

### 30.4 Outgoing authorization header

```text
token = currentAccessToken

if token is missing:
    token = issuer.obtainTokenOnDemand()

if token exists:
    Authorization = "Bearer " + token
```

The actual decision whether a current token is appropriate for a target must follow target/token-source policy.

---

## 31. Optional Interoperability with Other Ecosystems

A future-compatible goal is to allow other ecosystems, including systems such as WordPress, to consume the same token configuration semantics.

Possible architecture:

```text
shared AuthTokenConfig
      │
      ├─ .NET runtime
      ├─ PHP runtime
      ├─ JavaScript runtime
      └─ other runtime
```

Each implementation may be locally idiomatic while interpreting the same configuration vocabulary.

This makes `AuthTokenConfig` an important interoperability boundary.

---

## 32. Known Evolution Areas / Next Steps

The following areas are intentionally identified for future improvement.

### 32.1 PKCE

Add proper PKCE support for modern authorization-code flows.

This is a high-priority evolution area.

### 32.2 Refresh-token model

Clarify and improve:

- storage,
- lifecycle,
- rotation,
- persistence,
- refresh timing,
- client vs. server responsibilities,
- security boundaries.

V1 does not define a new desired-state refresh-token architecture beyond current semantics.

### 32.3 Requirements inversion of control

Continue moving from contract-attribute-centric assumptions toward explicit replaceable policy providers.

### 32.4 `AuthTokenConfig` evolution

The config is initially frozen as the cross-stack semantic baseline.

Future revisions SHOULD improve it incrementally while preserving migration and interoperability awareness.

### 32.5 Modernize provider/HTTP implementations

Older WebClient-style and compatibility HTTP modes SHOULD progressively be replaced by cleaner modern implementations without changing the stable semantic contracts unnecessarily.

### 32.6 OAuth naming cleanup

Some current mode names are historically shaped and may not map perfectly to modern OAuth terminology.

Future revisions may improve naming carefully, with compatibility implications documented explicitly.

---

## 33. Migration and Adoption Guidance

This section is secondary to the desired state.

### 33.1 Ad-hoc token validation → framework validation

1. identify current token source,
2. implement/select an introspector,
3. implement/select requirements provider,
4. configure `AccessTokenValidator`,
5. move scope evaluation into validator policy,
6. move auditing into the auditing hook,
7. remove token parsing from business methods.

### 33.2 Hard-coded token source routing → policy/introspector routing

1. identify token-origin rules,
2. represent them in token-source metadata or policy,
3. implement introspector selection,
4. fail closed for unknown origins,
5. remove environment-specific branches from generic validator code.

### 33.3 .NET-only config → cross-stack config consumer

1. preserve `AuthTokenConfig`,
2. implement only required modes,
3. preserve field/mode semantics,
4. explicitly reject unsupported modes,
5. avoid copying unnecessary .NET architecture.

### 33.4 Existing ASP.NET Core authentication

Do not remove a working platform authentication layer merely to force AccessTokenHandling.

Use AccessTokenHandling where its ecosystem integration and lightweight control provide actual architectural value.

---

## 34. Source-Derived Invariants

The reviewed source and usage patterns establish the following important consumer-facing facts:

- `IAccessTokenIssuer` and `IAccessTokenIntrospector` are separate abstractions,
- `IAccessTokenIntrospector` returns activity plus claims,
- `IAuthRequirementsProvider` decides token necessity/source/required permissions,
- `AccessTokenValidator` combines requirements, introspection, scopes, caching, hooks, and auditing,
- `AuthTokenConfig` separates issuing configuration from validation configuration,
- `IssuerFactory` and `IntrospectorFactory` map config modes to runtime strategies,
- local JWT introspection validates signature and time claims,
- remote introspection can use RFC-7662-style behavior,
- remote GET introspection is compatibility behavior rather than preferred standard behavior,
- scope-prefix evaluation is configurable,
- anonymous access is explicitly configurable,
- permitted scopes can be normalized through a visitor,
- raw-token exposure happens only after successful validation,
- auditing is a distinct hook,
- UJMW can delegate incoming auth evaluation to AccessTokenHandling,
- UJMW can delegate outgoing auth-header retrieval to AccessTokenHandling,
- current token context can support optional multi-hop propagation,
- OAuth flow behavior is abstracted through `IOAuthOperationsProvider`,
- the optional ASP.NET Core OAuth server is decoupled from custom auth/token policy through `IOAuthService`,
- authorization-code, client-credentials, refresh-token, and introspection scenarios are present in the broader framework,
- the codebase contains compatibility and transition mechanisms that must not automatically be treated as desired-state architecture.

---

## 35. Maintenance Rules

After this initial V1, this document MUST be maintained incrementally.

1. Keep top-level section numbering and ordering stable whenever possible.
2. Modify existing sections instead of regenerating the document.
3. Add top-level sections only for genuinely new architectural dimensions.
4. Avoid cosmetic rewrites of unchanged text.
5. Preserve established terminology.
6. Distinguish:
   - desired-state rules,
   - current framework semantics,
   - optional capabilities,
   - compatibility behavior,
   - known evolution areas.
7. Keep `AuthTokenConfig` changes especially explicit because it is a cross-stack interoperability boundary.
8. When changing a mode name or property, document compatibility impact.
9. When adding a new issuing/validation mode, update:
   - `AuthTokenConfig`,
   - factory/strategy mapping,
   - native .NET guidance,
   - foreign-stack guidance where relevant.
10. Keep enterprise-specific implementation hacks out of normative examples.
11. Add canonical examples only when they illustrate stable reusable behavior.
12. Keep migration/process guidance secondary to the desired-state sections.

---

## 36. Reference Basis

This V1 is based on the reviewed AccessTokenHandling source and integration patterns covering, among others:

- `AccessTokenValidator`,
- `AccessTokenValidator.ConfigureTokenValidation`,
- validator hooks and options,
- `IAccessTokenIntrospector`,
- `LocalJwtIntrospector`,
- `OAuthTokenIntrospectionEndpointCaller`,
- `OAuthRemoteTokenIntrospector`,
- `IAuthRequirementsProvider`,
- `AttributeBasedAuthRequirementsProvider`,
- `CompositeAuthRequirementsProvider`,
- enterprise requirements-provider usage as design evidence,
- `IAccessTokenIssuer`,
- `LocalJwtIssuer`,
- `ClientCredentialOAuthIssuer`,
- `IssuerFactory`,
- `IntrospectorFactory`,
- `AuthTokenConfig`,
- `TokenIssuingResult`,
- `OAuthTokenIntrospectionResult`,
- `ScopeDescriptor`,
- `IOAuthOperationsProvider`,
- `GenericOAuthOperationsProvider`,
- provider-specific OAuth operations,
- `IOAuthService`,
- optional ASP.NET Core OAuth controllers,
- UJMW incoming/outgoing authentication integration,
- current-token and multi-hop usage patterns.

The implementation is evidence for the capabilities and semantics described here. Future versions SHOULD continue to distinguish deliberate architecture from incidental implementation detail.
