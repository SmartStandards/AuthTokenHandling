# OAuth Discovery and Extended Authentication-Required Response

Status: implementation handoff; requirements agreed on 2026-10-19. No implementation is included.
Owner: SmartStandards/AuthTokenHandling.
Priority: maximum backward compatibility; additive changes with a narrowly scoped implementation.

## Motivation and intended outcome

Applications using AuthTokenHandling should be able to publish standard OAuth discovery metadata and reference it from their authentication-required responses with one ASP.NET Core convenience registration. This is a general authentication capability, useful beyond MCP.

The motivating integration is a generic MCP facade in SmartStandards/AiSupport. When a user adds its URL in ChatGPT or Claude, the client should discover the required authentication process and offer an interactive login. The client must not need to understand the authentication conventions of every underlying controller. Client capabilities and registration support still require real interoperability tests; a bare HTTP 401 does not universally trigger a browser login.

## Agreed design direction

1. Add an optional static property/hook to the shared token-validation system for an extended authentication-required response. Working terminology: AuthRequired / ExtendedAuthRequired; final public names remain an implementation decision.
2. Integrate it carefully at the existing central HTTP rejection mapping, especially AccessTokenValidator.TryValidateHttpAuthHeader.
3. With the property unset, preserve existing behavior exactly.
4. Add an ASP.NET Core extension that registers the protected-resource well-known endpoint AND automatically configures the shared property/hook to reference that endpoint.
5. The resulting configuration applies globally to callers using this AuthTokenHandling path in the same loaded static context. It does not automatically intercept unrelated middleware or third-party authentication handlers.
6. Keep discovery, challenge formatting and token validation separate from business services and from MCP.

The extension must establish both required service registrations and endpoint mapping through the host's supported startup lifecycle. The one-line convenience is the desired user experience; do not promise a particular IServiceCollection-only signature before confirming how endpoint registration is performed.

## Requirements

| ID | Requirement |
| --- | --- |
| BC-01 | Preserve existing public signatures, overloads, delegate compatibility and binary compatibility wherever possible. Do not add parameters to an existing callback signature. |
| BC-02 | Without opt-in, preserve status codes, messages, token validation, scope handling, anonymous-access behavior, caching and auditing. |
| BC-03 | Do not silently remap existing rejection statuses while introducing discovery. Missing privileges must not become an invitation to bypass authorization. |
| BC-04 | Existing UJMW AuthHeaderEvaluator wiring must continue to work without consumer changes. |
| DISC-01 | Publish OAuth Protected Resource Metadata according to RFC 9728, including the resource identifier and authorization_servers. |
| DISC-02 | Emit a WWW-Authenticate Bearer challenge with resource_metadata pointing to the public metadata URL. A response body or reason phrase alone is insufficient. |
| DISC-03 | Keep metadata publicly accessible, independent of the authentication it describes; avoid login/discovery loops. |
| DISC-04 | Use explicit, consistent public URLs behind reverse proxies and path bases. Support the relevant path-aware well-known rules; do not assume every resource is hosted at the domain root. |
| EXT-01 | Provide an optional shared static response configuration or hook, activated automatically by the ASP.NET Core discovery registration. |
| EXT-02 | Represent enough information for the HTTP adapter to write headers as well as status and optional message, without an ASP.NET Core dependency in the shared core. |
| EXT-03 | Preserve authorization decisions. Extending a challenge must never grant access. |
| EXT-04 | Keep registration deterministic and thread-safe. Define duplicate/conflicting registration behavior. Never store request-specific identity or credentials in the global property. |
| EXT-05 | Document the initial single-application/global-discovery assumption and the limitations of static state for multiple hosts/resources. A contextual hook can leave room for future selection without requiring a new framework now. |
| SCOPE-01 | Do not rewrite existing authentication infrastructure or implement the MCP facade in this change. |

## Protocol behavior

Example authentication-required response after opt-in:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://calendar.example.com/.well-known/oauth-protected-resource"
```

Example resource metadata:

```json
{
  "resource": "https://calendar.example.com/mcp",
  "authorization_servers": ["https://identity.example.com"],
  "scopes_supported": ["calendar:read", "calendar:write"]
}
```

These documents contain public configuration, never credentials or tokens. The resource server may refer to an external authorization server; enabling resource discovery must not require hosting an OAuth server locally.

Authorization-server metadata under RFC 8414 is a separate capability. Our later example may host both roles, but they must remain independently configurable. Do not advertise OpenID Connect discovery unless the implementation actually supports the advertised OIDC behavior.

## Current source observations and investigation points

Reviewed source baseline: d09cbcd84128290bcdb7d3ebafe135f6d85f5072. Re-read the current branch before implementing.

- AccessTokenValidator.cs contains TryValidateHttpAuthHeader overloads intentionally compatible with UJMW's AuthHeaderEvaluator. They return bool and mutate status/reason via ref parameters; they cannot directly carry response headers.
- Current mapping uses 401 for missing tokens and reasons containing "xpired"; other negative outcomes map to 403. This is existing behavior to preserve by default, not a recommendation for new protocol semantics.
- AccessTokenValidator.Setup.cs already uses static configuration and hooks. Follow existing conventions without changing unrelated validation behavior.
- EvaluateBearerTokenAttribute.cs calls this validator and emits a ContentResult on rejection. This is a concrete HTTP response integration point.
- UJMW's AuthHeaderInterceptor is an external consumer of the legacy callback. A core message change alone cannot make that adapter emit headers. Establish a backward-compatible header propagation seam; explicitly identify whether a small UJMW adapter change is required. Do not claim automatic coverage before verifying it.
- Existing core extension points include IAccessTokenIntrospector, requirement providers, per-contract/method introspector selection, auditing and scope visitation.
- MvcSupport contains multiple OAuth controller source variants. Its .projitems currently selects OAuth2Controller.Flow_*, StateBag, Helpers and Introspect_RFC7662 files; inspect compilation inputs rather than treating every .cs file as active.
- The expected repository skills were not found at the advertised .agents/skills paths during inspection. Follow any current repository instructions available in the implementation session.

Choose the smallest additive design after checking these seams. A new overload or response descriptor is a possible mechanism, not an agreed mandatory class structure. Do not use ambient mutable response state that could leak between concurrent requests.

## Ownership and later work

| Concern | Owning location |
| --- | --- |
| Shared challenge configuration, response abstraction and token integration | AuthTokenHandling core |
| Well-known HTTP endpoints and response writing | AuthTokenHandling.MvcSupport |
| General OAuth-server discovery, PKCE and code/refresh-flow improvements | AuthTokenHandling; separate follow-up scope |
| Generic MCP endpoint, API catalog projection and in-process controller dispatch | AiSupport ASP.NET Core integration |
| Independent CalDAV connector | Separate domain component; repository placement remains open |
| STRATO login validation and encrypted credential token strategy | Example composition, using reusable AuthTokenHandling extension points |

The future sample should accept STRATO credentials on its own login page, validate them through the CalDAV connector and issue OAuth tokens. Encrypted credential-bearing refresh tokens are an explicit experiment strategy, not the default for the framework. Access-token calls also need server-side access to the credentials. Key persistence, authenticated encryption, expiration, refresh rotation/reuse detection and revocation require explicit design before that follow-up is implemented.

PKCE/S256, resource binding and a client-registration method compatible with ChatGPT and Claude require separate verification. Basic optional S256 PKCE for the authorization-code flow is meanwhile built into the ASP.NET Core `OAuth2Controller` (see `oauth-server-pkce.md`); metadata advertisement and per-client enforcement are still open.

## Acceptance and implementation handoff

- With opt-in disabled, compare representative existing success and rejection responses and public API/delegate compatibility against the baseline.
- With opt-in enabled, verify the well-known document, public URL handling and actual WWW-Authenticate header on the supported HTTP validation paths.
- Verify a 403 permission denial remains a denial and is not blindly transformed into a login challenge.
- Verify discovery remains reachable before authentication.
- Exercise direct MVC and existing UJMW integration paths; document any required adapter extension.
- Check concurrent requests, application startup registration and static-state isolation in tests.
- Full login, refresh and URL-only onboarding in ChatGPT and Claude are later end-to-end acceptance checks once the OAuth sample exists. Discovery alone is not sufficient to claim these work.

Targeted tests and documentation are recommended; the user has not yet explicitly answered the earlier optional question about generating them. This handoff authorizes documentation of the design, not implementation or broad refactoring. Follow the repository's build targets and shared-project inclusion rules when implementation begins. Do not modify generated changelog/version files as part of this handoff.

## References

- [RFC 9728: OAuth 2.0 Protected Resource Metadata](https://www.rfc-editor.org/rfc/rfc9728.html)
- [RFC 8414: OAuth 2.0 Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414.html)
- [RFC 6750: Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750.html)
- [OpenAI MCP authentication guidance](https://developers.openai.com/plugins/build/auth)
- [Claude custom remote connectors](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp)
