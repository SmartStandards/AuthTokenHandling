---
name: most-important-details-for-auth-token-handling
description: Project-specific implementation details, constraints and pitfalls for this repository (shared projects, multi-targeting net48/net8/net10, UJMW-exposable contracts, generated versioning artifacts, documentation layout). Use before changing code, project files or docs in this repository.
---

# Most important details for AuthTokenHandling

## Documentation layout

- `doc/AccessTokenManager-Refactoring.md` - authoritative plan and decision record for the AccessTokenManager refactoring
  (resolution, scopes, UC-1..UC-4, Cheap OAuth Server, compatibility table, acceptance criteria). Record every new
  design decision there.
- `doc/oauth-discovery-implementation-handoff.md`, `doc/oauth-server-pkce.md` - discovery (RFC 9728) and PKCE details.
- `doc/changelog.md`, `doc/versioninfo.json` - maintained ONLY manually by the maintainer; agents never edit them.
- `.nuspec` files are adjusted later by the maintainer (KVU) in the pipeline; agents never edit them.

## Code structure

- Source lives in **shared projects** (`*.shproj` + `*.projitems`) below `dotnet/src/<Project>/`. **Every new `.cs` file
  must be added to the matching `.projitems`** (`<Compile Include="$(MSBuildThisFileDirectory)…" />`), otherwise no
  target project compiles it. There are no valid `.projitems` files directly below `dotnet/` (stale copies were removed).
- Target projects per framework: `*.net48`, `*.net8.0`, `*.net10.0`. Changes must build for all of them.
- Compiler constants: `NET_FX` (net48, enables `[ServiceContract]`/`[OperationContract]` on contracts), `NET_CORE`, `NET_8_`, `NET_10_`.
- Namespaces: `Security.AccessTokenHandling` (core and MvcSupport), `Security.AccessTokenHandling.OAuth` (OAuth types).
- Do not add `InternalsVisibleTo` from core to MvcSupport: both contain copied logging extensions, which then become
  ambiguous (CS0121). Expose additive public APIs instead.
- Tests: MSTest, `dotnet/test/AuthTokenHandling.Tests.net10.0` (+ shared `AuthTokenHandling.Tests.projitems`).
  `AccessTokenManager` and `AccessTokenValidator` hold static state: use `[DoNotParallelize]`, `AccessTokenManager.Reset()`
  and re-configure the validator in `[TestInitialize]`/`[TestCleanup]`.

## Contract rules

- Contracts must stay **UJMW/WCF-transportable**: synchronous methods, simple DTOs with public properties, no callbacks.
- All OAuth endpoints belong in the official `OAuth2Controller`; discovery (`.well-known`) goes into a generic
  `OAuthDiscoverController` in the API group `.well-known`. Controllers depend only on `IOAuthService`; extend that
  interface so implementation-specific needs are delegated down into the implementation.

## Compatibility rules (central infrastructure - nothing may break)

- No breaking changes, except the (unreleased 6.0) `IOAuthService` PKCE + `resource` change.
- Only additive overloads; never change existing signatures or their semantics.
- A configured `IAuthRequirementsProvider` is always asked first and alone decides (legacy hosts unchanged).
- New behavior is opt-in: persistence, extended auth-required response / challenge, discovery, Cheap OAuth Server.
- Scope prefix symmetry: the configured prefix (default `API:`) is applied once everywhere (validation, `RequireScope`,
  Cheap OAuth grants and `scopes_supported`, challenge `scope`, Swagger). `RequireScope(scope, name, false)` is the
  explicit escape hatch for literal scopes.
- Challenge only on 401, never on 403. Status mapping in `TryValidateHttpAuthHeaderCore`: token missing/inactive
  (expired, revoked, malformed)/bad origin -> 401 + challenge; only `AccessDeniedMissingPrivileges` -> 403. Never map
  an inactive token to 403 - MCP clients (e.g. Copilot) only re-authenticate on 401. MvcSupport feeds it into the core via the slim BCL-only hook
  `AccessTokenValidator.ConfigureChallengeHeaders(Func<int, string[], KeyValuePair<string, string>[]>)` (status code,
  effective prefixed scopes); headers travel only as `ref KeyValuePair<string, string>[]`. The former
  `ExtendedAuthRequiredResponse*` / `HttpResponseHeader` types were removed (breaking vs. tag 5.1.2, accepted for 6.0) -
  never reintroduce a response carrier type; status and reason travel via `ref int` / `ref string`.

## Known state and pitfalls

- UC-4 resolver: `EndpointAuthResolver.ResolveEndpointAuthAsync` / `EndpointAuthInfo` in MvcSupport; UC-3
  (`EvaluateBearerTokenAttribute`) uses the same scheme/policy resolution.
- Composite introspection: a technical failure of an introspector must never be cached as an inactive result.

## Related skills

- `asp-net-core-development-guidelines` - SmartStandards-wide ASP.NET Core integration rules for explicit controller exposure and controlled endpoint registration (leading version in the `AI-SKILLS-SMART` consolidation repository, no local copy).
- `auth-token-handling` - Normative desired-state reference for AccessTokenHandling concepts and integration patterns.
