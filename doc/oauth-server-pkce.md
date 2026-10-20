# PKCE Support in the Built-in OAuth Server

## Abstract and Motivation

AuthTokenHandling ships an optional, lightweight OAuth 2.0 authorization server for ASP.NET Core (`OAuth2Controller` in `AuthTokenHandling.MvcSupport`). The actual identity, session, scope and token logic lives behind the technology-neutral contract `IOAuthService` (in the core assembly `AuthTokenHandling`), which is implemented by the hosting solution (inversion of control).

The server supports **PKCE**

## Design Principles and Differentiation

- **Minimally invasive:** the whole PKCE protocol handling (parameter validation, S256 computation, transport through the login and consent pages, verification at the token endpoint, OAuth error responses) is implemented once in the controller. An `IOAuthService` implementation never needs to know anything about hashing or PKCE rules.
- **Persistence stays with the supplier:** the only thing an `IOAuthService` must do is to store the code challenge as an *opaque string* together with the code it creates, and to return it when the code is redeemed. This keeps multi-instance / load-balanced hosting possible, because the code storage is owned by the supplier anyway (no hidden in-memory state inside the controller).
- **Secure defaults:** only `S256` is accepted (`plain` is rejected), verification uses a constant-time comparison, and a downgrade (sending a `code_verifier` for a code that was issued without challenge) is rejected.
- **Backward compatible behavior:** PKCE is optional. Clients that do not send `code_challenge` work exactly as before.
- **ASP.NET Core only:** the PKCE logic lives in `AuthTokenHandling.MvcSupport` (net8/net10). The core assembly (also built for net48) only carries the two extended contract signatures.

Compared to large authorization-server frameworks (e.g. IdentityServer/Duende, OpenIddict) this implementation does not introduce stores, entities or configuration models: it extends two existing methods by one parameter each.

## Scope: Authorization-Code Flow only (not Implicit Flow)

PKCE is defined **only for the authorization-code flow** and cannot be applied to the implicit flow (`response_type=token`):

- PKCE works by proving, at the *token endpoint*, that the party redeeming the code is the party that started the authorization request (`code_verifier` must hash to the earlier `code_challenge`).
- In the implicit flow there is no code and no token-endpoint exchange: the access token is delivered directly in the redirect. There is no point in time where a verifier could be presented and checked.

The implicit flow is deprecated ([RFC 9700](https://www.rfc-editor.org/rfc/rfc9700), removed in OAuth 2.1) precisely because it cannot be protected this way. Public clients that currently use `response_type=token` should migrate to `response_type=code` together with PKCE. The same applies to `response_type=display` (a non-standard mode of this server, which shows the token on a page).

Current behavior: a `code_challenge` sent together with `response_type=token` or `display` is validated for its format, but has no effect on the issued token.

## Getting Started

### Client side (authorization request)

1. Create a random `code_verifier` (43-128 characters out of `A-Z a-z 0-9 - . _ ~`, e.g. 32 random bytes BASE64URL-encoded).
2. Compute `code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))` without padding.
3. Start the flow:

```text
GET /oauth2/authorize?response_type=code
		&client_id=my-spa
		&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback
		&state=xyz
		&scope=read
		&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
		&code_challenge_method=S256
```

4. Redeem the code:

```text
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&client_id=my-spa&client_secret=...&code=...&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

The (non-standard) `GET /oauth2/token` proxy accepts `code_verifier` as query parameter as well.

### Server side (`IOAuthService` implementation)

```csharp
public bool TryValidateSessionIdAndCreateRetrievalCode(
	string apiClientId, string sessionId, string[] selectedScopes, string codeChallenge,
	out string code, out string message
) {
	// ... validate session, create token or grant ...
	code = this.CreateCode();
	this.CodeStore.Save(code, stagedGrant, codeChallenge); // store opaque, may be null
	message = null;
	return true;
}

public TokenIssuingResult RetrieveTokenByCode(
	string clientId, string clientSecret, string code, out string codeChallenge
) {
	codeChallenge = null;
	// ... validate client ...
	StoredCode stored = this.CodeStore.TakeAndRemove(code); // one-time use!
	if (stored == null) {
		return TokenIssuingResult.FromError("invalid_grant", "Invalid Code");
	}
	codeChallenge = stored.CodeChallenge; // return unchanged
	return stored.TokenResult;
}
```

The controller verifies the returned challenge against the `code_verifier` afterwards. A complete reference implementation is `DemoOAuthService` in `dotnet/test/AuthTokenHandling.DemoWebService`.

## Advanced Scenarios

### Windows pass-through (silent, `view_mode=3`)

The challenge is passed directly into `TryValidateSessionIdAndCreateRetrievalCode`, because the code is created within the same request.

### Delegation to another OAuth server (`IOAuthServiceWithDelegation`)

When the authorization is delegated, the challenge of the *original* client is carried inside the server's own `state` (`StateBag.OriginalCodeChallenge`) through the foreign flow and restored after returning. It is bound to the code issued by *this* server; the delegation target itself is not involved in the client's PKCE.

### Login errors and consent page

After a failed login or a failed code creation the user is redirected back to `./authorize`. The PKCE parameters are appended to those redirects, and they are carried through the login and consent forms as hidden field `codeChallenge`. If a custom `IAuthPageBuilder` produces a page without `</form>`, the request fails with an error page instead of silently dropping PKCE.

### Public clients

PKCE replaces the client secret as proof of possession for public clients. Whether `RetrieveTokenByCode` accepts an empty `client_secret` for a given client is still decided by the `IOAuthService` implementation.

## Requirements

| # | Requirement | Behavior |
| --- | --- | --- |
| 1 | PKCE is optional | Requests without `code_challenge` and `code_verifier` behave as before |
| 2 | Only `S256` | `plain` or a missing `code_challenge_method` leads to `invalid_request` (redirect to the client including `state`) |
| 3 | Challenge format | Exactly 43 BASE64URL characters, otherwise `invalid_request` |
| 4 | Method without challenge | `invalid_request` |
| 5 | Verifier format | 43-128 characters of `A-Z a-z 0-9 - . _ ~`, otherwise `invalid_grant` |
| 6 | Verifier mismatch | `invalid_grant`, issued token is discarded, code stays consumed |
| 7 | Missing verifier for a PKCE code | `invalid_grant` |
| 8 | Verifier for a code without challenge (downgrade) | `invalid_grant` |
| 9 | Comparison | Constant time |
| 10 | Persistence | By the `IOAuthService` implementation, opaque, bound to the code, one-time use |
| 11 | Platforms | PKCE logic only in ASP.NET Core (`MvcSupport`, net8/net10); contract in core (also net48) |

## Artifacts (bottom-up)

### `IOAuthService` (core, `Security.AccessTokenHandling.OAuth.Server`)

**Breaking change:** two signatures were extended. All implementations must be adapted.

| Method | Change |
| --- | --- |
| `TryValidateSessionIdAndCreateRetrievalCode` | New parameter `string codeChallenge` (opaque, null/empty without PKCE), to be persisted with the code |
| `RetrieveTokenByCode` | New parameter `out string codeChallenge`, returns the persisted value unchanged |

Migration for implementations without own PKCE needs: store and return the value; if PKCE should not be supported at all, return `null` (clients sending a `code_verifier` will then get `invalid_grant`).

### `OAuth2Controller.Pkce.cs` (MvcSupport)

Internal helpers: `TryValidatePkceRequest`, `IsValidS256Challenge`, `IsValidCodeVerifier`, `TryVerifyPkce`, `ComputeS256Challenge`, `TryInjectPkceFormField`, `AppendPkceQueryParams`.

### `OAuth2Controller.Flow_Entry.cs` / `Flow_Post.cs` / `Flow_Retrieval.cs` / `StateBag.cs`

Read, validate and carry the challenge (query, hidden form field, redirects, delegation state) and verify the `code_verifier` at the token endpoint, after `RetrieveTokenByCode` has consumed the code.

### Tests

`dotnet/test/AuthTokenHandling.Tests.net10.0/PkceTests.cs` covers the RFC 7636 Appendix B test vector, parameter validation, verifier checks (mismatch, missing, downgrade, format), form injection and the token endpoint (POST and GET) against a fake `IOAuthService`.

## Open Follow-ups

- Optional per-client enforcement of PKCE (e.g. for public clients).
- Advertising `code_challenge_methods_supported` via authorization-server metadata ([RFC 8414](https://www.rfc-editor.org/rfc/rfc8414)), see `oauth-discovery-implementation-handoff.md`.
- Optionally rejecting `code_challenge` for `response_type=token` / `display` instead of ignoring it (current decision: keep ignoring it).
- Later: a fundamental OAuth standards validation and scope decision as well as a dedicated security hardening round against attack vectors (see sections 32.7 and 32.8 of `.agents/skills/auth-token-handling/SKILL.md`).
