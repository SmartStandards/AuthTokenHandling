# Copilot Instructions

## Project Guidelines
- Always use MSTest as the unit test framework.
- All OAuth endpoints belong in the official OAuth2Controller; discovery (.well-known) goes into a generic 'OAuthDiscoverController' in API group '.well-known'. Controllers depend only on IOAuthService, which may be extended so implementation-specific needs are delegated down into the implementation.