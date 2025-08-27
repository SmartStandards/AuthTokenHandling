# Change log
This files contains a version history including all changes relevant for semantic Versioning...

*(it is automatically maintained using the ['KornSW-VersioningUtil'](https://github.com/KornSW/VersioningUtil))*


## Upcoming Changes

*(none)*



## v 4.0.1
released **2025-08-27**, including:
 - Fix multi threading issue when accessing the validation cache



## v 4.0.0
released **2025-08-27**, including:
 - **breaking Change**: Added transport of concrete reason-phrases when tokens are rejected to increase auditing details.
 - **breaking Change**: Implemented ClientCredential-Flow (changed *IOAuthService*)
 - Added DemoService



## v 3.0.4
released **2025-05-30**, including:
 - new revision without significant changes



## v 3.0.3
released **2025-05-30**, including:
 - Removed .NET 4.6-Targets and enabled .NET 8.0-Targets (while switching build-runner from Win-2019 to WIN-2022)



## v 3.0.2
released **2025-03-21**, including:
 - Added Targets for net8.0 and net4.8
 - Removed net4.6.1 target for 'MvcSupport'-Package (is now .net-Core only)
 - Removed net5 targets



## v 3.0.1
released **2025-02-07**, including:
 - Fix: malformed token redirect-url

   

## v 3.0.0
released **2024-10-16**, including:
 - (**breaking Change**): added IAuthRequirementsProvider to evaluate the necessity of tokens and/or explicit apipermissions per contract



## v 2.8.7
released **2024-09-25**, including:
 - new revision without significant changes



## v 2.8.6
released **2024-07-18**, including:
 - new revision without significant changes



## v 2.8.5
released **2024-07-18**, including:
 - Fix: OAuthTokenRequestor -> customQueryParameters parsing



## v 2.8.4
released **2024-07-08**, including:
 - new revision without significant changes



## v 2.8.3
released **2024-06-24**, including:
 - new revision without significant changes



## v 2.8.2
released **2024-06-24**, including:
 - Fix: OAuthTokenRequestor -> improved customQueryParameters parsing



## v 2.8.1
released **2024-06-21**, including:
 - new revision without significant changes



## v 2.8.0
released **2024-06-20**, including:
 - **new Feature**: OAuthTokenRequestor: addded optional parameter -> customQueryParameters



## v 2.7.0
released **2024-06-13**, including:
 - **new Feature**: addded Support for OAuth implicit flow



## v 2.6.2
released **2024-05-03**, including:
 - Fixed net-fx version 4.6.2 to 4.6.1 for WinFormsClient (was wrong before)



## v 2.6.1
released **2024-04-30**, including:
 - Fix: fixed AuthForm (was broken after migration to CefSharp.Wrapped Lib)



## v 2.6.0
released **2024-04-30**, including:
 - **new Feature**: 'RequiredApiPermissionAttribute' was added.
 - **new Feature**: RawTokenExposalMethod now offers 'subject' and 'permittedScopes'



## v 2.5.0
released **2024-04-29**, including:
 - **new Feature**: added ClaimCustomizer-Hook for LocalJwtIntrospector
 - Fix: AssemblyInfo for .NET-Fx 4 Projects are now without wildcard, to ensure propper versions instead of 999.x



## v 2.4.0
released **2024-02-16**, including:
 - **new Feature**: added fluent-style configuration & rawToken exposal hook



## v 2.3.0
released **2023-09-19**, including:
 - added unattended Authentication support for headless clients (**new Feature**)
 - added http-get support for token retrieval



## v 2.2.2
released **2023-09-19**, including:
 - fix: login error messages are now shown properly
 - fix: readonly enabled scopes are now present in selection
 - some cleanup for the default auth page builder



## v 2.2.1
released **2023-09-19**, including:
 - fixed wrong compiler constant for .NET 6 (Windows Authentication was disabled there)



## v 2.2.0
released **2023-09-12**, including:
 - added Windows Authentication support (**new Feature**)



## v 2.1.0
released **2023-09-12**, including:
 - added Winforms Client support (**new Feature**)



## v 2.0.0
released **2023-07-17**, including:
 - spitted ASP related parts into separate package (**breaking Change**)
 - removed unnecessary reference



## v 1.0.1
released **2023-06-27**, including:
 - removed unnecessary reference


## v 1.0.0
released **2023-06-26**, including:
 - initial Version of gen-2 (gen-1 was: [KornSW.TokenValidation](https://github.com/KornSW/KornSW.TokenValidation)) - **MVP** state already reached



