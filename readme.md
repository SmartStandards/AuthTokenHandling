# AuthTokenHandling

Moved/Migrated from [KornSW.TokenValidation](https://github.com/KornSW/KornSW.TokenValidation)





## AuthTokenHandling.MvcSupport

Server-Side usage within **ASP.NET Core WebAPI** Projects:

### Setup

Configure the Framework during your startup

```c#
//(from Nuget Pkg 'SmartStandards.AuthTokenHandling')
AccessTokenValidator.ConfigureTokenIntrospection(
    new LocalJwtIntrospector("myTokeSignKey12345"),
    IdentityStateManager.InitializeCurrentContext, //[opt] populate MAC-scopes ambient 
    introspectionResultCachingMinutes: 2,  //[opt] caching if introsp. is expensive
    auditingHook: this.CreateAuditingEntry //[opt] auditing for introsp. outcome
);
```



### WebAPI-Controller

Just place the "EvaluateBearerToken"-Attribute over the methods for which the access should be restricted and classify it with an API scope name. In this case were requiring accessors to have the "*NiceActionExecutorRole*".

```c#
class MyMvcController {
    ...
    
    [EvaluateBearerToken("NiceActionExecutorRole")] //<<< use this attribute
    [HttpPost("DoANiceAction"), Produces("application/json")]
    public NiceResponseDto DoANiceAction([FromBody] NiceRequestDto args) {
       ...
    }
    
}
```



### Token-Content

Contains the "API"-Clearance for "*NiceActionExecutorRole*" within the  "scopes"-claim)

```json
{
    "iss": "the issuer",
    "sub": "832",
    "iat": 1684927942,
    "exp": 1842607942,
    "scope": "API:NiceActionExecutorRole Tenant:1243 DataProtectionLevel:3"
}
```





