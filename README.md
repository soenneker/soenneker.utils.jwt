[![](https://img.shields.io/nuget/v/Soenneker.Utils.Jwt.svg?style=for-the-badge)](https://www.nuget.org/packages/Soenneker.Utils.Jwt/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.utils.jwt/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.utils.jwt/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/Soenneker.Utils.Jwt.svg?style=for-the-badge)](https://www.nuget.org/packages/Soenneker.Utils.Jwt/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.utils.jwt/codeql.yml?label=CodeQL&style=for-the-badge)](https://github.com/soenneker/soenneker.utils.jwt/actions/workflows/codeql.yml)

# ![](https://user-images.githubusercontent.com/4441470/224455560-91ed3ee7-f510-4041-a8d2-3fc093025112.png) Soenneker.Utils.Jwt
Creates and validates HS256 JWTs and validates Azure OpenID Connect tokens.

## Installation

```bash
dotnet add package Soenneker.Utils.Jwt
```

## Quick start

```csharp
using Soenneker.Utils.Jwt.Registrars;

services.AddJwtUtilAsSingleton();
```

Then inject `IJwtUtil` wherever you need it.

## Create and verify an HMAC token

Configure the default signing key and lifetime:

```json
{
  "Jwt": {
    "SigningKey": "a-long-random-secret-kept-out-of-source-control",
    "LifetimeMinutes": 30
  }
}
```

```csharp
string token = jwtUtil.Create(
    subject: userId,
    extraClaims: new Dictionary<string, object> { ["role"] = "admin" });

ClaimsPrincipal? principal = jwtUtil.Verify(token);
```

`Create` emits an HS256 token containing `sub`, `jti`, `iat`, `nbf`, and `exp`. Extra claim values
are converted to strings, and reserved claims supplied through `extraClaims` are ignored. You can
provide both `signingKey` and `lifetime` directly when configuration is unavailable.

`Verify` validates the signature and, by default, the expiration time with zero clock skew. It
does not validate issuer or audience, so use it only where possession of the shared key is the
intended trust boundary. Invalid or expired tokens return `null`.

## Validate Azure OpenID Connect tokens

The Azure overloads require these configuration values:

```json
{
  "Azure": {
    "AzureAd": {
      "ClientId": "expected-audience",
      "JwtIssuer": "https://login.microsoftonline.com/{tenant-id}/v2.0",
      "MetadataAddress": "https://login.microsoftonline.com/{tenant-id}/v2.0/.well-known/openid-configuration"
    }
  }
}
```

```csharp
ClaimsPrincipal? principal = await jwtUtil.GetPrincipal(token, cancellationToken: cancellationToken);
```

This path validates the configured issuer, audience, signature, expiration, and rotating signing
keys obtained from the HTTPS metadata endpoint. Invalid tokens return `null`; metadata retrieval
errors are logged and also result in `null` from `GetPrincipal`. Requested cancellation propagates.

## Other validation option

`GetValidationParameters(audience, issuer, publicKey, exponent)` builds parameters for a specific
RSA public key. The modulus and exponent must be Base64Url encoded. It enables issuer, audience,
signature, and lifetime validation with zero clock skew.
