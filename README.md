[![](https://img.shields.io/nuget/v/Soenneker.Utils.Jwt.svg?style=for-the-badge)](https://www.nuget.org/packages/Soenneker.Utils.Jwt/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.utils.jwt/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.utils.jwt/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/Soenneker.Utils.Jwt.svg?style=for-the-badge)](https://www.nuget.org/packages/Soenneker.Utils.Jwt/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.utils.jwt/codeql.yml?label=CodeQL&style=for-the-badge)](https://github.com/soenneker/soenneker.utils.jwt/actions/workflows/codeql.yml)

# ![](https://user-images.githubusercontent.com/4441470/224455560-91ed3ee7-f510-4041-a8d2-3fc093025112.png) Soenneker.Utils.Jwt
Various JWT related operations.

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

## Common operations

- `GetValidationParameters()` - Builds strict parameters from an explicit RSA key, issuer, and audience, or asynchronously loads rotating Azure OIDC signing keys from configuration. The Azure overload can disable lifetime validation.
- `GetPrincipal()` - Validates a token with the configured Azure OIDC parameters and returns its `ClaimsPrincipal`; configuration is required.
- `Create()` - Creates a compact HS256 token with `sub`, `jti`, `iat`, and `exp`, plus optional claims. It reads `Jwt:SigningKey` unless a key is supplied.
- `Verify()` - Verifies HS256 signature and optionally lifetime, returning a principal on success and `null` on failure. It does not validate issuer or audience.
