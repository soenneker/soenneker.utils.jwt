using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace Soenneker.Utils.Jwt.Abstract;

/// <summary>
/// Creates and validates JSON Web Tokens using configured Azure OpenID Connect metadata or an HMAC signing key.
/// </summary>
public interface IJwtUtil
{
    /// <summary>
    /// Builds JWT validation parameters for the expected audience and issuer using an RSA public key.
    /// </summary>
    /// <param name="jwtAudience">The required token audience.</param>
    /// <param name="jwtIssuer">The required token issuer.</param>
    /// <param name="publicKey">The Base64Url-encoded RSA modulus.</param>
    /// <param name="exponent">The Base64Url-encoded RSA exponent.</param>
    /// <returns>Parameters configured for audience, issuer, signature, and lifetime validation.</returns>
    [Pure]
    TokenValidationParameters GetValidationParameters(string jwtAudience, string jwtIssuer, string publicKey, string exponent);

    /// <summary>
    /// Builds validation parameters from the configured Azure OpenID Connect metadata and its rotating signing keys.
    /// </summary>
    /// <param name="validateLifetime"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    [Pure]
    Task<TokenValidationParameters> GetValidationParameters(bool validateLifetime = true, CancellationToken cancellationToken = default);

    /// <summary>
    /// Requires that <see cref="IConfiguration"/> be registered and configured in DI
    /// </summary>
    /// <returns>Requires that <see cref="IConfiguration"/> be registered and configured in DI.</returns>
    [Pure]
    ValueTask<ClaimsPrincipal?> GetPrincipal(string token, bool validateLifetime = true, CancellationToken cancellationToken = default);

    /// <summary>
    /// Create a compact HS256 JWT with only the essentials: sub, jti, iat, exp (+ optional extra claims).
    /// Reads SigningKey from config key "Jwt:SigningKey" unless provided.
    /// </summary>
    /// <returns>Create a compact HS256 JWT with only the essentials: sub, jti, iat, exp (+ optional extra claims). Reads SigningKey from config key "Jwt:SigningKey" unless provided.</returns>
    [Pure]
    string Create(string subject, IDictionary<string, object>? extraClaims = null, TimeSpan? lifetime = null, string? signingKey = null);

    /// <summary>
    /// Verify signature and (optionally) lifetime. No issuer/audience validation.
    /// Reads the signing key from "Jwt:SigningKey" unless one is provided.
    /// Returns ClaimsPrincipal on success, null on failure.
    /// </summary>
    /// <returns>Verify signature and (optionally) lifetime. No issuer/audience validation. Reads the signing key from "Jwt:SigningKey" unless provided. Returns ClaimsPrincipal on success, null on failure.</returns>
    [Pure]
    ClaimsPrincipal? Verify(string token, bool validateLifetime = true, string? signingKey = null);
}
