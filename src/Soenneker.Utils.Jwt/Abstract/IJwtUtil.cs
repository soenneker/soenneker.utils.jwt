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
/// Various JWT related operations <para/>
/// Typically Scoped IoC
/// </summary>
public interface IJwtUtil
{
    /// <param name="jwtAudience">ClientId of the application within AzureAd</param>
    /// <param name="jwtIssuer"></param>
    /// <param name="publicKey"></param>
    /// <param name="exponent"></param>
    [Pure]
    TokenValidationParameters GetValidationParameters(string jwtAudience, string jwtIssuer, string publicKey, string exponent);

    /// <summary>
    /// This is the method you want for rotating keys (live environments)
    /// </summary>
    /// <param name="validateLifetime"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    [Pure]
    Task<TokenValidationParameters> GetValidationParameters(bool validateLifetime = true, CancellationToken cancellationToken = default);

    /// <summary>
    /// Requires that <see cref="IConfiguration"/> be registered and configured in DI
    /// </summary>
    [Pure]
    ValueTask<ClaimsPrincipal?> GetPrincipal(string token, bool validateLifetime = true, CancellationToken cancellationToken = default);

    /// <summary>
    /// Create a compact HS256 JWT with only the essentials: sub, jti, iat, exp (+ optional extra claims).
    /// Reads SigningKey from config key "Jwt:SigningKey" unless provided.
    /// </summary>
    [Pure]
    string Create(string subject, IDictionary<string, object>? extraClaims = null, TimeSpan? lifetime = null, string? signingKey = null);

    /// <summary>
    /// Verify signature and (optionally) lifetime. No issuer/audience validation.
    /// Reads SigningKey from "Jwt:ClientState:SigningKey" unless provided.
    /// Returns ClaimsPrincipal on success, null on failure.
    /// </summary>
    [Pure]
    ClaimsPrincipal? Verify(string token, bool validateLifetime = true, string? signingKey = null);
}