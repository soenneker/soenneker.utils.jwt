using System.Diagnostics.Contracts;
using System.Security.Claims;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace Soenneker.Utils.Jwt.Abstract;

/// <summary>
/// Various JWT related operations <para/>
/// Typically Scoped IoC
/// </summary>
public interface IJwtUtil
{
    /// <summary>
    /// Uses B2C defaults TODO: Make this configurable
    /// </summary>
    /// <returns></returns>
    [Pure]
    TokenValidationParameters GetValidationParameters();

    /// <param name="jwtAudience">ClientId of the application within B2C</param>
    /// <param name="jwtIssuer"></param>
    /// <param name="publicKey"></param>
    /// <param name="exponent"></param>
    [Pure]
    TokenValidationParameters GetValidationParameters(string jwtAudience, string jwtIssuer, string publicKey, string exponent);

    /// <summary>
    /// Requires that <see cref="IConfiguration"/> be registered and configured in DI
    /// </summary>
    [Pure]
    ClaimsPrincipal? GetPrincipal(string token, bool validateLifetime = true);
}