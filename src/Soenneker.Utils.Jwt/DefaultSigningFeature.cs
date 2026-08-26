using Microsoft.IdentityModel.Tokens;

namespace Soenneker.Utils.Jwt;

internal readonly record struct DefaultSigningFeature(
    SigningCredentials SigningCredentials,
    SymmetricSecurityKey SymmetricKey,
    int TtlMinutes,
    TokenValidationParameters VerifyTvpValidateLifetime,
    TokenValidationParameters VerifyTvpNoValidateLifetime);
