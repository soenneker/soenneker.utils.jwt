using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Soenneker.Extensions.Configuration;
using Soenneker.Utils.Jwt.Abstract;

namespace Soenneker.Utils.Jwt;

///<inheritdoc cref="IJwtUtil"/>
public sealed class JwtUtil : IJwtUtil
{
    private readonly IConfiguration? _config;
    private readonly ILogger<JwtUtil>? _logger;

    public JwtUtil()
    {
    }

    public JwtUtil(IConfiguration config, ILogger<JwtUtil>? logger)
    {
        _config = config;
        _logger = logger;
    }

    public TokenValidationParameters GetValidationParameters()
    {
        if (_config == null)
            throw new InvalidOperationException("Configuration is required for GetValidationParameters()");

        var clientId = _config.GetValueStrict<string>("Azure:AzureAd:ClientId");
        var jwtIssuer = _config.GetValueStrict<string>("Azure:AzureAd:JwtIssuer");
        var jwtPublicKey = _config.GetValueStrict<string>("Azure:AzureAd:JwtPublicKey");
        var jwtExponent = _config.GetValueStrict<string>("Azure:AzureAd:JwtExponent");

        return GetValidationParameters(clientId, jwtIssuer, jwtPublicKey, jwtExponent);
    }

    public TokenValidationParameters GetValidationParameters(string jwtAudience, string jwtIssuer, string publicKey, string exponent)
    {
        using var rsa = new RSACryptoServiceProvider();

        rsa.ImportParameters(new RSAParameters
        {
            Modulus = Base64UrlEncoder.DecodeBytes(publicKey),
            Exponent = Base64UrlEncoder.DecodeBytes(exponent)
        });

        return new TokenValidationParameters
        {
            ClockSkew = TimeSpan.Zero,
            RequireSignedTokens = true,
            RequireExpirationTime = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidIssuer = jwtIssuer,
            IssuerSigningKey = new RsaSecurityKey(rsa.ExportParameters(false)), // Only exports public parameters
            ValidAudience = jwtAudience
        };
    }

    public ClaimsPrincipal? GetPrincipal(string token, bool validateLifetime = true)
    {
        var handler = new JwtSecurityTokenHandler();

        TokenValidationParameters parameters = GetValidationParameters();
        parameters.ValidateLifetime = validateLifetime;

        try
        {
            return handler.ValidateToken(token, parameters, out _);
        }
        catch (SecurityTokenExpiredException ex)
        {
            _logger?.LogWarning(ex, "Token has expired");
            return null;
        }
        catch (SecurityTokenInvalidSignatureException ex)
        {
            _logger?.LogCritical(ex, "Invalid token signature");
            return null;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Error decoding JWT");
            return null;
        }
    }
}
