using Soenneker.Extensions.Configuration;
using Soenneker.Extensions.String;
using Soenneker.Extensions.Task;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Soenneker.Utils.Jwt.Abstract;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Soenneker.Utils.Jwt;

///<inheritdoc cref="IJwtUtil"/>
public sealed class JwtUtil : IJwtUtil
{
    private static readonly JwtSecurityTokenHandler _handler = new();

    private readonly IConfiguration? _config;
    private readonly ILogger<JwtUtil>? _logger;

    private readonly ConfigurationManager<OpenIdConnectConfiguration>? _configurationManager;

    // Cached config values (no per-call config reads)
    private readonly string? _azureAudience;
    private readonly string? _azureIssuer;

    private readonly int _jwtLifetimeMinutes;

    // Default signing material cache
    private readonly SigningCredentials? _defaultSigningCredentials;

    // Verify() TVP cache for default key (validateLifetime true/false)
    private readonly TokenValidationParameters? _verifyTvpValidateLifetime;
    private readonly TokenValidationParameters? _verifyTvpNoValidateLifetime;

    public JwtUtil()
    {
        // parameterless for DI flexibility, but Create/Verify/GetValidationParameters(bool) will throw if config missing
    }

    public JwtUtil(IConfiguration config, ILogger<JwtUtil>? logger)
    {
        _config = config;
        _logger = logger;

        var defaultSigningKeyRaw = _config.GetValueStrict<string>("Jwt:SigningKey");
        _jwtLifetimeMinutes = _config.GetValueStrict<int>("Jwt:LifetimeMinutes");

        _azureAudience = _config.GetValueStrict<string>("Azure:AzureAd:ClientId");
        _azureIssuer = _config.GetValueStrict<string>("Azure:AzureAd:JwtIssuer");

        byte[]? defaultSigningKeyBytes = defaultSigningKeyRaw.ToBytes();
        var defaultSymmetricKey = new SymmetricSecurityKey(defaultSigningKeyBytes);
        _defaultSigningCredentials = new SigningCredentials(defaultSymmetricKey, SecurityAlgorithms.HmacSha256);

        // Cache Verify TVPs (default key only)
        _verifyTvpValidateLifetime = BuildVerifyTvp(validateLifetime: true, defaultSymmetricKey);
        _verifyTvpNoValidateLifetime = BuildVerifyTvp(validateLifetime: false, defaultSymmetricKey);

        var metadataAddress = _config.GetValueStrict<string>("Azure:AzureAd:MetadataAddress");
        var documentRetriever = new HttpDocumentRetriever { RequireHttps = true };

        _configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
            metadataAddress, new OpenIdConnectConfigurationRetriever(), documentRetriever);
    }

    private static TokenValidationParameters BuildVerifyTvp(bool validateLifetime, SymmetricSecurityKey key) => new()
    {
        ClockSkew = TimeSpan.Zero,
        RequireSignedTokens = true,
        RequireExpirationTime = true,
        ValidateLifetime = validateLifetime,

        ValidateIssuer = false,
        ValidateAudience = false,

        ValidateIssuerSigningKey = true,
        IssuerSigningKey = key
    };

    public TokenValidationParameters GetValidationParameters(string jwtAudience, string jwtIssuer, string publicKey, string exponent)
    {
        var rsaParams = new RSAParameters
        {
            Modulus = Base64UrlEncoder.DecodeBytes(publicKey),
            Exponent = Base64UrlEncoder.DecodeBytes(exponent)
        };

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
            IssuerSigningKey = new RsaSecurityKey(rsaParams),
            ValidAudience = jwtAudience
        };
    }

    public async Task<TokenValidationParameters> GetValidationParameters(bool validateLifetime = true, CancellationToken cancellationToken = default)
    {
        if (_configurationManager == null || _azureAudience == null || _azureIssuer == null)
            throw new InvalidOperationException("Configuration is required");

        OpenIdConnectConfiguration openIdConfig;

        try
        {
            openIdConfig = await _configurationManager.GetConfigurationAsync(cancellationToken)
                                                      .NoSync();
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to retrieve OpenID configuration");
            throw;
        }

        return new TokenValidationParameters
        {
            ClockSkew = TimeSpan.Zero,
            RequireSignedTokens = true,
            RequireExpirationTime = true,
            ValidateLifetime = validateLifetime,

            ValidateAudience = true,
            ValidAudience = _azureAudience,

            ValidateIssuer = true,
            ValidIssuer = _azureIssuer,

            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = openIdConfig.SigningKeys
        };
    }

    public async ValueTask<ClaimsPrincipal?> GetPrincipal(string token, bool validateLifetime = true, CancellationToken cancellationToken = default)
    {
        try
        {
            TokenValidationParameters validationParameters = await GetValidationParameters(validateLifetime, cancellationToken)
                .NoSync();

            return _handler.ValidateToken(token, validationParameters, out _);
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

    public string Create(string subject, IDictionary<string, object>? extraClaims = null, TimeSpan? lifetime = null, string? signingKey = null)
    {
        SigningCredentials creds;
        int ttlMinutes;

        if (signingKey == null)
        {
            if (_defaultSigningCredentials == null)
                throw new InvalidOperationException("Configuration is required");

            creds = _defaultSigningCredentials;
            ttlMinutes = _jwtLifetimeMinutes;
        }
        else
        {
            // Override path: avoid retaining unbounded key material
            creds = new SigningCredentials(new SymmetricSecurityKey(signingKey.ToBytes()), SecurityAlgorithms.HmacSha256);
            ttlMinutes = _jwtLifetimeMinutes != 0 ? _jwtLifetimeMinutes : (_config?.GetValueStrict<int>("Jwt:LifetimeMinutes") ?? 0);
        }

        DateTimeOffset now = DateTimeOffset.UtcNow;
        DateTimeOffset expires = now.Add(lifetime ?? TimeSpan.FromMinutes(ttlMinutes));

        var claims = new List<Claim>(3 + (extraClaims?.Count ?? 0))
        {
            new(JwtRegisteredClaimNames.Sub, subject),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid()
                                                 .ToString("N")),
            new(JwtRegisteredClaimNames.Iat, now.ToUnixTimeSeconds()
                                                .ToString(), ClaimValueTypes.Integer64)
        };

        if (extraClaims != null)
        {
            // Fast-path to avoid interface enumerator boxing
            if (extraClaims is Dictionary<string, object> dict)
            {
                foreach (KeyValuePair<string, object> kvp in dict)
                    AddExtraClaimIfValid(claims, kvp.Key, kvp.Value);
            }
            else
            {
                foreach (KeyValuePair<string, object> kvp in extraClaims)
                    AddExtraClaimIfValid(claims, kvp.Key, kvp.Value);
            }
        }

        var token = new JwtSecurityToken(claims: claims, notBefore: now.AddSeconds(-5)
                                                                       .UtcDateTime, expires: expires.UtcDateTime, signingCredentials: creds);

        return _handler.WriteToken(token);

        static void AddExtraClaimIfValid(List<Claim> claims, string k, object? v)
        {
            if (v is null)
                return;

            if (k is JwtRegisteredClaimNames.Sub or JwtRegisteredClaimNames.Iat or JwtRegisteredClaimNames.Jti or JwtRegisteredClaimNames.Exp or "nbf")
                return;

            claims.Add(new Claim(k, v.ToString()!));
        }
    }

    public ClaimsPrincipal? Verify(string token, bool validateLifetime = true, string? signingKey = null)
    {
        try
        {
            TokenValidationParameters tvp;

            if (signingKey == null)
            {
                if (_verifyTvpValidateLifetime == null || _verifyTvpNoValidateLifetime == null)
                    throw new InvalidOperationException("Configuration is required");

                tvp = validateLifetime ? _verifyTvpValidateLifetime : _verifyTvpNoValidateLifetime;
            }
            else
            {
                tvp = BuildVerifyTvp(validateLifetime, new SymmetricSecurityKey(signingKey.ToBytes()));
            }

            return _handler.ValidateToken(token, tvp, out _);
        }
        catch (SecurityTokenExpiredException ex)
        {
            _logger?.LogWarning(ex, "Token expired");
            return null;
        }
        catch (SecurityTokenInvalidSignatureException ex)
        {
            _logger?.LogCritical(ex, "Invalid token signature");
            return null;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Token verification failed");
            return null;
        }
    }
}