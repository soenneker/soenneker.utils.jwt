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

    // Feature bundles (initialized only if feature is used)
    private readonly Lazy<DefaultSigningFeature>? _defaultSigningFeature;
    private readonly Lazy<AzureValidationFeature>? _azureValidationFeature;

    public JwtUtil()
    {
        // parameterless for DI flexibility; feature accessors will throw if config missing
    }

    public JwtUtil(IConfiguration config, ILogger<JwtUtil>? logger)
    {
        _config = config;
        _logger = logger;

        // Default signing / default verify (Jwt:*). Nothing is read until Create/Verify (default key) is used.
        _defaultSigningFeature = new Lazy<DefaultSigningFeature>(CreateDefaultSigningFeature, isThreadSafe: true);

        // Azure OIDC validation (Azure:*). Nothing is read until GetPrincipal/GetValidationParameters(bool) is used.
        _azureValidationFeature = new Lazy<AzureValidationFeature>(CreateAzureValidationFeature, isThreadSafe: true);
    }

    private DefaultSigningFeature CreateDefaultSigningFeature()
    {
        if (_config is null)
            throw new InvalidOperationException("Configuration is required");

        var signingKeyRaw = _config.GetValueStrict<string>("Jwt:SigningKey");
        var ttlMinutes = _config.GetValueStrict<int>("Jwt:LifetimeMinutes");

        byte[] keyBytes = signingKeyRaw.ToBytes();

        var symmetricKey = new SymmetricSecurityKey(keyBytes);
        var signingCredentials = new SigningCredentials(symmetricKey, SecurityAlgorithms.HmacSha256);

        // Cache Verify TVPs (default key only)
        TokenValidationParameters tvpValidateLifetime = BuildVerifyTvp(validateLifetime: true, symmetricKey);
        TokenValidationParameters tvpNoValidateLifetime = BuildVerifyTvp(validateLifetime: false, symmetricKey);

        return new DefaultSigningFeature(signingCredentials, symmetricKey, ttlMinutes, tvpValidateLifetime, tvpNoValidateLifetime);
    }

    private AzureValidationFeature CreateAzureValidationFeature()
    {
        if (_config is null)
            throw new InvalidOperationException("Configuration is required");

        var audience = _config.GetValueStrict<string>("Azure:AzureAd:ClientId");
        var issuer = _config.GetValueStrict<string>("Azure:AzureAd:JwtIssuer");
        var metadataAddress = _config.GetValueStrict<string>("Azure:AzureAd:MetadataAddress");

        var documentRetriever = new HttpDocumentRetriever { RequireHttps = true };

        var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
            metadataAddress, new OpenIdConnectConfigurationRetriever(), documentRetriever);

        return new AzureValidationFeature(audience, issuer, configurationManager);
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
        if (_azureValidationFeature is null)
            throw new InvalidOperationException("Configuration is required");

        AzureValidationFeature azure = _azureValidationFeature.Value;

        OpenIdConnectConfiguration openIdConfig;

        try
        {
            openIdConfig = await azure.ConfigurationManager.GetConfigurationAsync(cancellationToken)
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
            ValidAudience = azure.Audience,

            ValidateIssuer = true,
            ValidIssuer = azure.Issuer,

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
        SigningCredentials credentials;
        int ttlMinutes;

        if (signingKey is null)
        {
            if (_defaultSigningFeature is null)
                throw new InvalidOperationException("Configuration is required");

            DefaultSigningFeature feature = _defaultSigningFeature.Value;
            credentials = feature.SigningCredentials;
            ttlMinutes = feature.TtlMinutes;
        }
        else
        {
            // Override path: do NOT cache unbounded key material
            credentials = new SigningCredentials(new SymmetricSecurityKey(signingKey.ToBytes()), SecurityAlgorithms.HmacSha256);

            // Prefer default ttl if configured; otherwise read on-demand
            if (_defaultSigningFeature is not null)
            {
                ttlMinutes = _defaultSigningFeature.Value.TtlMinutes;
            }
            else
            {
                ttlMinutes = _config?.GetValueStrict<int>("Jwt:LifetimeMinutes") ?? 0;
            }
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
                                                                       .UtcDateTime, expires: expires.UtcDateTime, signingCredentials: credentials);

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

            if (signingKey is null)
            {
                if (_defaultSigningFeature is null)
                    throw new InvalidOperationException("Configuration is required");

                DefaultSigningFeature feature = _defaultSigningFeature.Value;
                tvp = validateLifetime ? feature.VerifyTvpValidateLifetime : feature.VerifyTvpNoValidateLifetime;
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

    private readonly record struct DefaultSigningFeature(
        SigningCredentials SigningCredentials,
        SymmetricSecurityKey SymmetricKey,
        int TtlMinutes,
        TokenValidationParameters VerifyTvpValidateLifetime,
        TokenValidationParameters VerifyTvpNoValidateLifetime);

    private readonly record struct AzureValidationFeature(
        string Audience,
        string Issuer,
        ConfigurationManager<OpenIdConnectConfiguration> ConfigurationManager);
}