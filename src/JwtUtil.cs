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
using System.Threading;
using System.Threading.Tasks;

namespace Soenneker.Utils.Jwt;

/// <inheritdoc cref="IJwtUtil"/>
public sealed class JwtUtil : IJwtUtil
{
    // Reuse handler (cuts allocations; behavior unchanged unless you mutate handler properties, which we don't).
    private static readonly JwtSecurityTokenHandler _handler = new();

    private readonly IConfiguration? _config;
    private readonly ILogger<JwtUtil>? _logger;

    private readonly ConfigurationManager<OpenIdConnectConfiguration>? _configurationManager;

    // Lazy cached default signing objects (common path: config signing key)
    private string? _defaultSigningKey;
    private SymmetricSecurityKey? _defaultSymmetricKey;
    private SigningCredentials? _defaultSigningCredentials;

    public JwtUtil()
    {
    }

    public JwtUtil(IConfiguration config, ILogger<JwtUtil>? logger)
    {
        _config = config;
        _logger = logger;

        var metadataAddress = _config.GetValueStrict<string>("Azure:AzureAd:MetadataAddress");
        var documentRetriever = new HttpDocumentRetriever { RequireHttps = true };

        _configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
            metadataAddress,
            new OpenIdConnectConfigurationRetriever(),
            documentRetriever);
    }

    public TokenValidationParameters GetValidationParameters(string jwtAudience, string jwtIssuer, string publicKey, string exponent)
    {
        // Avoid RSA.Create() + ExportParameters(false); build the key directly from RSAParameters.
        var rsaParams = new System.Security.Cryptography.RSAParameters
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

    // Needs to remain Task until async startup
    public async Task<TokenValidationParameters> GetValidationParameters(bool validateLifetime = true, CancellationToken cancellationToken = default)
    {
        if (_config == null || _configurationManager == null)
            throw new InvalidOperationException("Configuration is required");

        var audience = _config.GetValueStrict<string>("Azure:AzureAd:ClientId");
        var issuer = _config.GetValueStrict<string>("Azure:AzureAd:JwtIssuer");

        OpenIdConnectConfiguration openIdConfig;

        try
        {
            openIdConfig = await _configurationManager.GetConfigurationAsync(cancellationToken).NoSync();
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
            ValidAudience = audience,

            ValidateIssuer = true,
            ValidIssuer = issuer,

            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = openIdConfig.SigningKeys // uses keys from discovery metadata
        };
    }

    public async ValueTask<ClaimsPrincipal?> GetPrincipal(string token, bool validateLifetime = true, CancellationToken cancellationToken = default)
    {
        try
        {
            TokenValidationParameters validationParameters = await GetValidationParameters(validateLifetime, cancellationToken).NoSync();
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
        signingKey ??= GetDefaultSigningKey();
        int ttlMinutes = GetLifetimeMinutes();

        DateTime now = DateTime.UtcNow;
        DateTime expires = now.Add(lifetime ?? TimeSpan.FromMinutes(ttlMinutes));

        SigningCredentials credentials = GetSigningCredentials(signingKey);

        // Pre-size: 3 core claims + extras (upper bound)
        var claims = new List<Claim>(3 + (extraClaims?.Count ?? 0))
        {
            new(JwtRegisteredClaimNames.Sub, subject),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            new(JwtRegisteredClaimNames.Iat, new DateTimeOffset(now).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
        };

        if (extraClaims != null)
        {
            foreach ((string k, var v) in extraClaims)
            {
                if (v is null)
                    continue;

                // avoid overwriting core registered claims
                if (k is JwtRegisteredClaimNames.Sub
                    or JwtRegisteredClaimNames.Iat
                    or JwtRegisteredClaimNames.Jti
                    or JwtRegisteredClaimNames.Exp
                    or "nbf")
                    continue;

                claims.Add(new Claim(k, v.ToString()!));
            }
        }

        var token = new JwtSecurityToken(
            claims: claims,
            notBefore: now.AddSeconds(-5), // small skew tolerance
            expires: expires,
            signingCredentials: credentials);

        return _handler.WriteToken(token);
    }

    public ClaimsPrincipal? Verify(string token, bool validateLifetime = true, string? signingKey = null)
    {
        try
        {
            // Keep old behavior: signingKey is optional; when null we read Jwt:SigningKey from config.
            signingKey ??= GetDefaultSigningKey();

            var tvp = new TokenValidationParameters
            {
                ClockSkew = TimeSpan.Zero,
                RequireSignedTokens = true,
                RequireExpirationTime = true,
                ValidateLifetime = validateLifetime,

                ValidateIssuer = false,
                ValidateAudience = false,

                ValidateIssuerSigningKey = true,
                IssuerSigningKey = GetSymmetricKey(signingKey)
            };

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

    private string GetDefaultSigningKey()
    {
        return _defaultSigningKey ??= _config.GetValueStrict<string>("Jwt:SigningKey");
    }

    private int GetLifetimeMinutes()
    {
        return _config.GetValueStrict<int>("Jwt:LifetimeMinutes");
    }

    private SymmetricSecurityKey GetSymmetricKey(string rawKey)
    {
        // Common path: default config signing key. Cache to avoid per-call byte[] allocation.
        if (_defaultSigningKey != null && rawKey == _defaultSigningKey)
            return _defaultSymmetricKey ??= new SymmetricSecurityKey(rawKey.ToBytes());

        // Override keys: don't cache by default (avoid unbounded key-material retention).
        return new SymmetricSecurityKey(rawKey.ToBytes());
    }

    private SigningCredentials GetSigningCredentials(string rawKey)
    {
        // Common path: default config signing key. Cache creds too.
        if (_defaultSigningKey != null && rawKey == _defaultSigningKey)
            return _defaultSigningCredentials ??= new SigningCredentials(GetSymmetricKey(rawKey), SecurityAlgorithms.HmacSha256);

        return new SigningCredentials(GetSymmetricKey(rawKey), SecurityAlgorithms.HmacSha256);
    }
}