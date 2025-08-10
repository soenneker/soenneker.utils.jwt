using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Soenneker.Extensions.Configuration;
using Soenneker.Extensions.String;
using Soenneker.Extensions.Task;
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
    private readonly IConfiguration? _config;
    private readonly ILogger<JwtUtil>? _logger;

    private readonly ConfigurationManager<OpenIdConnectConfiguration>? _configurationManager;

    public JwtUtil()
    {
    }

    public JwtUtil(IConfiguration config, ILogger<JwtUtil>? logger)
    {
        _config = config;
        _logger = logger;

        var metadataAddress = _config.GetValueStrict<string>("Azure:AzureAd:MetadataAddress");

        var documentRetriever = new HttpDocumentRetriever {RequireHttps = true};

        _configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(metadataAddress,
            new OpenIdConnectConfigurationRetriever(), documentRetriever);
    }

    public TokenValidationParameters GetValidationParameters(string jwtAudience, string jwtIssuer, string publicKey, string exponent)
    {
        using var rsa = RSA.Create();

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

    // Needs to remain Task until async startup 
    public async Task<TokenValidationParameters> GetValidationParameters(bool validateLifetime = true, CancellationToken cancellationToken = default)
    {
        if (_config == null || _configurationManager == null)
            throw new InvalidOperationException("Configuration is required");

        var audience = _config.GetValueStrict<string>("Azure:AzureAd:ClientId");
        var issuer = _config.GetValueStrict<string>("Azure:AzureAd:JwtIssuer");

        OpenIdConnectConfiguration? config;

        try
        {
            config = await _configurationManager.GetConfigurationAsync(cancellationToken).NoSync();
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
            IssuerSigningKeys = config.SigningKeys // ← uses keys from discovery metadata
        };
    }

    public async ValueTask<ClaimsPrincipal?> GetPrincipal(string token, bool validateLifetime = true, CancellationToken cancellationToken = default)
    {
        var handler = new JwtSecurityTokenHandler();

        try
        {
            TokenValidationParameters validationParameters = await GetValidationParameters(validateLifetime, cancellationToken).NoSync();
            return handler.ValidateToken(token, validationParameters, out _);
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
        signingKey ??= _config!.GetValueStrict<string>("Jwt:SigningKey");
        var ttlMinutes = _config!.GetValueStrict<int>("Jwt:LifetimeMinutes");

        DateTime now = DateTime.UtcNow;
        DateTime expires = now.Add(lifetime ?? TimeSpan.FromMinutes(ttlMinutes));

        SymmetricSecurityKey key = BuildSymmetricKey(signingKey);
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim>
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
                if (k is JwtRegisteredClaimNames.Sub or JwtRegisteredClaimNames.Iat or JwtRegisteredClaimNames.Jti or JwtRegisteredClaimNames.Exp or "nbf")
                    continue;

                claims.Add(new Claim(k, v.ToString()!));
            }
        }

        var token = new JwtSecurityToken(claims: claims, notBefore: now.AddSeconds(-5), // small skew tolerance
            expires: expires, signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public ClaimsPrincipal? Verify(string token, bool validateLifetime = true, string? signingKey = null)
    {
        try
        {
            signingKey ??= _config!.GetValueStrict<string>("Jwt:SigningKey");

            var tvp = new TokenValidationParameters
            {
                ClockSkew = TimeSpan.Zero,
                RequireSignedTokens = true,
                RequireExpirationTime = true,
                ValidateLifetime = validateLifetime,
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = BuildSymmetricKey(signingKey)
            };

            var handler = new JwtSecurityTokenHandler();
            return handler.ValidateToken(token, tvp, out _);
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

    private static SymmetricSecurityKey BuildSymmetricKey(string rawKey)
    {
        byte[] bytes = rawKey.ToBytes();

        return new SymmetricSecurityKey(bytes);
    }
}