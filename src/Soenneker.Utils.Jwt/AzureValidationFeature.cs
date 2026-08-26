using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Soenneker.Utils.Jwt;

internal readonly record struct AzureValidationFeature(
    string Audience,
    string Issuer,
    ConfigurationManager<OpenIdConnectConfiguration> ConfigurationManager);
