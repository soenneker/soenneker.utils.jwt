using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Soenneker.Utils.Jwt.Abstract;

namespace Soenneker.Utils.Jwt.Registrars;

/// <summary>
/// Various JWT related operations
/// </summary>
public static class JwtUtilRegistrar
{
    /// <summary>
    /// Adds <see cref="IJwtUtil"/> as a scoped service. (Recommended) <para/>
    /// </summary>
    public static void AddJwtUtilAsScoped(this IServiceCollection services)
    {
        services.TryAddScoped<IJwtUtil, JwtUtil>();
    }

    /// <summary>
    /// Adds <see cref="IJwtUtil"/> as a singleton service. <para/>
    /// </summary>
    public static void AddJwtUtilAsSingleton(this IServiceCollection services)
    {
        services.TryAddSingleton<IJwtUtil, JwtUtil>();
    }
}