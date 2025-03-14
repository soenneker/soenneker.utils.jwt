﻿using Microsoft.Extensions.DependencyInjection;
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
    public static IServiceCollection AddJwtUtilAsScoped(this IServiceCollection services)
    {
        services.TryAddScoped<IJwtUtil, JwtUtil>();
        return services;
    }

    /// <summary>
    /// Adds <see cref="IJwtUtil"/> as a singleton service. <para/>
    /// </summary>
    public static IServiceCollection AddJwtUtilAsSingleton(this IServiceCollection services)
    {
        services.TryAddSingleton<IJwtUtil, JwtUtil>();
        return services;
    }
}