using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Toolkit.Cryptography;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddCryptography(
        this IServiceCollection services, 
        Action<CryptographyOptions>? options = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.Configure(options ??= o =>
        {
            o.Passphrase = "123456";
            o.IV = "abcede0123456789";
        });
        services.TryAddSingleton<ICryptography, Cryptographic>();
        return services;
    }
    
    public static IServiceCollection AddCryptography(
        this IServiceCollection services, 
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.Configure<CryptographyOptions>(configuration.GetSection("Cryptography"));
        services.TryAddSingleton<ICryptography, Cryptographic>();
        return services;
    }
}