global using Xunit;
global using Microsoft.Extensions.DependencyInjection;
using System.Security.Cryptography;
using Microsoft.Extensions.Options;

namespace Toolkit.Cryptography.Tests;

public class ServiceCollectionExtensionsTests
{
    private readonly IServiceCollection _services = new ServiceCollection()
        .AddCryptography(Helper.GetConfiguration());

    [Fact]
    public void AddToServices_ReturnContains()
    {
        Assert.Contains(_services, d => d.ServiceType == typeof(ICryptography));
        Assert.Contains(_services, d => d.ServiceType == typeof(IConfigureOptions<CryptographyOptions>));
    }
    

    [Fact]
    public void Match_OptionsWithAppSettings_ReturnEqual()
    {
        using var serviceProvider = _services.BuildServiceProvider();
        
        var options = serviceProvider.GetService<IOptions<CryptographyOptions>>()?.Value;
        Assert.NotNull(options);
        
        Assert.Equal(Helper.InMemorySettings[$"{Helper.Client}:{nameof(options.Passphrase)}"], options.Passphrase);
        Assert.Equal(Helper.InMemorySettings[$"{Helper.Client}:{nameof(options.IV)}"], options.IV);
        Assert.Equal(Helper.InMemorySettings[$"{Helper.Client}:{nameof(options.Salt)}"], options.Salt);
        Assert.Equal(Helper.InMemorySettings[$"{Helper.Client}:{nameof(options.Iterations)}"], options.Iterations.ToString());
        Assert.Equal(Helper.InMemorySettings[$"{Helper.Client}:{nameof(options.DesiredKeyLength)}"], options.DesiredKeyLength.ToString());
        Assert.Equal(Helper.InMemorySettings[$"{Helper.Client}:{nameof(options.HashMethod)}"], options.HashMethod.ToString());
    }
    
    [Fact]
    public void GetFromServices_ReturnNotNull()
    {
        using var serviceProvider = _services.BuildServiceProvider();
        
        var cryptography = serviceProvider.GetService<ICryptography>();
        Assert.NotNull(cryptography);
    }
}