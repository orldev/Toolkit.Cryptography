namespace Toolkit.Cryptography.Tests;

public class MethodTests
{
    private readonly IServiceCollection _services = new ServiceCollection()
        .AddCryptography(Helper.GetConfiguration());

    [Fact]
    public async Task EncryptAndDecrypt_ToBase64_ReturnEqual()
    {
        const string text = "Hello world";
        await using var serviceProvider = _services.BuildServiceProvider();
        
        var cryptography = serviceProvider.GetService<ICryptography>();
        Assert.NotNull(cryptography);
        
        var encryptToBase64 = await cryptography.EncryptToBase64Async(text);
        var decryptFromBase64 = await cryptography.DecryptFromBase64Async(encryptToBase64);
        
        Assert.Equal(text, decryptFromBase64);
    }
    
    [Fact]
    public async Task EncryptAndDecrypt_ToBytes_ReturnEqual()
    {
        const string text = "Hello world";
        await using var serviceProvider = _services.BuildServiceProvider();
        
        var cryptography = serviceProvider.GetService<ICryptography>();
        Assert.NotNull(cryptography);
        
        var encrypt = await cryptography.EncryptAsync(text);
        var decrypt = await cryptography.DecryptAsync(encrypt);
        
        Assert.Equal(text, decrypt);
    }
}