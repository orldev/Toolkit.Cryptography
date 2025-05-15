using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace Toolkit.Cryptography;

public class Cryptographic(IOptions<CryptographyOptions> options) : ICryptography
{
    private readonly CryptographyOptions _options = options.Value;

    public async Task<byte[]> EncryptAsync(string clearText)
    {
        using var aes = Aes.Create();
        aes.Key = DeriveKeyFromPassword(_options.Passphrase);
        aes.IV = InitializationVector(_options.IV);
        await using MemoryStream output = new();
        await using CryptoStream cryptoStream = new(output, aes.CreateEncryptor(), CryptoStreamMode.Write);
        await cryptoStream.WriteAsync(Encoding.Unicode.GetBytes(clearText));
        await cryptoStream.FlushFinalBlockAsync();
        return output.ToArray();
    }
    
    public async Task<string> DecryptAsync(byte[] encrypted)
    {
        using var aes = Aes.Create();
        aes.Key = DeriveKeyFromPassword(_options.Passphrase);
        aes.IV = InitializationVector(_options.IV);
        await using MemoryStream input = new(encrypted);
        await using CryptoStream cryptoStream = new(input, aes.CreateDecryptor(), CryptoStreamMode.Read);
        await using MemoryStream output = new();
        await cryptoStream.CopyToAsync(output);
        return Encoding.Unicode.GetString(output.ToArray());
    }

    public async Task<string> EncryptToBase64Async(string clearText) =>
        Convert.ToBase64String(await EncryptAsync(clearText));
    
    public async Task<string> DecryptFromBase64Async(string encrypted) => 
        await DecryptAsync(Convert.FromBase64String(encrypted));

    private byte[] DeriveKeyFromPassword(string password)
    {
        var emptySalt = string.IsNullOrEmpty(_options.Salt) ? [] : Encoding.ASCII.GetBytes(_options.Salt);
        var iterations = _options.Iterations;
        var desiredKeyLength = _options.DesiredKeyLength; // 16 bytes equal 128 bits.
        var hashMethod = new HashAlgorithmName(_options.HashMethod.ToString());
        return Rfc2898DeriveBytes.Pbkdf2(Encoding.Unicode.GetBytes(password),
            emptySalt,
            iterations,
            hashMethod,
            desiredKeyLength);
    }
    
    private static byte[] InitializationVector(string? iv)
    {
        return string.IsNullOrEmpty(iv)
            ? new byte[]
            {
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16
            }
            : Encoding.ASCII.GetBytes(iv);
    }
}