namespace Toolkit.Cryptography;

public interface ICryptography
{
    Task<byte[]> EncryptAsync(string clearText);

    Task<string> EncryptToBase64Async(string clearText);

    Task<string> DecryptAsync(byte[] encrypted);

    Task<string> DecryptFromBase64Async(string encrypted);
}