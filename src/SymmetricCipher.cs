using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Toolkit.Cryptography.Entities;
using Toolkit.Cryptography.Interfaces;

namespace Toolkit.Cryptography;

/// <summary>
/// Provides symmetric encryption/decryption services using AES with PBKDF2 key derivation.
/// </summary>
/// <remarks>
/// This implementation uses:
/// - AES (Advanced Encryption Standard) for symmetric encryption
/// - PBKDF2 (Password-Based Key Derivation Function 2) for key derivation
/// - Configurable parameters via <see cref="SymCryptoOpts"/>
/// </remarks>
/// <param name="options">The configuration options for cryptographic operations</param>
public class SymmetricCipher(IOptions<SymCryptoOpts> options) : ISymmetricCipher
{
    private readonly SymCryptoOpts _options = options.Value;

    /// <summary>
    /// Encrypts a plaintext string and returns the ciphertext as a byte array.
    /// </summary>
    /// <param name="clearText">The plaintext to encrypt</param>
    /// <returns>Encrypted ciphertext as byte array</returns>
    /// <exception cref="ArgumentNullException">Thrown when clearText is null</exception>
    /// <exception cref="CryptographicException">Thrown when encryption fails</exception>
    /// <remarks>
    /// Security considerations:
    /// - Uses Unicode encoding for text conversion
    /// - Generates a new IV for each operation if not specified in options
    /// - Combines IV and ciphertext in output
    /// - Always dispose cryptographic objects with 'using' statements
    /// </remarks>
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
    
    /// <summary>
    /// Decrypts ciphertext and returns the original plaintext string.
    /// </summary>
    /// <param name="encrypted">The ciphertext to decrypt</param>
    /// <returns>Decrypted plaintext string</returns>
    /// <exception cref="ArgumentNullException">Thrown when encrypted is null</exception>
    /// <exception cref="CryptographicException">Thrown when decryption fails</exception>
    /// <remarks>
    /// Implementation notes:
    /// - Expects input in the format produced by EncryptAsync
    /// - Uses same key derivation parameters as encryption
    /// - Handles both memory and crypto streams asynchronously
    /// </remarks>
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

    /// <summary>
    /// Encrypts a plaintext string and returns Base64-encoded ciphertext.
    /// </summary>
    /// <param name="clearText">The plaintext to encrypt</param>
    /// <returns>Base64-encoded ciphertext string</returns>
    /// <remarks>
    /// Convenience method that combines encryption and Base64 encoding.
    /// Suitable for text-based storage or transmission.
    /// </remarks>
    public async Task<string> EncryptToBase64Async(string clearText) =>
        Convert.ToBase64String(await EncryptAsync(clearText));
    
    /// <summary>
    /// Decrypts Base64-encoded ciphertext and returns the original plaintext.
    /// </summary>
    /// <param name="encrypted">Base64-encoded ciphertext</param>
    /// <returns>Decrypted plaintext string</returns>
    /// <exception cref="FormatException">Thrown when input is not valid Base64</exception>
    /// <remarks>
    /// Counterpart to EncryptToBase64Async, handles the common case of
    /// Base64-encoded ciphertext from text-based storage.
    /// </remarks>
    public async Task<string> DecryptFromBase64Async(string encrypted) => 
        await DecryptAsync(Convert.FromBase64String(encrypted));

    /// <summary>
    /// Derives a cryptographic key from a password using PBKDF2.
    /// </summary>
    /// <param name="password">The password to derive key from</param>
    /// <returns>Derived key as byte array</returns>
    /// <remarks>
    /// Key derivation parameters:
    /// - Uses configured salt (or empty if not specified)
    /// - Applies configured iteration count
    /// - Produces key of configured length
    /// - Uses specified hash algorithm
    /// SECURITY NOTE: Default empty salt significantly reduces security
    /// </remarks>
    private byte[] DeriveKeyFromPassword(string password)
    {
        var emptySalt = string.IsNullOrEmpty(_options.Salt) ? [] : Encoding.ASCII.GetBytes(_options.Salt);
        var iterations = _options.Iterations;
        var desiredKeyLength = _options.DesiredKeyLength;
        var hashMethod = new HashAlgorithmName(_options.HashMethod.ToString());
        
        return Rfc2898DeriveBytes.Pbkdf2(Encoding.Unicode.GetBytes(password),
            emptySalt,
            iterations,
            hashMethod,
            desiredKeyLength);
    }
    
    /// <summary>
    /// Generates or parses an initialization vector (IV) for AES operations.
    /// </summary>
    /// <param name="iv">Optional IV string</param>
    /// <returns>IV as byte array</returns>
    /// <remarks>
    /// SECURITY WARNING:
    /// - Default IV is hardcoded and INSECURE for production use
    /// - IV should be random and unique for each encryption
    /// - In production, always specify a proper IV in options
    /// </remarks>
    private static byte[] InitializationVector(string? iv)
    {
        return string.IsNullOrEmpty(iv)
            ?
            [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16
            ]
            : Encoding.ASCII.GetBytes(iv);
    }
}