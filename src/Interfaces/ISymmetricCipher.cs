namespace Toolkit.Cryptography.Interfaces;

/// <summary>
/// Defines a service for performing symmetric encryption and decryption operations.
/// </summary>
/// <remarks>
/// This interface provides asynchronous methods for encrypting and decrypting data
/// using symmetric key algorithms (typically AES). It supports both raw byte array
/// and Base64-encoded string formats.
/// </remarks>
public interface ISymmetricCipher
{
    /// <summary>
    /// Encrypts the specified plaintext string and returns the ciphertext as a byte array.
    /// </summary>
    /// <param name="clearText">The plaintext string to encrypt.</param>
    /// <returns>
    /// A task that represents the asynchronous operation. The task result contains
    /// the encrypted ciphertext as a byte array.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="clearText"/> is null.</exception>
    /// <exception cref="CryptographicException">Thrown when encryption fails.</exception>
    /// <remarks>
    /// The encryption process typically includes:
    /// 1. UTF-8 encoding of the input string
    /// 2. Generation of a cryptographically random IV (if not specified in options)
    /// 3. Encryption using AES with the configured parameters
    /// 4. Returns the IV + ciphertext combined in the byte array
    /// </remarks>
    Task<byte[]> EncryptAsync(string clearText);

    /// <summary>
    /// Encrypts the specified plaintext string and returns the ciphertext as a Base64-encoded string.
    /// </summary>
    /// <param name="clearText">The plaintext string to encrypt.</param>
    /// <returns>
    /// A task that represents the asynchronous operation. The task result contains
    /// the encrypted ciphertext as a Base64-encoded string.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="clearText"/> is null.</exception>
    /// <exception cref="CryptographicException">Thrown when encryption fails.</exception>
    /// <remarks>
    /// This method is convenient for scenarios where the ciphertext needs to be
    /// stored or transmitted as text (e.g., in JSON, XML, or URLs).
    /// The output includes both the IV and ciphertext encoded as a single Base64 string.
    /// </remarks>
    Task<string> EncryptToBase64Async(string clearText);

    /// <summary>
    /// Decrypts the specified ciphertext byte array and returns the original plaintext.
    /// </summary>
    /// <param name="encrypted">The ciphertext byte array to decrypt.</param>
    /// <returns>
    /// A task that represents the asynchronous operation. The task result contains
    /// the decrypted plaintext string.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="encrypted"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="encrypted"/> is empty or malformed.</exception>
    /// <exception cref="CryptographicException">Thrown when decryption fails (invalid key, corrupted data, etc.).</exception>
    /// <remarks>
    /// The input byte array is expected to contain both the IV and ciphertext
    /// in the same format produced by <see cref="EncryptAsync"/>.
    /// </remarks>
    Task<string> DecryptAsync(byte[] encrypted);

    /// <summary>
    /// Decrypts the specified Base64-encoded ciphertext and returns the original plaintext.
    /// </summary>
    /// <param name="encrypted">The Base64-encoded ciphertext string to decrypt.</param>
    /// <returns>
    /// A task that represents the asynchronous operation. The task result contains
    /// the decrypted plaintext string.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="encrypted"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="encrypted"/> is empty or malformed.</exception>
    /// <exception cref="FormatException">Thrown when the input is not valid Base64.</exception>
    /// <exception cref="CryptographicException">Thrown when decryption fails (invalid key, corrupted data, etc.).</exception>
    /// <remarks>
    /// This method is the counterpart to <see cref="EncryptToBase64Async"/>, handling
    /// ciphertext that was encoded as Base64 for text-based storage or transmission.
    /// </remarks>
    Task<string> DecryptFromBase64Async(string encrypted);
}