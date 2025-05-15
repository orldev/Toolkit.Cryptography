using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Toolkit.Cryptography;

public class CryptographyOptions
{
    [AllowNull]
    public string Passphrase { get; set; }
    
    /// <summary>
    /// An initialization vector is required to implement AES
    /// </summary>
    public string? IV { get; set; }
    
    public string? Salt { get; set; }

    // MARK: For Rfc2898DeriveBytes.Pbkdf2
    public int Iterations { get; set; } = 1000;
    
    /// <summary>
    /// 16 bytes equal 128 bits
    /// </summary>
    public int DesiredKeyLength { get; set; } = 16;
    
    public HashAlgorithm HashMethod { get; set; } = HashAlgorithm.SHA384;
}