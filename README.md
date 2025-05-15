## Toolkit.Cryptography

Extension for the framework `System.Security.Cryptography`

#### Sources
- [Encrypting and Decrypting a String in C#](https://code-maze.com/csharp-string-encryption-decryption/)

#### Connecting the configuration

```c#
builder.Services.AddCryptography(o =>
{
    o.Passphrase = "123456";
    o.IV = "abcede0123456789";
});
```
or
```c# 
builder.Services.AddCryptography(builder.Configuration);
```
or
```c# 
builder.Services.AddCryptography();
```

Encrypt data
```c#
var encryptToBase64 = await _cryptography.EncryptToBase64Async(string);
```

Decrypt data
```c#
var decryptFromBase64 = await _cryptography.DecryptFromBase64Async(string);
```

#### Sample configuration appsettings.json

```json lines
{
  "Cryptography": {
    "Passphrase" : "0123456789",
    "IV" : "abcede0123456789",
    "Salt" : "0123456789abcede",
    "Iterations" : 1000,
    "DesiredKeyLength" : 16, // 16 bytes equal 128 bits. Max 256 bits
    "HashMethod" : "SHA384"
  }
}
```

The name of the algorithm supported by cryptographic hashing `HashMethod`.
- SHA1
- SHA256
- SHA384
- SHA512

This is an unsupported hashing algorithm.
- MD5
- SHA3-256
- SHA3-384
- SHA3-512

## License

Toolkit.Cryptography is a free and open source project, released under the permissible [MIT license](LICENSE).

