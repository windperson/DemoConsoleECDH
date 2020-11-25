using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace DemoConsoleECDH
{
    public class DiffieHellman : IDisposable
    {
        private readonly Aes _aes = null;
        private readonly ECDiffieHellman _diffieHellman = null;
        private ECDiffieHellmanPublicKey _publicKey = null;


        public DiffieHellman(ECParameters? parameters = null)
        {
            _aes = new AesCryptoServiceProvider();

            _diffieHellman = parameters.HasValue ? ECDiffieHellman.Create(parameters.Value) : ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

            // This is the public key we will send to the other party
            _publicKey = _diffieHellman.PublicKey;
        }

        public byte[] PublicKey
        {
            get
            {
                try
                {
                    if (OperatingSystem.IsWindows())
                    {
                        return _publicKey.ToByteArray();
                    }
                    else
                    {
                        var sslEcdh = new ECDiffieHellmanOpenSsl(ECCurve.NamedCurves.nistP256);
                        return sslEcdh.DeriveKeyMaterial(_publicKey);
                    }
                }
                catch (PlatformNotSupportedException)
                {
                    return _diffieHellman.DeriveKeyMaterial(_publicKey);
                }
            }
        }

        public byte[] IV => _aes.IV;

        public byte[] Encrypt(byte[] publicKey, string secretMessage)
        {
            try
            {
                var ecdhKey = GetEcdhKey(publicKey);
                var derivedKey = _diffieHellman.DeriveKeyMaterial(ecdhKey);

                _aes.Key = derivedKey;
            }
            catch (PlatformNotSupportedException)
            {
                _aes.Key = publicKey;
            }

            byte[] encryptedMessage;
            using (var cipherText = new MemoryStream())
            {
                using (var encryptor = _aes.CreateEncryptor())
                {
                    using (var cryptoStream = new CryptoStream(cipherText, encryptor, CryptoStreamMode.Write))
                    {
                        byte[] buffer = Encoding.UTF8.GetBytes(secretMessage);
                        cryptoStream.Write(buffer, 0, buffer.Length);
                    }
                }

                encryptedMessage = cipherText.ToArray();
            }

            return encryptedMessage;
        }

        private static ECDiffieHellmanPublicKey GetEcdhKey(byte[] publicKey)
        {
            //see: https://stackoverflow.com/a/22239489/1075882
            return ECDiffieHellmanCngPublicKey.FromByteArray(publicKey, CngKeyBlobFormat.EccPublicBlob);
        }

        public string Decrypt(byte[] publicKey, byte[] encryptedMessage, byte[] iv)
        {
            try
            {
                var ecdhKey = GetEcdhKey(publicKey);
                var derivedKey = _diffieHellman.DeriveKeyMaterial(ecdhKey);

                _aes.Key = derivedKey;
            }
            catch (PlatformNotSupportedException)
            {
                _aes.Key = publicKey;
            }

            _aes.IV = iv;

            string decryptedMessage;
            using (var plainText = new MemoryStream())
            {
                using (var decryptor = this._aes.CreateDecryptor())
                {
                    using (var cryptoStream = new CryptoStream(plainText, decryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(encryptedMessage, 0, encryptedMessage.Length);
                    }
                }

                decryptedMessage = Encoding.UTF8.GetString(plainText.ToArray());
            }

            return decryptedMessage;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                _aes?.Dispose();

                _diffieHellman?.Dispose();
            }
        }
    }
}
