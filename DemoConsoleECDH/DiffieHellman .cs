using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
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

            _diffieHellman = parameters.HasValue ? ECDiffieHellman.Create(parameters.Value) : ECDiffieHellman.Create();
            
            // This is the public key we will send to the other party
            _publicKey = _diffieHellman.PublicKey;
        }
        public byte[] PublicKey => _publicKey.ToByteArray();

        public byte[] IV => _aes.IV;

        public byte[] Encrypt(byte[] publicKey, string secretMessage)
        {
            var ecdhKey = GetEcdhKey(publicKey);
            var derivedKey = _diffieHellman.DeriveKeyMaterial(ecdhKey);

            _aes.Key = derivedKey;

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

        private ECDiffieHellmanPublicKey GetEcdhKey(byte[] publicKey)
        {
            return ECDiffieHellmanCngPublicKey.FromByteArray(publicKey, CngKeyBlobFormat.EccPublicBlob);
        }

        public string Decrypt(byte[] publicKey, byte[] encryptedMessage, byte[] iv)
        {
            var ecdhKey = GetEcdhKey(publicKey);
            var derivedKey = _diffieHellman.DeriveKeyMaterial(ecdhKey);
            _aes.Key = derivedKey;

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
