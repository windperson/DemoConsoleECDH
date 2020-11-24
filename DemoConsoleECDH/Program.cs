using System;
using System.Linq;

namespace DemoConsoleECDH
{
    class Program
    {
        static void Main(string[] args)
        {
            string text = "ABCD";

            using (var bob = new DiffieHellman())
            {
                using (var alice = new DiffieHellman())
                {
                    // Bob uses Alice's public key to encrypt his message.
                    byte[] secretMessage = bob.Encrypt(alice.PublicKey, text);

                    var transmitMsg = Convert.ToBase64String(secretMessage);
                    var hexMsg = BitConverter.ToString(secretMessage).Replace("-", "");

                    Console.WriteLine($"encrypted base64 = {transmitMsg}");
                    Console.WriteLine($"encrypted hexStr = {hexMsg}");
                    Console.ReadKey();

                    // Alice uses Bob's public key and IV to decrypt the secret message.
                    //string decryptedMessage = alice.Decrypt(bob.PublicKey, Convert.FromBase64String(transmitMsg), bob.IV);
                    
                    string decryptedMessage = alice.Decrypt(bob.PublicKey, StringToByteArray(hexMsg), bob.IV);

                    Console.WriteLine($"\ndecrypted = {decryptedMessage}");
                }
            }
            Console.ReadKey();

        }

        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }
    }
}
