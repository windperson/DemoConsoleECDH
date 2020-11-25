using System;
using System.Linq;
using System.Security.Cryptography;

namespace DemoConsoleECDH
{
    class Program
    {
        static void Main(string[] args)
        {
            string text = "ABCD";

            var ecParameters_Bob = CreateECParametersUtil.CreateECParameters(
                "71:a7:11:fb:27:f6:cf:4a:e7:cf:60:5e:40:6f:5f:9d:c1:cb:f5:e5:82:2a:89:60:42:31:dc:ff:ba:41:a2:bb:51:e4:14:47:be:05:69:5e:dd:ce:d6:e9:75:88:c4:98:70:c9:42:cb:2b:da:64:8c:b5:f1:57:57:79:2b:b2:cc",
                "68:12:bd:1c:1b:d9:32:02:42:6d:95:fc:ba:66:84:7a:b0:44:a1:d6:ba:f6:56:f9:a5:b1:5d:33:b7:d9:49:fd");

            var ecParameters_Alice = CreateECParametersUtil.CreateECParameters(
                "2ec4d77a79719da37f099ff3ab8caf150ab5979b80963bd21ad64bd42f4c28aa75fe19d01937a5e5529066474aa4100d169aa00f3ff9884bc74f6db39211dd74",
                "79fc0797c5ad4d81c55e7c6983d1e05499ba4fd5276dea2003c090eb54915a1e");

            using (var bob = new DiffieHellman(ecParameters_Bob))
            {
                using (var alice = new DiffieHellman(ecParameters_Alice))
                {
                    Console.WriteLine($"\nEncrypt public key = \n{ByteArrayToHexString(alice.PublicKey, false)}\n");

                    // Bob uses Alice's public key to encrypt his message.
                    byte[] secretMessage = bob.Encrypt(alice.PublicKey, text);

                    var transmitMsg = Convert.ToBase64String(secretMessage);
                    var hexMsg = ByteArrayToHexString(secretMessage);

                    Console.WriteLine($"encrypted base64 = {transmitMsg}");
                    Console.WriteLine($"encrypted hexStr = {hexMsg}");
                    Console.ReadKey();

                    Console.WriteLine($"\nDecrypt PublicKey = \n{ByteArrayToHexString(bob.PublicKey, false)}\nDecrypt IV = \n{ByteArrayToHexString(bob.IV, false)}\n");

                    // Alice uses Bob's public key and IV to decrypt the secret message.
                    string decryptedMessage = alice.Decrypt(bob.PublicKey, Convert.FromBase64String(transmitMsg), bob.IV);
                    Console.WriteLine($"\nBase64 decrypted = {decryptedMessage}");

                    string hexDecryptedMessage = alice.Decrypt(bob.PublicKey, HexStringToByteArray(hexMsg), bob.IV);

                    Console.WriteLine($"\nHex    decrypted = {hexDecryptedMessage}");
                }
            }
            Console.ReadKey();

        }

        public static byte[] HexStringToByteArray(string hex)
        {
            return CreateECParametersUtil.HexStringToByteArray(hex);
        }

        public static string ByteArrayToHexString(byte[] input, bool removeDash = true)
        {
            var retStr = BitConverter.ToString(input);

            return removeDash ? retStr.Replace("-", "") : retStr;
        }
    }
}
