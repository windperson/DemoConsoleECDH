using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace DemoConsoleECDH
{
    public static class CreateECParametersUtil
    {
        public static ECParameters CreateECParameters(string hexPublicKey, string hexPrivateKey)
        {
            var pubkey = HexStringToByteArray(hexPublicKey);
            var prikey = HexStringToByteArray(hexPrivateKey);

            return new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                D = prikey,
                Q = new ECPoint
                {
                    X = pubkey.Take(32).ToArray(),
                    Y = pubkey.Skip(32).ToArray()
                }
            };
        }

        public static byte[] HexStringToByteArray(string hex)
        {
            hex = hex.Replace("-", "");
            hex = hex.Replace(":", "");

            return Enumerable.Range(0, hex.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                .ToArray();
        }
    }
}
