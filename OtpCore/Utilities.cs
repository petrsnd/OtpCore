using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace OtpCore
{
    public static class Utilities
    {
        public static byte[] CounterToBuffer(long counter)
        {
            var counterBytes = new List<byte>();
            while (counter != 0)
            {
                counterBytes.Add((byte)(counter & 0xff));
                counter >>= 8;
            }
            while (counterBytes.Count < 8)
                counterBytes.Add(0);
            counterBytes.Reverse();
            return counterBytes.ToArray();
        }

        public static byte[] CalculateHmac(OtpHmacAlgorithm algorithm, byte[] key, byte[] buffer)
        {
            HMAC hmacAlg = null;
            try
            {
                switch (algorithm)
                {
                    case OtpHmacAlgorithm.HmacSha1:
                        hmacAlg = new HMACSHA1(key);
                        break;
                    case OtpHmacAlgorithm.HmacSha256:
                        hmacAlg = new HMACSHA256(key);
                        break;
                    case OtpHmacAlgorithm.HmacSha384:
                        hmacAlg = new HMACSHA384(key);
                        break;
                    case OtpHmacAlgorithm.HmacSha512:
                        hmacAlg = new HMACSHA512(key);
                        break;
                    default:
                        throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "No such hash algorithm");
                }
                hmacAlg.ComputeHash(buffer);
                return hmacAlg.Hash;
            }
            finally
            {
                hmacAlg?.Dispose();
            }
        }

        private static readonly int[] DigitsPower = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000 };
        public static string GetTruncatedDigits(byte[] hmac, int digits)
        {
            // Assumes dynamic truncation algorithm from RFC 4226 5.3
            var offset = hmac[hmac.Length - 1] & 0xf;
            var truncated =
                ((hmac[offset] & 0x7f) << 24)
                | ((hmac[offset + 1] & 0xff) << 16)
                | ((hmac[offset + 2] & 0xff) << 8)
                | (hmac[offset + 3] & 0xff);
            var otp = truncated % DigitsPower[digits];
            var result = $"{otp}";
            // prefix string with 0s to get desired number of digits
            while (result.Length < digits)
            {
                result = "0" + result;
            }
            return result;
        }
    }
}
