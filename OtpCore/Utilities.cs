using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

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

        private static readonly char[] LookupTable =
        {
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
            'V', 'W', 'X', 'Y', 'Z', '2', '3', '4', '5', '6', '7'
        };
        public static string Base32Encode(byte[] buffer, bool includePadding = false)
        {
            var sb = new StringBuilder();
            for (var i = 0; i < buffer.Length; i += 5)
            {
                sb.Append(LookupTable[buffer[i] >> 3]); // byte0(bits 0 - 4)
                if (i + 1 >= buffer.Length)
                {
                    sb.Append(LookupTable[(buffer[i] & 0x07) << 2]); // byte0(bits 5 - 7)
                    if (includePadding)
                        sb.Append("======");
                }
                else
                {
                    sb.Append(LookupTable[(buffer[i] & 0x07) << 2 | (buffer[i + 1] >> 6)]); // byte0(bits 5 - 7) + byte1(bits 0 - 1)
                    sb.Append(LookupTable[(buffer[i + 1] & 0x3f) >> 1]); // byte1(bits 2 - 6)
                    if (i + 2 >= buffer.Length)
                    {
                        sb.Append(LookupTable[(buffer[i + 1] & 0x01) << 4]); // byte1(bit 7)
                        if (includePadding)
                            sb.Append("====");
                    }
                    else
                    {
                        sb.Append(LookupTable[(buffer[i + 1] & 0x01) << 4 | buffer[i + 2] >> 4]); // byte1(bit 7) + byte2(bits 0 - 3)
                        if (i + 3 >= buffer.Length)
                        {
                            sb.Append(LookupTable[(buffer[i + 2] & 0x0f) << 1]); // byte2(bits 4 - 7)
                            if (includePadding)
                                sb.Append("===");
                        }
                        else
                        {
                            sb.Append(LookupTable[(buffer[i + 2] & 0x0f) << 1 | buffer[i + 3] >> 7]); // byte2(bits 4 - 7) + byte3(bit 0)
                            sb.Append(LookupTable[(buffer[i + 3] & 0x7f) >> 2]); // byte3(bits 1 - 5)
                            if (i + 4 >= buffer.Length)
                            {
                                sb.Append(LookupTable[(buffer[i + 3] & 0x03) << 3]); // byte3(bits 6 - 7)
                                if (includePadding)
                                    sb.Append("=");
                            }
                            else
                            {
                                sb.Append(LookupTable[(buffer[i + 3] & 0x03) << 3 | buffer[i + 4] >> 5]); // byte3(bits 6 - 7) + byte4(bits 0 - 2)
                                sb.Append(LookupTable[buffer[i + 4] & 0x1f]);
                            }
                        }
                    }
                }
            }
            return sb.ToString();
        }

        public static byte[] Base32Decode(string encoded)
        {
            throw new NotImplementedException();
        }
    }
}
