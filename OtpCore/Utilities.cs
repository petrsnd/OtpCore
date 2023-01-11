using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Petrsnd.OtpCore
{
    public static class Utilities
    {
        internal static string OtpHmacAlgorithmToString(OtpHmacAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case OtpHmacAlgorithm.HmacSha1:
                    return "SHA1";
                case OtpHmacAlgorithm.HmacSha256:
                    return "SHA256";
                case OtpHmacAlgorithm.HmacSha384:
                    return "SHA384";
                case OtpHmacAlgorithm.HmacSha512:
                    return "SHA512";
                default:
                    throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "No such hash algorithm");
            }
        }

        public static byte[] CounterToBuffer(long counter)
        {
            if (counter < 0)
                throw new ArgumentOutOfRangeException(nameof(counter), counter,
                    "Counter is a signed integer but must be positive");
            var counterBytes = new List<byte>();
            while (counter > 0)
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

        private static readonly long[] DigitsPower =
            { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000, 10000000000 };
        public static string GetTruncatedDigits(byte[] hmac, int digits)
        {
            if (digits < 6 || digits > 10)
                throw new ArgumentException("Code digits length must be between 6 and 10", nameof(digits));
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
                result = "0" + result;

            return result;
        }

        private static readonly char[] LookupEncoding =
        {
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
            'V', 'W', 'X', 'Y', 'Z', '2', '3', '4', '5', '6', '7'
        };
        public static string Base32Encode(byte[] buffer, bool includePadding = false)
        {
            if (buffer == null)
                return "";

            var sb = new StringBuilder();
            for (var i = 0; i < buffer.Length; i += 5)
            {
                sb.Append(LookupEncoding[buffer[i] >> 3]); // byte0(bits 0 - 4)
                if (i + 1 >= buffer.Length)
                {
                    sb.Append(LookupEncoding[(buffer[i] & 0x07) << 2]); // byte0(bits 5 - 7)
                    if (includePadding)
                        sb.Append("======");
                }
                else
                {
                    sb.Append(LookupEncoding[(buffer[i] & 0x07) << 2 | (buffer[i + 1] >> 6)]); // byte0(bits 5 - 7) + byte1(bits 0 - 1)
                    sb.Append(LookupEncoding[(buffer[i + 1] & 0x3f) >> 1]); // byte1(bits 2 - 6)
                    if (i + 2 >= buffer.Length)
                    {
                        sb.Append(LookupEncoding[(buffer[i + 1] & 0x01) << 4]); // byte1(bit 7)
                        if (includePadding)
                            sb.Append("====");
                    }
                    else
                    {
                        sb.Append(LookupEncoding[(buffer[i + 1] & 0x01) << 4 | buffer[i + 2] >> 4]); // byte1(bit 7) + byte2(bits 0 - 3)
                        if (i + 3 >= buffer.Length)
                        {
                            sb.Append(LookupEncoding[(buffer[i + 2] & 0x0f) << 1]); // byte2(bits 4 - 7)
                            if (includePadding)
                                sb.Append("===");
                        }
                        else
                        {
                            sb.Append(LookupEncoding[(buffer[i + 2] & 0x0f) << 1 | buffer[i + 3] >> 7]); // byte2(bits 4 - 7) + byte3(bit 0)
                            sb.Append(LookupEncoding[(buffer[i + 3] & 0x7f) >> 2]); // byte3(bits 1 - 5)
                            if (i + 4 >= buffer.Length)
                            {
                                sb.Append(LookupEncoding[(buffer[i + 3] & 0x03) << 3]); // byte3(bits 6 - 7)
                                if (includePadding)
                                    sb.Append("=");
                            }
                            else
                            {
                                sb.Append(LookupEncoding[(buffer[i + 3] & 0x03) << 3 | buffer[i + 4] >> 5]); // byte3(bits 6 - 7) + byte4(bits 0 - 2)
                                sb.Append(LookupEncoding[buffer[i + 4] & 0x1f]);
                            }
                        }
                    }
                }
            }
            return sb.ToString();
        }

        private static readonly byte[] LookupDecoding =
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //  0-15  PAD
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 16-31  PAD
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 32-47  PAD
            0x00, 0x00, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 48-63  PAD, at 50 (chars 2-7), PAD
            0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, // 64-79  PAD, at 65 (chars A-O)
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19                                // 80-90  (chars P-Z)
        };

        private static readonly HashSet<char> ValidCharacters = new HashSet<char>("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567");
        public static byte[] Base32Decode(string encoded)
        {
            if (encoded == null)
                return new byte[] { };
            var trimmed = new string(encoded.Where(c => !char.IsWhiteSpace(c)).ToArray()).TrimEnd('=').ToUpper();
            if (trimmed.Any(c => !ValidCharacters.Contains(c)))
                throw new ArgumentException("The encoded string contains invalid RFC 4648 base32 characters");
            var buffer = new byte[(trimmed.Length * 5) / 8];
            for (var i = 0; i < trimmed.Length; i += 8)
            {
                var j = (i * 5) / 8;
                buffer[j] = (byte)(LookupDecoding[trimmed[i]] << 3);
                buffer[j] |= (byte)(LookupDecoding[trimmed[i + 1]] >> 2);
                if (j + 1 >= buffer.Length)
                    break;
                buffer[j + 1] = (byte)(LookupDecoding[trimmed[i + 1]] << 6);
                buffer[j + 1] |= (byte)(LookupDecoding[trimmed[i + 2]] << 1);
                buffer[j + 1] |= (byte)(LookupDecoding[trimmed[i + 3]] >> 4);
                if (j + 2 >= buffer.Length)
                    break;
                buffer[j + 2] = (byte)(LookupDecoding[trimmed[i + 3]] << 4);
                buffer[j + 2] |= (byte)(LookupDecoding[trimmed[i + 4]] >> 1);
                if (j + 3 >= buffer.Length)
                    break;
                buffer[j + 3] = (byte)(LookupDecoding[trimmed[i + 4]] << 7);
                buffer[j + 3] |= (byte)(LookupDecoding[trimmed[i + 5]] << 2);
                buffer[j + 3] |= (byte)(LookupDecoding[trimmed[i + 6]] >> 3);
                if (j + 4 >= buffer.Length)
                    break;
                buffer[j + 4] = (byte)(LookupDecoding[trimmed[i + 6]] << 5);
                buffer[j + 4] |= LookupDecoding[trimmed[i + 7]];
            }
            return buffer;
        }
    }
}
