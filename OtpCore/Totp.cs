using System;

namespace OtpCore
{
    public class Totp
    {
        public static string GetTotpCode(byte[] secret, long unixTime, int period, OtpHmacAlgorithm algorithm, int digits)
        {
            var counter = unixTime / period;
            return Hotp.GetHotpCode(secret, counter, algorithm, digits);
        }

        public static string GetTotpCode(byte[] secret, DateTimeOffset time, int period, OtpHmacAlgorithm algorithm, int digits)
        {
            var unixTime = time.ToUniversalTime().ToUnixTimeSeconds();
            return GetTotpCode(secret, unixTime, period, algorithm, digits);
        }
    }
}
