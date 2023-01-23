using System;
using System.Collections.Generic;

namespace Petrsnd.OtpCore
{
    public class Totp
    {
        public static string GetTotpCode(byte[] secret, long unixTime, int period, OtpHmacAlgorithm algorithm, int digits)
        {
            if (period < 1 || period > 3600)
                throw new ArgumentOutOfRangeException(nameof(period),
                    "TOTP period, or time step, must be between 1 second and 1 hour");
            var counter = unixTime / period;
            return Hotp.GetHotpCode(secret, counter, algorithm, digits);
        }

        public static string GetTotpCode(byte[] secret, DateTimeOffset time, int period, OtpHmacAlgorithm algorithm, int digits)
        {
            var unixTime = time.ToUniversalTime().ToUnixTimeSeconds();
            return GetTotpCode(secret, unixTime, period, algorithm, digits);
        }

        public static TotpValue[] GetTotpRange(byte[] secret, long unixTime, int rangeSeconds, int period,
            OtpHmacAlgorithm algorithm, int digits)
        {
            if (period < 1 || period > 3600)
                throw new ArgumentOutOfRangeException(nameof(period),
                    "TOTP period, or time step, must be between 1 second and 1 hour");
            var totpValues = new List<TotpValue>();
            for (var i = unixTime; i <= unixTime + rangeSeconds; i += period)
            {
                var counter = i / period;
                var code = Hotp.GetHotpCode(secret, counter, algorithm, digits);
                var intervalStart = counter * period;
                totpValues.Add(new TotpValue
                {
                    TimeStamp = DateTimeOffset.FromUnixTimeSeconds(intervalStart),
                    UnixTime = intervalStart,
                    Counter = counter,
                    Period = period,
                    Code = code
                });
            }
            return totpValues.ToArray();
        }

        public static TotpValue[] GetTotpRange(byte[] secret, DateTimeOffset time, TimeSpan range, int period,
            OtpHmacAlgorithm algorithm, int digits)
        {
            var unixTime = time.ToUniversalTime().ToUnixTimeSeconds();
            var rangeSeconds = Convert.ToInt32(range.TotalSeconds);
            return GetTotpRange(secret, unixTime, rangeSeconds, period, algorithm, digits);
        }

        public static TotpAuthenticator GetAuthenticator(string uriString)
        {
            return GetAuthenticator(new Uri(uriString));
        }

        public static TotpAuthenticator GetAuthenticator(Uri uri)
        {
            return GetAuthenticator(new OtpAuthUri(uri));
        }

        public static TotpAuthenticator GetAuthenticator(OtpAuthUri otpAuthUri)
        {
            return new TotpAuthenticator(otpAuthUri);
        }
    }
}
