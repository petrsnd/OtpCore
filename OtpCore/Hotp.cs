using System.Collections.Generic;

namespace OtpCore
{
    public class Hotp
    {
        public static string GetHotpCode(OtpHmacAlgorithm algorithm, byte[] secret, long counter, int digits)
        {
            var buffer = Utilities.CounterToBuffer(counter);
            var hmac = Utilities.CalculateHmac(algorithm, secret, buffer);
            return Utilities.GetTruncatedDigits(hmac, digits);
        }

        public static HotpValue[] GetHotpSequence(OtpHmacAlgorithm algorithm, byte[] secret, long counter, int sequenceLength, int digits)
        {
            var hotpValues = new List<HotpValue>();
            for (var i = counter; i < counter + sequenceLength; i++)
            {
                hotpValues.Add(new HotpValue
                {
                    Counter = i,
                    Code = GetHotpCode(algorithm, secret, i, digits)
                });
            }
            return hotpValues.ToArray();
        }
    }
}