using System.Collections.Generic;

namespace Petrsnd.OtpCore
{
    public class Hotp
    {
        public static string GetHotpCode(byte[] secret, long counter, OtpHmacAlgorithm algorithm, int digits)
        {
            var buffer = Utilities.CounterToBuffer(counter);
            var hmac = Utilities.CalculateHmac(algorithm, secret, buffer);
            return Utilities.GetTruncatedDigits(hmac, digits);
        }

        public static HotpValue[] GetHotpSequence(byte[] secret, long counter, int sequenceLength, OtpHmacAlgorithm algorithm, int digits)
        {
            var hotpValues = new List<HotpValue>();
            for (var i = counter; i < counter + sequenceLength; i++)
            {
                hotpValues.Add(new HotpValue
                {
                    Counter = i,
                    Code = GetHotpCode(secret, i, algorithm, digits)
                });
            }
            return hotpValues.ToArray();
        }
    }
}