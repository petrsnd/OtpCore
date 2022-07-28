using System.Text;
using Xunit;

namespace Petrsnd.OtpCore.Test
{
    public class HotpTest
    {
        [Fact]
        public void GetHotpCode()
        {
            // Test values from RFC 4226 Appendix D
            // secret
            var secret = Encoding.ASCII.GetBytes("12345678901234567890");
            Assert.Equal(
                new byte[]
                {
                    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
                    0x37, 0x38, 0x39, 0x30
                }, secret);
            // counter values 0 through 9
            Assert.Equal("755224", Hotp.GetHotpCode(secret, 0, OtpHmacAlgorithm.HmacSha1, 6));
            Assert.Equal("287082", Hotp.GetHotpCode(secret, 1, OtpHmacAlgorithm.HmacSha1, 6));
            Assert.Equal("359152", Hotp.GetHotpCode(secret, 2, OtpHmacAlgorithm.HmacSha1, 6));
            Assert.Equal("969429", Hotp.GetHotpCode(secret, 3, OtpHmacAlgorithm.HmacSha1, 6));
            Assert.Equal("338314", Hotp.GetHotpCode(secret, 4, OtpHmacAlgorithm.HmacSha1, 6));
            Assert.Equal("254676", Hotp.GetHotpCode(secret, 5, OtpHmacAlgorithm.HmacSha1, 6));
            Assert.Equal("287922", Hotp.GetHotpCode(secret, 6, OtpHmacAlgorithm.HmacSha1, 6));
            Assert.Equal("162583", Hotp.GetHotpCode(secret, 7, OtpHmacAlgorithm.HmacSha1, 6));
            Assert.Equal("399871", Hotp.GetHotpCode(secret, 8, OtpHmacAlgorithm.HmacSha1, 6));
            Assert.Equal("520489", Hotp.GetHotpCode(secret, 9, OtpHmacAlgorithm.HmacSha1, 6));
        }

        [Fact]
        public void GetHotpSequence()
        {
            // Test values from RFC 4226 Appendix D
            // secret
            var secret = Encoding.ASCII.GetBytes("12345678901234567890");
            Assert.Equal(
                new byte[]
                {
                    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
                    0x37, 0x38, 0x39, 0x30
                }, secret);
            // counter values 0 through 9
            var hotpValues = Hotp.GetHotpSequence(secret, 0, 10, OtpHmacAlgorithm.HmacSha1, 6);
            Assert.Equal(10, hotpValues.Length);
            Assert.Equal(0, hotpValues[0].Counter);
            Assert.Equal("755224", hotpValues[0].Code);
            Assert.Equal(1, hotpValues[1].Counter);
            Assert.Equal("287082", hotpValues[1].Code);
            Assert.Equal(2, hotpValues[2].Counter);
            Assert.Equal("359152", hotpValues[2].Code);
            Assert.Equal(3, hotpValues[3].Counter);
            Assert.Equal("969429", hotpValues[3].Code);
            Assert.Equal(4, hotpValues[4].Counter);
            Assert.Equal("338314", hotpValues[4].Code);
            Assert.Equal(5, hotpValues[5].Counter);
            Assert.Equal("254676", hotpValues[5].Code);
            Assert.Equal(6, hotpValues[6].Counter);
            Assert.Equal("287922", hotpValues[6].Code);
            Assert.Equal(7, hotpValues[7].Counter);
            Assert.Equal("162583", hotpValues[7].Code);
            Assert.Equal(8, hotpValues[8].Counter);
            Assert.Equal("399871", hotpValues[8].Code);
            Assert.Equal(9, hotpValues[9].Counter);
            Assert.Equal("520489", hotpValues[9].Code);
        }
    }
}
