using System;
using System.Text;
using OtpCore;
using Xunit;

namespace TestOtpCore
{
    public class TotpTest
    {
        [Fact]
        public void GetTotpCode()
        {
            // Test values from RFC 6238 Appendix B
            // secret -- HMAC-SHA1
            var secret = Encoding.ASCII.GetBytes("12345678901234567890");
            Assert.Equal(
                new byte[]
                {
                    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
                    0x37, 0x38, 0x39, 0x30
                }, secret);
            // secret 32 -- HMAC-SHA256
            var secret32 = Encoding.ASCII.GetBytes("12345678901234567890123456789012");
            Assert.Equal(
                new byte[]
                {
                    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
                    0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32
                }, secret32);
            // secret 64 -- HMAC-SHA256
            var secret64 = Encoding.ASCII.GetBytes("1234567890123456789012345678901234567890123456789012345678901234");
            Assert.Equal(
                new byte[]
                {
                    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
                    0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32,
                    0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                    0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34
                }, secret64);
            // Call Unix time directly
            Assert.Equal("94287082", Totp.GetTotpCode(secret, 59, 30, OtpHmacAlgorithm.HmacSha1, 8));
            Assert.Equal("46119246", Totp.GetTotpCode(secret32, 59, 30, OtpHmacAlgorithm.HmacSha256, 8));
            Assert.Equal("90693936", Totp.GetTotpCode(secret64, 59, 30, OtpHmacAlgorithm.HmacSha512, 8));

            Assert.Equal("07081804", Totp.GetTotpCode(secret, 1111111109, 30, OtpHmacAlgorithm.HmacSha1, 8));
            Assert.Equal("68084774", Totp.GetTotpCode(secret32, 1111111109, 30, OtpHmacAlgorithm.HmacSha256, 8));
            Assert.Equal("25091201", Totp.GetTotpCode(secret64, 1111111109, 30, OtpHmacAlgorithm.HmacSha512, 8));

            Assert.Equal("14050471", Totp.GetTotpCode(secret, 1111111111, 30, OtpHmacAlgorithm.HmacSha1, 8));
            Assert.Equal("67062674", Totp.GetTotpCode(secret32, 1111111111, 30, OtpHmacAlgorithm.HmacSha256, 8));
            Assert.Equal("99943326", Totp.GetTotpCode(secret64, 1111111111, 30, OtpHmacAlgorithm.HmacSha512, 8));

            Assert.Equal("89005924", Totp.GetTotpCode(secret, 1234567890, 30, OtpHmacAlgorithm.HmacSha1, 8));
            Assert.Equal("91819424", Totp.GetTotpCode(secret32, 1234567890, 30, OtpHmacAlgorithm.HmacSha256, 8));
            Assert.Equal("93441116", Totp.GetTotpCode(secret64, 1234567890, 30, OtpHmacAlgorithm.HmacSha512, 8));

            Assert.Equal("69279037", Totp.GetTotpCode(secret, 2000000000, 30, OtpHmacAlgorithm.HmacSha1, 8));
            Assert.Equal("90698825", Totp.GetTotpCode(secret32, 2000000000, 30, OtpHmacAlgorithm.HmacSha256, 8));
            Assert.Equal("38618901", Totp.GetTotpCode(secret64, 2000000000, 30, OtpHmacAlgorithm.HmacSha512, 8));

            Assert.Equal("65353130", Totp.GetTotpCode(secret, 20000000000, 30, OtpHmacAlgorithm.HmacSha1, 8));
            Assert.Equal("77737706", Totp.GetTotpCode(secret32, 20000000000, 30, OtpHmacAlgorithm.HmacSha256, 8));
            Assert.Equal("47863826", Totp.GetTotpCode(secret64, 20000000000, 30, OtpHmacAlgorithm.HmacSha512, 8));

            // Call with DateTimeOffset
            var time1 = DateTimeOffset.Parse("1970-01-01 00:00:59 +0:00");
            Assert.Equal("94287082", Totp.GetTotpCode(secret, time1, 30, OtpHmacAlgorithm.HmacSha1, 8));
            Assert.Equal("46119246", Totp.GetTotpCode(secret32, time1, 30, OtpHmacAlgorithm.HmacSha256, 8));
            Assert.Equal("90693936", Totp.GetTotpCode(secret64, time1, 30, OtpHmacAlgorithm.HmacSha512, 8));

            var time2 = DateTimeOffset.Parse("2005-03-18 01:58:29 +0:00");
            Assert.Equal("07081804", Totp.GetTotpCode(secret, time2, 30, OtpHmacAlgorithm.HmacSha1, 8));
            Assert.Equal("68084774", Totp.GetTotpCode(secret32, time2, 30, OtpHmacAlgorithm.HmacSha256, 8));
            Assert.Equal("25091201", Totp.GetTotpCode(secret64, time2, 30, OtpHmacAlgorithm.HmacSha512, 8));

            var time3 = DateTimeOffset.Parse("2005-03-18 01:58:31 +0:00");
            Assert.Equal("14050471", Totp.GetTotpCode(secret, time3, 30, OtpHmacAlgorithm.HmacSha1, 8));
            Assert.Equal("67062674", Totp.GetTotpCode(secret32, time3, 30, OtpHmacAlgorithm.HmacSha256, 8));
            Assert.Equal("99943326", Totp.GetTotpCode(secret64, time3, 30, OtpHmacAlgorithm.HmacSha512, 8));

            var time4 = DateTimeOffset.Parse("2009-02-13 23:31:30 +0:00");
            Assert.Equal("89005924", Totp.GetTotpCode(secret, time4, 30, OtpHmacAlgorithm.HmacSha1, 8));
            Assert.Equal("91819424", Totp.GetTotpCode(secret32, time4, 30, OtpHmacAlgorithm.HmacSha256, 8));
            Assert.Equal("93441116", Totp.GetTotpCode(secret64, time4, 30, OtpHmacAlgorithm.HmacSha512, 8));

            var time5 = DateTimeOffset.Parse("2033-05-18 03:33:20 +0:00");
            Assert.Equal("69279037", Totp.GetTotpCode(secret, time5, 30, OtpHmacAlgorithm.HmacSha1, 8));
            Assert.Equal("90698825", Totp.GetTotpCode(secret32, time5, 30, OtpHmacAlgorithm.HmacSha256, 8));
            Assert.Equal("38618901", Totp.GetTotpCode(secret64, time5, 30, OtpHmacAlgorithm.HmacSha512, 8));

            var time6 = DateTimeOffset.Parse("2603-10-11 11:33:20 +0:00");
            Assert.Equal("65353130", Totp.GetTotpCode(secret, time6, 30, OtpHmacAlgorithm.HmacSha1, 8));
            Assert.Equal("77737706", Totp.GetTotpCode(secret32, time6, 30, OtpHmacAlgorithm.HmacSha256, 8));
            Assert.Equal("47863826", Totp.GetTotpCode(secret64, time6, 30, OtpHmacAlgorithm.HmacSha512, 8));

            // Test with Timezone
            var timeWithZone = DateTimeOffset.Parse("2009-02-13 16:31:30 -7:00");
            Assert.Equal("89005924", Totp.GetTotpCode(secret, timeWithZone, 30, OtpHmacAlgorithm.HmacSha1, 8));
            Assert.Equal("91819424", Totp.GetTotpCode(secret32, timeWithZone, 30, OtpHmacAlgorithm.HmacSha256, 8));
            Assert.Equal("93441116", Totp.GetTotpCode(secret64, timeWithZone, 30, OtpHmacAlgorithm.HmacSha512, 8));
        }
    }
}
