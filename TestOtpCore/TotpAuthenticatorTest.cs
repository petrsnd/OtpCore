using System;
using Xunit;

namespace Petrsnd.OtpCore.Test
{
    public class TotpAuthenticatorTest
    {
        [Fact]
        public void TotpAuthenticatorCreation()
        {
            var authenticator =
                Totp.GetAuthenticator(
                    "otpauth://totp/NOBODY:petrsnd@gmail.com?issuer=NOBODY&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&algorithm=SHA256&digits=8");
            Assert.Equal(
                "otpauth://totp/NOBODY:petrsnd@gmail.com?issuer=NOBODY&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&algorithm=SHA256&digits=8",
                authenticator.ToString());
            Assert.NotNull(authenticator.GetCode());
            Assert.NotEmpty(authenticator.GetCode());
            Assert.NotEmpty(authenticator.GetRange(TimeSpan.Zero));
        }

        [Fact]
        public void GetCode()
        {
            var authenticator =
                Totp.GetAuthenticator(
                    "otpauth://totp/NOBODY:petrsnd@gmail.com?issuer=NOBODY&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&algorithm=SHA256&digits=8");
            Assert.Equal(
                "otpauth://totp/NOBODY:petrsnd@gmail.com?issuer=NOBODY&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&algorithm=SHA256&digits=8",
                authenticator.ToString());
            Assert.Equal("46119246", authenticator.GetCode(DateTimeOffset.Parse("1970-01-01 00:00:59 +0:00")));
        }

        [Fact]
        public void GetRange()
        {
            // There is no way to unit test for date time NOW
            var authenticator =
                Totp.GetAuthenticator(
                    "otpauth://totp/NOBODY:petrsnd@gmail.com?issuer=NOBODY&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA1&digits=6");

            var range = authenticator.GetRange(DateTimeOffset.Parse("1970-01-01 00:00:29 +0:00"),
                TimeSpan.FromSeconds(299));
            Assert.Equal(10, range.Length);
            Assert.Equal("755224", range[0].Code);
            Assert.Equal("287082", range[1].Code);
            Assert.Equal("359152", range[2].Code);
            Assert.Equal("969429", range[3].Code);
            Assert.Equal("338314", range[4].Code);
            Assert.Equal("254676", range[5].Code);
            Assert.Equal("287922", range[6].Code);
            Assert.Equal("162583", range[7].Code);
            Assert.Equal("399871", range[8].Code);
            Assert.Equal("520489", range[9].Code);
        }
    }
}
