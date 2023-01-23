﻿using System;
using Xunit;

namespace Petrsnd.OtpCore.Test
{
    public class TotpAuthenticatorTest
    {
        [Fact]
        public void TotpAuthenticatorCreation()
        {
            Assert.Throws<ArgumentException>(() => Totp.GetAuthenticator(
                "otpauth://hotp/NOBODY:petrsnd@gmail.com?issuer=NOBODY&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&algorithm=SHA256&digits=8&counter=12"));
            var uriString =
                "otpauth://totp/NOBODY:petrsnd@gmail.com?issuer=NOBODY&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&algorithm=SHA256&digits=8";
            var authenticator = Totp.GetAuthenticator(uriString);
            Assert.True(UriComparer.AreEqual(authenticator.ToString(), uriString));
            Assert.NotNull(authenticator.GetCode());
            Assert.NotEmpty(authenticator.GetCode());
            Assert.NotEmpty(authenticator.GetRange(TimeSpan.Zero));
        }

        [Fact]
        public void TotpAuthenticatorPeriodZero()
        {
            var uriString =
                "otpauth://totp/NOBODY:petrsnd@gmail.com?issuer=NOBODY&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&period=0";
            Assert.Throws<ArgumentException>(() => Totp.GetAuthenticator(uriString));
            Assert.Throws<ArgumentException>(() => new OtpAuthUri(uriString));
            Assert.Throws<ArgumentOutOfRangeException>(() =>
                new OtpAuthUri(OtpType.Totp, new byte[] { 0x00 }, "petrsnd@gmail.com", "NOBODY", 0));
            Assert.Throws<ArgumentOutOfRangeException>(() =>
                Totp.GetTotpCode(new byte[] { 0x00 }, DateTimeOffset.Now, 0, OtpHmacAlgorithm.HmacSha1, 6));
            Assert.Throws<ArgumentOutOfRangeException>(() =>
                Totp.GetTotpRange(new byte[] { 0x00 }, DateTimeOffset.Now, TimeSpan.FromMinutes(3), 0,
                    OtpHmacAlgorithm.HmacSha1, 6));
        }

        [Fact]
        public void GetCode()
        {
            var uriString =
                "otpauth://totp/NOBODY:petrsnd@gmail.com?issuer=NOBODY&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&algorithm=SHA256&digits=8";
            var authenticator = Totp.GetAuthenticator(uriString);
            Assert.True(UriComparer.AreEqual(authenticator.ToString(), uriString));
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
