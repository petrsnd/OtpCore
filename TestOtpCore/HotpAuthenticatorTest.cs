﻿using System;
using Xunit;

namespace Petrsnd.OtpCore.Test
{
    public class HotpAuthenticatorTest
    {
        [Fact]
        public void HotpAuthenticatorCreation()
        {
            Assert.Throws<ArgumentException>(() => Hotp.GetAuthenticator(
                "otpauth://totp/NOBODY:petrsnd@gmail.com?issuer=NOBODY&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&algorithm=SHA256&digits=8"));
            Assert.Throws<ArgumentException>(() => Hotp.GetAuthenticator(
                "otpauth://hotp/NOBODY:petrsnd@gmail.com?issuer=NOBODY&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&algorithm=SHA256&digits=8"));
            var authenticator =
                Hotp.GetAuthenticator(
                    "otpauth://hotp/NOBODY:petrsnd@gmail.com?issuer=NOBODY&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&algorithm=SHA256&digits=8&counter=12");
            Assert.Equal(
                "otpauth://hotp/NOBODY:petrsnd@gmail.com?issuer=NOBODY&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&algorithm=SHA256&digits=8&counter=12",
                authenticator.ToString());
            Assert.NotNull(authenticator.GetCode());
            Assert.NotEmpty(authenticator.GetCode());
            Assert.NotEmpty(authenticator.GetSequence(10));
        }

        [Fact]
        public void GetCode()
        {
            var authenticator =
                Hotp.GetAuthenticator(
                    "otpauth://hotp/NOBODY:petrsnd@gmail.com?issuer=NOBODY&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA1&digits=6&counter=0");
            Assert.Equal(
                "otpauth://hotp/NOBODY:petrsnd@gmail.com?issuer=NOBODY&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA1&digits=6&counter=0",
                authenticator.ToString());
            Assert.Equal("755224", authenticator.GetCode());
        }

        [Fact]
        public void GetSequence()
        {
            var authenticator =
                Hotp.GetAuthenticator(
                    "otpauth://hotp/NOBODY:petrsnd@gmail.com?issuer=NOBODY&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA1&digits=6&counter=0");

            var sequence = authenticator.GetSequence(10);
            Assert.Equal(10, sequence.Length);
            Assert.Equal("755224", sequence[0].Code);
            Assert.Equal("287082", sequence[1].Code);
            Assert.Equal("359152", sequence[2].Code);
            Assert.Equal("969429", sequence[3].Code);
            Assert.Equal("338314", sequence[4].Code);
            Assert.Equal("254676", sequence[5].Code);
            Assert.Equal("287922", sequence[6].Code);
            Assert.Equal("162583", sequence[7].Code);
            Assert.Equal("399871", sequence[8].Code);
            Assert.Equal("520489", sequence[9].Code);
        }

        [Fact]
        public void IncrementCounter()
        {
            var authenticator =
                Hotp.GetAuthenticator(
                    "otpauth://hotp/NOBODY:petrsnd@gmail.com?issuer=NOBODY&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA1&digits=6&counter=0");

            Assert.Equal("755224", authenticator.GetCode());
            authenticator.IncrementCounter();
            Assert.Equal("287082", authenticator.GetCode());
            authenticator.IncrementCounter();
            Assert.Equal("359152", authenticator.GetCode());
            authenticator.IncrementCounter();
            Assert.Equal("969429", authenticator.GetCode());
            authenticator.IncrementCounter();
            Assert.Equal("338314", authenticator.GetCode());
            authenticator.IncrementCounter();
            Assert.Equal("254676", authenticator.GetCode());
            authenticator.IncrementCounter();
            Assert.Equal("287922", authenticator.GetCode());
            authenticator.IncrementCounter();
            Assert.Equal("162583", authenticator.GetCode());
            authenticator.IncrementCounter();
            Assert.Equal("399871", authenticator.GetCode());
            authenticator.IncrementCounter();
            Assert.Equal("520489", authenticator.GetCode());
            authenticator.IncrementCounter();

            Assert.Equal("otpauth://hotp/NOBODY:petrsnd@gmail.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=NOBODY&algorithm=SHA1&counter=10&digits=6",
                authenticator.ToString());
        }

        [Fact]
        public void SetCounter()
        {
            var authenticator =
                Hotp.GetAuthenticator(
                    "otpauth://hotp/NOBODY:petrsnd@gmail.com?issuer=NOBODY&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA1&digits=6&counter=0");

            Assert.Equal("755224", authenticator.GetCode());
            authenticator.SetCounter(9);
            Assert.Equal("520489", authenticator.GetCode());

            Assert.Equal("otpauth://hotp/NOBODY:petrsnd@gmail.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=NOBODY&algorithm=SHA1&counter=9&digits=6",
                authenticator.ToString());
        }
    }
}
