using System;
using OtpCore;
using Xunit;

namespace TestOtpCore
{
    public class OtpAuthUriTest
    {
        [Fact]
        public void ConstructorString()
        {
            var uri = new OtpAuthUri("otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example");
            Assert.NotNull(uri);
            Assert.Equal(OtpType.Totp, uri.Type);
            Assert.Equal("Example", uri.Issuer);
            Assert.Equal("alice@google.com", uri.Account);
            Assert.Equal("JBSWY3DPEHPK3PXP", uri.Secret);
            Assert.Equal(6, uri.Digits);
            Assert.Equal(30, uri.Period);
            Assert.Equal(OtpHmacAlgorithm.HmacSha1, uri.Algorithm);

            uri = new OtpAuthUri(
                "otpauth://totp/Amazon%3Afred%40gmail.com?secret=ASDFASDFASDFASDFASDFASDFASDFASDFASDFASDFASDFASDFASDF&issuer=Amazon");
            Assert.NotNull(uri);
            Assert.Equal(OtpType.Totp, uri.Type);
            Assert.Equal("Amazon", uri.Issuer);
            Assert.Equal("fred@gmail.com", uri.Account);
            Assert.Equal("ASDFASDFASDFASDFASDFASDFASDFASDFASDFASDFASDFASDFASDF", uri.Secret);
            Assert.Equal(6, uri.Digits);
            Assert.Equal(30, uri.Period);
            Assert.Equal(OtpHmacAlgorithm.HmacSha1, uri.Algorithm);

            uri = new OtpAuthUri(
                "otpauth://totp/id.churchofjesuschrist.org:john?secret=ASDFASDFASDFASDF&issuer=id.churchofjesuschrist.org");
            Assert.NotNull(uri);
            Assert.Equal(OtpType.Totp, uri.Type);
            Assert.Equal("id.churchofjesuschrist.org", uri.Issuer);
            Assert.Equal("john", uri.Account);
            Assert.Equal("ASDFASDFASDFASDF", uri.Secret);
            Assert.Equal(6, uri.Digits);
            Assert.Equal(30, uri.Period);
            Assert.Equal(OtpHmacAlgorithm.HmacSha1, uri.Algorithm);

            uri = new OtpAuthUri(
                "otpauth://totp/Google%3Abob%40gmail.com?secret=y67ccl5qy7cvuzgmwa7rtmkccle5rvx&issuer=Google");
            Assert.NotNull(uri);
            Assert.Equal(OtpType.Totp, uri.Type);
            Assert.Equal("Google", uri.Issuer);
            Assert.Equal("bob@gmail.com", uri.Account);
            Assert.Equal("y67ccl5qy7cvuzgmwa7rtmkccle5rvx", uri.Secret);
            Assert.Equal(6, uri.Digits);
            Assert.Equal(30, uri.Period);
            Assert.Equal(OtpHmacAlgorithm.HmacSha1, uri.Algorithm);

            uri = new OtpAuthUri(
                "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=20");
            Assert.NotNull(uri);
            Assert.Equal(OtpType.Totp, uri.Type);
            Assert.Equal("ACME Co", uri.Issuer);
            Assert.Equal("john.doe@email.com", uri.Account);
            Assert.Equal("HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ", uri.Secret);
            Assert.Equal(8, uri.Digits);
            Assert.Equal(20, uri.Period);
            Assert.Equal(OtpHmacAlgorithm.HmacSha256, uri.Algorithm);

            // no issuer
            uri = new OtpAuthUri(
                "otpauth://totp/john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&algorithm=SHA256&digits=8&period=20");
            Assert.NotNull(uri);
            Assert.Equal(OtpType.Totp, uri.Type);
            Assert.Null(uri.Issuer);
            Assert.Equal("john.doe@email.com", uri.Label);
            Assert.Equal("john.doe@email.com", uri.Account);
            Assert.Equal("HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ", uri.Secret);
            Assert.Equal(8, uri.Digits);
            Assert.Equal(20, uri.Period);
            Assert.Equal(OtpHmacAlgorithm.HmacSha256, uri.Algorithm);
        }

        // TODO: Constructor exceptions
        [Fact]
        public void ConstructorExceptions()
        {
            Assert.Throws<UriFormatException>(() => new OtpAuthUri(""));
            Assert.Throws<UriFormatException>(() => new OtpAuthUri("otpauth/label:account?stuff=a"));

            // wrong scheme
            Assert.Throws<ArgumentException>(() => new OtpAuthUri("https://github.com/google/google-authenticator/wiki/Key-Uri-Format"));
            // invalid type
            Assert.Throws<ArgumentException>(() => new OtpAuthUri("otpauth://otp/ACME%20Co:john.doe@email.com"));
            // no secret
            Assert.Throws<ArgumentException>(() => new OtpAuthUri("otpauth://totp/ACME%20Co:john.doe@email.com"));
            
        }
    }
}
