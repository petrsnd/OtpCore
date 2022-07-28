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
            Assert.Equal(30, uri.Period);
            Assert.Equal(OtpHmacAlgorithm.HmacSha1, uri.Algorithm);


            uri = new OtpAuthUri(
                "otpauth://totp/Amazon%3Afred%40gmail.com?secret=ASDFASDFASDFASDFASDFASDFASDFASDFASDFASDFASDFASDFASDF&issuer=Amazon");
            Assert.NotNull(uri);
            Assert.Equal(OtpType.Totp, uri.Type);


            uri = new OtpAuthUri(
                "otpauth://totp/id.churchofjesuschrist.org:john?secret=ASDFASDFASDFASDF&issuer=id.churchofjesuschrist.org");
            Assert.NotNull(uri);
            Assert.Equal(OtpType.Totp, uri.Type);


            uri = new OtpAuthUri(
                "otpauth://totp/Google%3Abob%40gmail.com?secret=y67ccl5qy7c0vuzgmwa7rtmkccle5rvx&issuer=Google");
            Assert.NotNull(uri);
            Assert.Equal(OtpType.Totp, uri.Type);


            
        }

        // TODO: Constructor exceptions
    }
}
