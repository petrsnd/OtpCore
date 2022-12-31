using System;
using System.Text;
using Xunit;

namespace Petrsnd.OtpCore.Test
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
            Assert.Equal(6, uri.Digits); // default should be 6 if not specified
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
            Assert.Null(uri.Counter);
            Assert.Equal(OtpHmacAlgorithm.HmacSha256, uri.Algorithm);
        }

        [Fact]
        public void ConstructorParts()
        {
            var uri = new OtpAuthUri(OtpType.Totp, Encoding.ASCII.GetBytes("12345678901234567890"), "bob@example.corp");
            Assert.Equal("otpauth://totp/bob@example.corp?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA1&period=30&digits=6",
                uri.ToString());
            Assert.Equal(6, uri.Digits); // default should be 6

            uri = new OtpAuthUri(OtpType.Hotp, Encoding.ASCII.GetBytes("12345678901234567890"), "bob@example.corp",
                "Example", 0, OtpHmacAlgorithm.HmacSha512, 8);
            Assert.Equal("otpauth://hotp/Example:bob@example.corp?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example&algorithm=SHA512&counter=0&digits=8",
                uri.ToString());

            uri = new OtpAuthUri(OtpType.Hotp, Encoding.ASCII.GetBytes("12345678901234567890"), "bob@example.corp",
                null, 5);
            Assert.Equal(
                "otpauth://hotp/bob@example.corp?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA1&counter=5&digits=6",
                uri.ToString());
        }

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
            // empty secret
            Assert.Throws<ArgumentException>(() => new OtpAuthUri("otpauth://totp/ACME%20Co:john.doe@email.com?secret="));
            Assert.Throws<ArgumentException>(() => new OtpAuthUri("otpauth://totp/ACME%20Co:john.doe@email.com?secret=&algorithm=SHA1"));

            // no account
            Assert.Throws<ArgumentException>(() =>
                new OtpAuthUri(OtpType.Hotp, Encoding.ASCII.GetBytes("12345678901234567890"), null));
            // null secret
            Assert.Throws<ArgumentException>(() => new OtpAuthUri(OtpType.Hotp, null, "bob@example.corp", "Example"));
            // empty secret
            Assert.Throws<ArgumentException>(() =>
                new OtpAuthUri(OtpType.Hotp, new byte[] { }, "bob@example.corp", "Example"));
        }

        [Fact]
        public void ToStringPreserve()
        {
            // capitalization in key names and key order and alg lowercase--should be preserved
            var uriString =
                "otpauth://totp/Example:alice@google.com?Algorithm=sha256&Secret=JBSWY3DPEHPK3PXP&Issuer=Example";
            var uri = new OtpAuthUri(uriString);
            Assert.NotNull(uri);
            Assert.Equal(OtpType.Totp, uri.Type);
            Assert.Equal("Example", uri.Issuer);
            Assert.Equal("alice@google.com", uri.Account);
            Assert.Equal("JBSWY3DPEHPK3PXP", uri.Secret);
            Assert.Equal(6, uri.Digits);
            Assert.Equal(30, uri.Period);
            Assert.Equal(OtpHmacAlgorithm.HmacSha256, uri.Algorithm);
            Assert.Equal(uriString, uri.ToString());
        }

        [Fact]
        public void GitHubIssueNo9Pt1()
        {
            // test 1 -- simple named account with ampersand and equal sign
            var uriString =
                "otpauth://totp/Example:ACME&Co=foo?Algorithm=sha256&Secret=JBSWY3DPEHPK3PXP&Issuer=Example";
            var uri = new OtpAuthUri(uriString);
            Assert.NotNull(uri);
            Assert.Equal(OtpType.Totp, uri.Type);
            Assert.Equal("Example", uri.Issuer);
            Assert.Equal("ACME&Co=foo", uri.Account);
            Assert.Equal("JBSWY3DPEHPK3PXP", uri.Secret);
            Assert.Equal(6, uri.Digits);
            Assert.Equal(30, uri.Period);
            Assert.Equal(OtpHmacAlgorithm.HmacSha256, uri.Algorithm);
            Assert.Equal(uriString, uri.ToString());
            // test 2 -- email-style named account with ampersand and equal sign
            uriString =
                "otpauth://totp/Example:ACME&Co=foo@google.com?Algorithm=sha256&Secret=JBSWY3DPEHPK3PXP&Issuer=Example";
            uri = new OtpAuthUri(uriString);
            Assert.NotNull(uri);
            Assert.Equal(OtpType.Totp, uri.Type);
            Assert.Equal("Example", uri.Issuer);
            Assert.Equal("ACME&Co=foo@google.com", uri.Account);
            Assert.Equal("JBSWY3DPEHPK3PXP", uri.Secret);
            Assert.Equal(6, uri.Digits);
            Assert.Equal(30, uri.Period);
            Assert.Equal(OtpHmacAlgorithm.HmacSha256, uri.Algorithm);
            Assert.Equal(uriString, uri.ToString());
            // test 3 -- issuer with equal sign
            uriString =
                "otpauth://totp/ACME&Co=foo:alice@google.com?Algorithm=sha256&Secret=JBSWY3DPEHPK3PXP&Issuer=ACME%26Co%3Dfoo";
            uri = new OtpAuthUri(uriString);
            Assert.NotNull(uri);
            Assert.Equal(OtpType.Totp, uri.Type);
            Assert.Equal("ACME&Co=foo", uri.Issuer);
            Assert.Equal("alice@google.com", uri.Account);
            Assert.Equal("JBSWY3DPEHPK3PXP", uri.Secret);
            Assert.Equal(6, uri.Digits);
            Assert.Equal(30, uri.Period);
            Assert.Equal(OtpHmacAlgorithm.HmacSha256, uri.Algorithm);
            Assert.Equal(uriString, uri.ToString());
            // test 4 -- should throw if issuer is not escaped in parameter portion
            Assert.Throws<ArgumentException>(() =>
                new OtpAuthUri(
                    "otpauth://totp/ACME&Co=foo:alice@google.com?Algorithm=sha256&Secret=JBSWY3DPEHPK3PXP&Issuer=ACME&Co=foo"));
        }

        [Fact]
        public void GitHubIssueNo9Pt2()
        {
            // test 1 -- must allow optional spaces between the issuer delimiter and the account name
            var uriString = "otpauth://totp/Example:    alice@google.com?Algorithm=sha256&Secret=JBSWY3DPEHPK3PXP&Issuer=Example";
            var uri = new OtpAuthUri(uriString);
            Assert.NotNull(uri);
            Assert.Equal(OtpType.Totp, uri.Type);
            Assert.Equal("Example", uri.Issuer);
            Assert.Equal("alice@google.com", uri.Account);
            Assert.Equal("JBSWY3DPEHPK3PXP", uri.Secret);
            Assert.Equal(6, uri.Digits);
            Assert.Equal(30, uri.Period);
            Assert.Equal(OtpHmacAlgorithm.HmacSha256, uri.Algorithm);
            Assert.Equal(uriString, uri.ToString());
            // test 2 -- issuer and account may not contain colons
            Assert.Throws<ArgumentException>(() =>
                new OtpAuthUri(
                    "otpauth://totp/Example:al:ice@google.com?Algorithm=sha256&Secret=JBSWY3DPEHPK3PXP&Issuer=Example"));
            Assert.Throws<ArgumentException>(() =>
                new OtpAuthUri(
                    "otpauth://totp/Ex:ample:alice@google.com?Algorithm=sha256&Secret=JBSWY3DPEHPK3PXP&Issuer=Example"));
            Assert.Throws<ArgumentException>(() =>
                new OtpAuthUri(
                    "otpauth://totp/Example::alice@google.com?Algorithm=sha256&Secret=JBSWY3DPEHPK3PXP&Issuer=Example"));
        }
    }
}
