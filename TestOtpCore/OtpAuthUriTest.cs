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
            Assert.True(UriComparer.AreEqual(uri.ToString(),
                "otpauth://totp/bob@example.corp?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA1&period=30&digits=6"));
            Assert.Equal(6, uri.Digits); // default should be 6

            uri = new OtpAuthUri(OtpType.Hotp, Encoding.ASCII.GetBytes("12345678901234567890"), "bob@example.corp",
                "Example", 0, OtpHmacAlgorithm.HmacSha512, 8);
            Assert.True(UriComparer.AreEqual(uri.ToString(),
                "otpauth://hotp/Example:bob@example.corp?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example&algorithm=SHA512&counter=0&digits=8"));

            uri = new OtpAuthUri(OtpType.Hotp, Encoding.ASCII.GetBytes("12345678901234567890"), "bob@example.corp",
                null, 5);
            Assert.True(UriComparer.AreEqual(uri.ToString(),
                "otpauth://hotp/bob@example.corp?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA1&counter=5&digits=6"));
        }

        [Fact]
        public void ConstructorExceptions()
        {
            Assert.Throws<UriFormatException>(() => new OtpAuthUri(""));
            Assert.Throws<UriFormatException>(() => new OtpAuthUri("otpauth/label:account?stuff=a"));

            // wrong scheme
            Assert.Throws<ArgumentException>(() =>
                new OtpAuthUri("https://github.com/google/google-authenticator/wiki/Key-Uri-Format"));
            // invalid type
            Assert.Throws<ArgumentException>(() => new OtpAuthUri("otpauth://otp/ACME%20Co:john.doe@email.com"));
            // no secret
            Assert.Throws<ArgumentException>(() => new OtpAuthUri("otpauth://totp/ACME%20Co:john.doe@email.com"));
            // empty secret
            Assert.Throws<ArgumentException>(
                () => new OtpAuthUri("otpauth://totp/ACME%20Co:john.doe@email.com?secret="));
            Assert.Throws<ArgumentException>(() =>
                new OtpAuthUri("otpauth://totp/ACME%20Co:john.doe@email.com?secret=&algorithm=SHA1"));

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
            Assert.True(UriComparer.AreEqual(uri.ToString(), uriString));
        }

        [Fact]
        public void GitHubIssueNo9Pt1()
        {
            // test 1 -- simple named account with ampersand and equal sign
            var uriString =
                "otpauth://totp/Example:ACME%26Co=foo?Algorithm=sha256&Secret=JBSWY3DPEHPK3PXP&Issuer=Example";
            var uri = new OtpAuthUri(uriString);
            Assert.NotNull(uri);
            Assert.Equal(OtpType.Totp, uri.Type);
            Assert.Equal("Example", uri.Issuer);
            Assert.Equal("ACME&Co=foo", uri.Account);
            Assert.Equal("JBSWY3DPEHPK3PXP", uri.Secret);
            Assert.Equal(6, uri.Digits);
            Assert.Equal(30, uri.Period);
            Assert.Equal(OtpHmacAlgorithm.HmacSha256, uri.Algorithm);
            Assert.True(UriComparer.AreEqual(uri.ToString(), uriString));
            // test 2 -- email-style named account with ampersand and equal sign
            uriString =
                "otpauth://totp/Example:ACME&Co%3dfoo@google.com?Algorithm=sha256&Secret=JBSWY3DPEHPK3PXP&Issuer=Example";
            uri = new OtpAuthUri(uriString);
            Assert.NotNull(uri);
            Assert.Equal(OtpType.Totp, uri.Type);
            Assert.Equal("Example", uri.Issuer);
            Assert.Equal("ACME&Co=foo@google.com", uri.Account);
            Assert.Equal("JBSWY3DPEHPK3PXP", uri.Secret);
            Assert.Equal(6, uri.Digits);
            Assert.Equal(30, uri.Period);
            Assert.Equal(OtpHmacAlgorithm.HmacSha256, uri.Algorithm);
            Assert.True(UriComparer.AreEqual(uri.ToString(), uriString));
            // test 3 -- issuer with equal sign
            uriString =
                "otpauth://totp/ACME%26Co%3dfoo:alice@google.com?Algorithm=sha256&Secret=JBSWY3DPEHPK3PXP&Issuer=ACME%26Co%3Dfoo";
            uri = new OtpAuthUri(uriString);
            Assert.NotNull(uri);
            Assert.Equal(OtpType.Totp, uri.Type);
            Assert.Equal("ACME&Co=foo", uri.Issuer);
            Assert.Equal("alice@google.com", uri.Account);
            Assert.Equal("JBSWY3DPEHPK3PXP", uri.Secret);
            Assert.Equal(6, uri.Digits);
            Assert.Equal(30, uri.Period);
            Assert.Equal(OtpHmacAlgorithm.HmacSha256, uri.Algorithm);
            // test 3a -- issuer example from URI spec 'Big Corporation'
            uriString =
                "otpauth://totp/Big%20Corporation:alice@google.com?Algorithm=sha256&Secret=JBSWY3DPEHPK3PXP&Issuer=Big%20Corporation";
            uri = new OtpAuthUri(uriString);
            Assert.NotNull(uri);
            Assert.Equal(OtpType.Totp, uri.Type);
            Assert.Equal("Big Corporation", uri.Issuer);
            Assert.Equal("alice@google.com", uri.Account);
            Assert.Equal("JBSWY3DPEHPK3PXP", uri.Secret);
            Assert.Equal(6, uri.Digits);
            Assert.Equal(30, uri.Period);
            Assert.Equal(OtpHmacAlgorithm.HmacSha256, uri.Algorithm);
            Assert.True(UriComparer.AreEqual(uri.ToString(), uriString));
        }

        [Fact]
        public void GitHubIssueNo9Pt2()
        {
            // test 1 -- must allow optional spaces between the issuer delimiter and the account name
            var uriString =
                "otpauth://totp/Example:%20%20%20alice@google.com?Algorithm=sha256&Secret=JBSWY3DPEHPK3PXP&Issuer=Example";
            var uri = new OtpAuthUri(uriString);
            Assert.NotNull(uri);
            Assert.Equal(OtpType.Totp, uri.Type);
            Assert.Equal("Example", uri.Issuer);
            Assert.Equal("alice@google.com", uri.Account);
            Assert.Equal("JBSWY3DPEHPK3PXP", uri.Secret);
            Assert.Equal(6, uri.Digits);
            Assert.Equal(30, uri.Period);
            Assert.Equal(OtpHmacAlgorithm.HmacSha256, uri.Algorithm);
            Assert.True(UriComparer.AreEqual(uri.ToString(), uriString));
            // test 2 -- issuer and account may not contain colons
            Assert.Throws<ArgumentException>(() =>
                new OtpAuthUri(
                    "otpauth://totp/Example:al:ice@google.com?Algorithm=sha256&Secret=JBSWY3DPEHPK3PXP"));
            Assert.Throws<ArgumentException>(() =>
                new OtpAuthUri(
                    "otpauth://totp/Ex:ample%3Aalice@google.com?Algorithm=sha256&Secret=JBSWY3DPEHPK3PXP"));
            Assert.Throws<ArgumentException>(() =>
                new OtpAuthUri(
                    "otpauth://totp/Example::alice@google.com?Algorithm=sha256&Secret=JBSWY3DPEHPK3PXP"));
            // test 3 -- unless the issuer parameter also contains matching colons to remove ambiguity
            uriString =
                "otpauth://totp/ACME%3FCo%3D192.168.1.1%3A8080:%CE%B1ccount?secret=AE&issuer=ACME%3fCo%3d192.168.1.1%3a8080&algorithm=SHA1&period=30&digits=6";
            uri = new OtpAuthUri(uriString);
            Assert.NotNull(uri);
            Assert.Equal(OtpType.Totp, uri.Type);
            Assert.Equal("ACME?Co=192.168.1.1:8080", uri.Issuer);
            Assert.Equal("αccount", uri.Account);
            Assert.Equal("AE", uri.Secret);
            Assert.Equal(6, uri.Digits);
            Assert.Equal(30, uri.Period);
            Assert.Equal(OtpHmacAlgorithm.HmacSha1, uri.Algorithm);
            Assert.True(UriComparer.AreEqual(uri.ToString(), uriString));
        }

        [Fact]
        public void GitHubIssueNo9Pt3()
        {
            Assert.Throws<ArgumentException>(() =>
                new OtpAuthUri((OtpType)42, Encoding.ASCII.GetBytes("12345678901234567890"), "bob@example.corp"));
        }

        [Fact]
        public void GitHubIssueNo9Pt4()
        {
            var account = "αccount";
            var issuer = "ACME?Co=192.168.1.1:8080";
            var uri = new OtpAuthUri(OtpType.Totp, new byte[] { 0x01 }, account, issuer);

            var uriString =
                "otpauth://totp/ACME%3FCo%3D192.168.1.1%3A8080:%CE%B1ccount?secret=AE&issuer=ACME%3fCo%3d192.168.1.1%3a8080&algorithm=SHA1&period=30&digits=6";
            Assert.True(UriComparer.AreEqual(uri.ToString(), uriString));
        }

        [Fact]
        public void CommonAuthenticatorsGoogle()
        {
            // Google Authenticator Sample
            var uriString = "otpauth://totp/Google%3Apetrsnd%40gmail.com?secret=falgckrtx5fdbkwqukum666jo2mxpziy&issuer=Google";
            var uri = new OtpAuthUri(uriString);
            Assert.NotNull(uri);
            Assert.Equal(OtpType.Totp, uri.Type);
            Assert.Equal("Google", uri.Issuer);
            Assert.Equal("petrsnd@gmail.com", uri.Account);
            Assert.Equal("falgckrtx5fdbkwqukum666jo2mxpziy", uri.Secret);
            Assert.Equal(6, uri.Digits);
            Assert.Equal(30, uri.Period);
            Assert.Equal(OtpHmacAlgorithm.HmacSha1, uri.Algorithm);
            Assert.True(UriComparer.AreEqual(uri.ToString(), uriString));
        }

        [Fact]
        public void CommonAuthenticatorsMicrosoft()
        {
            // Microsoft Authenticator Sample
            var uriString = "otpauth://totp/Petrsnd.Org%3Atest2fa%40petrsnd.org?secret=cskm2nmg5cvbcjzx&issuer=Microsoft";
            var uri = new OtpAuthUri(uriString);
            Assert.NotNull(uri);
            Assert.Equal(OtpType.Totp, uri.Type);
            Assert.Equal("Microsoft", uri.Issuer);
            Assert.Equal("Microsoft", uri.IssuerParameter);
            Assert.Equal("Petrsnd.Org", uri.IssuerLabel);
            Assert.Equal("test2fa@petrsnd.org", uri.Account);
            Assert.Equal("cskm2nmg5cvbcjzx", uri.Secret);
            Assert.Equal(6, uri.Digits);
            Assert.Equal(30, uri.Period);
            Assert.Equal(OtpHmacAlgorithm.HmacSha1, uri.Algorithm);
            Assert.True(UriComparer.AreEqual(uri.ToString(), uriString));
        }

        [Fact]
        public void CommonAuthenticatorsTwilioAuthy()
        {
            // Twilio / Authy Authenticator
            var uriString = "";
            // var uri = new OtpAuthUri(uriString);
            // Assert.NotNull(uri);
            // Assert.Equal(OtpType.Totp, uri.Type);
            // Assert.Equal("ACME?Co=192.168.1.1:8080", uri.Issuer);
            // Assert.Equal("αccount", uri.Account);
            // Assert.Equal("AE", uri.Secret);
            // Assert.Equal(6, uri.Digits);
            // Assert.Equal(30, uri.Period);
            // Assert.Equal(OtpHmacAlgorithm.HmacSha1, uri.Algorithm);
            // Assert.True(UriComparer.AreEqual(uri.ToString(), uriString));
        }


        [Fact]
        public void CommonAuthenticatorsOktaGoogleAuthenticator()
        {
            // Okta Verify Authenticator uses the oktaverify:// uri scheme
            // Okta Google Authenticator uses the otpauth:// uri scheme
            var uriString = "otpauth://totp/dev-46457303.okta.com:dan.peterson%40oneidentity.com?secret=453T5PHSNTYJ4YEK&issuer=dev-46457303.okta.com";
            var uri = new OtpAuthUri(uriString);
            Assert.NotNull(uri);
            Assert.Equal(OtpType.Totp, uri.Type);
            Assert.Equal("dev-46457303.okta.com", uri.Issuer);
            Assert.Equal("dan.peterson@oneidentity.com", uri.Account);
            Assert.Equal("453T5PHSNTYJ4YEK", uri.Secret);
            Assert.Equal(6, uri.Digits);
            Assert.Equal(30, uri.Period);
            Assert.Equal(OtpHmacAlgorithm.HmacSha1, uri.Algorithm);
            Assert.True(UriComparer.AreEqual(uri.ToString(), uriString));
        }

        [Fact]
        public void CommonAuthenticatorsFreeOtp()
        {
            // FreeOtp Authenticator by default recommends FreeIPA
            // FreeIPA OTP Authenticator
            var uriString = "otpauth://totp/employee@DEMO1.FREEIPA.ORG:Phone%20Authenticator?issuer=employee%40DEMO1.FREEIPA.ORG&secret=ASDFASDFASDFASDF&digits=6&algorithm=SHA1&period=30";
            var uri = new OtpAuthUri(uriString);
            Assert.NotNull(uri);
            Assert.Equal(OtpType.Totp, uri.Type);
            Assert.Equal("employee@DEMO1.FREEIPA.ORG", uri.Issuer);
            Assert.Equal("Phone Authenticator", uri.Account);
            Assert.Equal("ASDFASDFASDFASDF", uri.Secret);
            Assert.Equal(6, uri.Digits);
            Assert.Equal(30, uri.Period);
            Assert.Equal(OtpHmacAlgorithm.HmacSha1, uri.Algorithm);
            Assert.True(UriComparer.AreEqual(uri.ToString(), uriString));
        }

        [Fact]
        public void CommonAuthenticatorsOneLoginAuthenticator()
        {
            // OneLogin Protect uses onelogin-otpauth uri scheme
            // OneLogin Authenticator uses otpauth:// uri scheme
            var uriString = "otpauth://totp/dan.peterson@oneidentity.com?secret=Z7CYH2IRBE7P73A2J7FFS7VHZHNCEPQL&issuer=OneLogin";
            var uri = new OtpAuthUri(uriString);
            Assert.NotNull(uri);
            Assert.Equal(OtpType.Totp, uri.Type);
            Assert.Equal("OneLogin", uri.Issuer);
            Assert.Equal("dan.peterson@oneidentity.com", uri.Account);
            Assert.Equal("Z7CYH2IRBE7P73A2J7FFS7VHZHNCEPQL", uri.Secret);
            Assert.Equal(6, uri.Digits);
            Assert.Equal(30, uri.Period);
            Assert.Equal(OtpHmacAlgorithm.HmacSha1, uri.Algorithm);
            Assert.True(UriComparer.AreEqual(uri.ToString(), uriString));
        }
    }
}
