using System.Text;
using Xunit;

namespace Petrsnd.OtpCore.Test
{
    public class UtilitiesTest
    {
        [Fact]
        public void CounterToBuffer()
        {
            Assert.Equal(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, Utilities.CounterToBuffer(0));
            Assert.Equal(new byte[] { 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, Utilities.CounterToBuffer(long.MaxValue));
            // Test values from RFC 6238 Appendix B
            Assert.Equal(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }, Utilities.CounterToBuffer(1));
            Assert.Equal(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x02, 0x35, 0x23, 0xEC }, Utilities.CounterToBuffer(37037036));
            Assert.Equal(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x02, 0x35, 0x23, 0xED }, Utilities.CounterToBuffer(37037037));
            Assert.Equal(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x02, 0x73, 0xEF, 0x07 }, Utilities.CounterToBuffer(41152263));
            Assert.Equal(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x03, 0xF9, 0x40, 0xAA }, Utilities.CounterToBuffer(66666666));
            Assert.Equal(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x27, 0xBC, 0x86, 0xAA }, Utilities.CounterToBuffer(666666666));
            Assert.Equal(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x27, 0xBC, 0x86, 0xAA }, Utilities.CounterToBuffer(666666666));
            // Additional value larger than 32-bits
            Assert.Equal(new byte[] { 0x00, 0x00, 0x00, 0x05, 0x2D, 0xC7, 0x47, 0xB1 }, Utilities.CounterToBuffer(22242871217));
        }

        [Fact]
        public void CalculateHmac()
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
            Assert.Equal(
                new byte[]
                {
                    0xcc, 0x93, 0xcf, 0x18, 0x50, 0x8d, 0x94, 0x93, 0x4c, 0x64, 0xb6, 0x5d, 0x8b, 0xa7, 0x66, 0x7f,
                    0xb7, 0xcd, 0xe4, 0xb0
                }, Utilities.CalculateHmac(OtpHmacAlgorithm.HmacSha1, secret, Utilities.CounterToBuffer(0)));
            Assert.Equal(
                new byte[]
                {
                    0x75, 0xa4, 0x8a, 0x19, 0xd4, 0xcb, 0xe1, 0x00, 0x64, 0x4e, 0x8a, 0xc1, 0x39, 0x7e, 0xea, 0x74,
                    0x7a, 0x2d, 0x33, 0xab
                }, Utilities.CalculateHmac(OtpHmacAlgorithm.HmacSha1, secret, Utilities.CounterToBuffer(1)));
            Assert.Equal(
                new byte[]
                {
                    0x0b, 0xac, 0xb7, 0xfa, 0x08, 0x2f, 0xef, 0x30, 0x78, 0x22, 0x11, 0x93, 0x8b, 0xc1, 0xc5, 0xe7,
                    0x04, 0x16, 0xff, 0x44
                }, Utilities.CalculateHmac(OtpHmacAlgorithm.HmacSha1, secret, Utilities.CounterToBuffer(2)));
            Assert.Equal(
                new byte[]
                {
                    0x66, 0xc2, 0x82, 0x27, 0xd0, 0x3a, 0x2d, 0x55, 0x29, 0x26, 0x2f, 0xf0, 0x16, 0xa1, 0xe6, 0xef,
                    0x76, 0x55, 0x7e, 0xce
                }, Utilities.CalculateHmac(OtpHmacAlgorithm.HmacSha1, secret, Utilities.CounterToBuffer(3)));
            Assert.Equal(
                new byte[]
                {
                    0xa9, 0x04, 0xc9, 0x00, 0xa6, 0x4b, 0x35, 0x90, 0x98, 0x74, 0xb3, 0x3e, 0x61, 0xc5, 0x93, 0x8a,
                    0x8e, 0x15, 0xed, 0x1c
                }, Utilities.CalculateHmac(OtpHmacAlgorithm.HmacSha1, secret, Utilities.CounterToBuffer(4)));
            Assert.Equal(
                new byte[]
                {
                    0xa3, 0x7e, 0x78, 0x3d, 0x7b, 0x72, 0x33, 0xc0, 0x83, 0xd4, 0xf6, 0x29, 0x26, 0xc7, 0xa2, 0x5f,
                    0x23, 0x8d, 0x03, 0x16
                }, Utilities.CalculateHmac(OtpHmacAlgorithm.HmacSha1, secret, Utilities.CounterToBuffer(5)));
            Assert.Equal(
                new byte[]
                {
                    0xbc, 0x9c, 0xd2, 0x85, 0x61, 0x04, 0x2c, 0x83, 0xf2, 0x19, 0x32, 0x4d, 0x3c, 0x60, 0x72, 0x56,
                    0xc0, 0x32, 0x72, 0xae
                }, Utilities.CalculateHmac(OtpHmacAlgorithm.HmacSha1, secret, Utilities.CounterToBuffer(6)));
            Assert.Equal(
                new byte[]
                {
                    0xa4, 0xfb, 0x96, 0x0c, 0x0b, 0xc0, 0x6e, 0x1e, 0xab, 0xb8, 0x04, 0xe5, 0xb3, 0x97, 0xcd, 0xc4,
                    0xb4, 0x55, 0x96, 0xfa
                }, Utilities.CalculateHmac(OtpHmacAlgorithm.HmacSha1, secret, Utilities.CounterToBuffer(7)));
            Assert.Equal(
                new byte[]
                {
                    0x1b, 0x3c, 0x89, 0xf6, 0x5e, 0x6c, 0x9e, 0x88, 0x30, 0x12, 0x05, 0x28, 0x23, 0x44, 0x3f, 0x04,
                    0x8b, 0x43, 0x32, 0xdb
                }, Utilities.CalculateHmac(OtpHmacAlgorithm.HmacSha1, secret, Utilities.CounterToBuffer(8)));
            Assert.Equal(
                new byte[]
                {
                    0x16, 0x37, 0x40, 0x98, 0x09, 0xa6, 0x79, 0xdc, 0x69, 0x82, 0x07, 0x31, 0x0c, 0x8c, 0x7f, 0xc0,
                    0x72, 0x90, 0xd9, 0xe5
                }, Utilities.CalculateHmac(OtpHmacAlgorithm.HmacSha1, secret, Utilities.CounterToBuffer(9)));
        }

        [Fact]
        public void GetTruncatedDigits()
        {
            // Test values from RFC 4226 Appendix D
            // counter values 0 through 9
            Assert.Equal("755224", Utilities.GetTruncatedDigits(
                new byte[]
                {
                    0xcc, 0x93, 0xcf, 0x18, 0x50, 0x8d, 0x94, 0x93, 0x4c, 0x64, 0xb6, 0x5d, 0x8b, 0xa7, 0x66, 0x7f,
                    0xb7, 0xcd, 0xe4, 0xb0
                }, 6));
            Assert.Equal("287082", Utilities.GetTruncatedDigits(
                new byte[]
                {
                    0x75, 0xa4, 0x8a, 0x19, 0xd4, 0xcb, 0xe1, 0x00, 0x64, 0x4e, 0x8a, 0xc1, 0x39, 0x7e, 0xea, 0x74,
                    0x7a, 0x2d, 0x33, 0xab
                }, 6));
            Assert.Equal("359152", Utilities.GetTruncatedDigits(
                new byte[]
                {
                    0x0b, 0xac, 0xb7, 0xfa, 0x08, 0x2f, 0xef, 0x30, 0x78, 0x22, 0x11, 0x93, 0x8b, 0xc1, 0xc5, 0xe7,
                    0x04, 0x16, 0xff, 0x44
                }, 6));
            Assert.Equal("969429", Utilities.GetTruncatedDigits(
                new byte[]
                {
                    0x66, 0xc2, 0x82, 0x27, 0xd0, 0x3a, 0x2d, 0x55, 0x29, 0x26, 0x2f, 0xf0, 0x16, 0xa1, 0xe6, 0xef,
                    0x76, 0x55, 0x7e, 0xce
                }, 6));
            Assert.Equal("338314", Utilities.GetTruncatedDigits(
                new byte[]
                {
                    0xa9, 0x04, 0xc9, 0x00, 0xa6, 0x4b, 0x35, 0x90, 0x98, 0x74, 0xb3, 0x3e, 0x61, 0xc5, 0x93, 0x8a,
                    0x8e, 0x15, 0xed, 0x1c
                }, 6));
            Assert.Equal("254676", Utilities.GetTruncatedDigits(
                new byte[]
                {
                    0xa3, 0x7e, 0x78, 0x3d, 0x7b, 0x72, 0x33, 0xc0, 0x83, 0xd4, 0xf6, 0x29, 0x26, 0xc7, 0xa2, 0x5f,
                    0x23, 0x8d, 0x03, 0x16
                }, 6));
            Assert.Equal("287922", Utilities.GetTruncatedDigits(
                new byte[]
                {
                    0xbc, 0x9c, 0xd2, 0x85, 0x61, 0x04, 0x2c, 0x83, 0xf2, 0x19, 0x32, 0x4d, 0x3c, 0x60, 0x72, 0x56,
                    0xc0, 0x32, 0x72, 0xae
                }, 6));
            Assert.Equal("162583", Utilities.GetTruncatedDigits(
                new byte[]
                {
                    0xa4, 0xfb, 0x96, 0x0c, 0x0b, 0xc0, 0x6e, 0x1e, 0xab, 0xb8, 0x04, 0xe5, 0xb3, 0x97, 0xcd, 0xc4,
                    0xb4, 0x55, 0x96, 0xfa
                }, 6));
            Assert.Equal("399871", Utilities.GetTruncatedDigits(
                new byte[]
                {
                    0x1b, 0x3c, 0x89, 0xf6, 0x5e, 0x6c, 0x9e, 0x88, 0x30, 0x12, 0x05, 0x28, 0x23, 0x44, 0x3f, 0x04,
                    0x8b, 0x43, 0x32, 0xdb
                }, 6));
            Assert.Equal("520489", Utilities.GetTruncatedDigits(
                new byte[]
                {
                    0x16, 0x37, 0x40, 0x98, 0x09, 0xa6, 0x79, 0xdc, 0x69, 0x82, 0x07, 0x31, 0x0c, 0x8c, 0x7f, 0xc0,
                    0x72, 0x90, 0xd9, 0xe5
                }, 6));
        }

        [Fact]
        public void Base32Encode()
        {
            // Test vectors from RFC 4648
            Assert.Equal("", Utilities.Base32Encode(Encoding.ASCII.GetBytes("")));
            Assert.Equal("MY======", Utilities.Base32Encode(Encoding.ASCII.GetBytes("f"), true));
            Assert.Equal("MZXQ====", Utilities.Base32Encode(Encoding.ASCII.GetBytes("fo"), true));
            Assert.Equal("MZXW6===", Utilities.Base32Encode(Encoding.ASCII.GetBytes("foo"), true));
            Assert.Equal("MZXW6YQ=", Utilities.Base32Encode(Encoding.ASCII.GetBytes("foob"), true));
            Assert.Equal("MZXW6YTB", Utilities.Base32Encode(Encoding.ASCII.GetBytes("fooba"), true));
            Assert.Equal("MZXW6YTBOI======", Utilities.Base32Encode(Encoding.ASCII.GetBytes("foobar"), true));

            // Test vectors from RFC 4648 w/o padding
            Assert.Equal("", Utilities.Base32Encode(Encoding.ASCII.GetBytes("")));
            Assert.Equal("MY", Utilities.Base32Encode(Encoding.ASCII.GetBytes("f")));
            Assert.Equal("MZXQ", Utilities.Base32Encode(Encoding.ASCII.GetBytes("fo")));
            Assert.Equal("MZXW6", Utilities.Base32Encode(Encoding.ASCII.GetBytes("foo")));
            Assert.Equal("MZXW6YQ", Utilities.Base32Encode(Encoding.ASCII.GetBytes("foob")));
            Assert.Equal("MZXW6YTB", Utilities.Base32Encode(Encoding.ASCII.GetBytes("fooba")));
            Assert.Equal("MZXW6YTBOI", Utilities.Base32Encode(Encoding.ASCII.GetBytes("foobar")));

            // Online test implementations
            Assert.Equal("KRUGS4ZANFZSAYJAOJSWC3DMPEQGY33OM4QHIZLTOQ======",
                Utilities.Base32Encode(Encoding.ASCII.GetBytes("This is a really long test"), true));
        }

        [Fact]
        public void Base32Decode()
        {
            // Test vectors from RFC 4648
            Assert.Equal(Encoding.ASCII.GetBytes(""), Utilities.Base32Decode(""));
            Assert.Equal(Encoding.ASCII.GetBytes("f"), Utilities.Base32Decode("MY======"));
            Assert.Equal(Encoding.ASCII.GetBytes("fo"), Utilities.Base32Decode("MZXQ===="));
            Assert.Equal(Encoding.ASCII.GetBytes("foo"), Utilities.Base32Decode("MZXW6==="));
            Assert.Equal(Encoding.ASCII.GetBytes("foob"), Utilities.Base32Decode("MZXW6YQ="));
            Assert.Equal(Encoding.ASCII.GetBytes("fooba"), Utilities.Base32Decode("MZXW6YTB"));
            Assert.Equal(Encoding.ASCII.GetBytes("foobar"), Utilities.Base32Decode("MZXW6YTBOI======"));

            // Test vectors from RFC 4648 w/o padding
            Assert.Equal(Encoding.ASCII.GetBytes(""), Utilities.Base32Decode(""));
            Assert.Equal(Encoding.ASCII.GetBytes("f"), Utilities.Base32Decode("MY"));
            Assert.Equal(Encoding.ASCII.GetBytes("fo"), Utilities.Base32Decode("MZXQ"));
            Assert.Equal(Encoding.ASCII.GetBytes("foo"), Utilities.Base32Decode("MZXW6"));
            Assert.Equal(Encoding.ASCII.GetBytes("foob"), Utilities.Base32Decode("MZXW6YQ"));
            Assert.Equal(Encoding.ASCII.GetBytes("fooba"), Utilities.Base32Decode("MZXW6YTB"));
            Assert.Equal(Encoding.ASCII.GetBytes("foobar"), Utilities.Base32Decode("MZXW6YTBOI"));

            // Online test implementations
            Assert.Equal(Encoding.ASCII.GetBytes("This is a really long test"),
                Utilities.Base32Decode("KRUGS4ZANFZSAYJAOJSWC3DMPEQGY33OM4QHIZLTOQ======"));
            Assert.Equal(Encoding.ASCII.GetBytes("This is a really long test"),
                Utilities.Base32Decode("KRUGS4ZANFZSAYJAOJSWC3DMPEQGY33OM4QHIZLTOQ"));
        }
    }
}
