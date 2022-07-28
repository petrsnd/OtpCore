using System;
using System.Collections.Generic;
using System.Web;

namespace OtpCore
{
    public class OtpAuthUri
    {
        private readonly Uri _uri;

        public OtpAuthUri(string issuer, string account, OtpType type, byte[] secret, long counterOrPeriod,
            OtpHmacAlgorithm algorithm = OtpHmacAlgorithm.HmacSha1, int digits = 6)
        {
            Issuer = issuer;
            if (string.IsNullOrEmpty(account))
                throw new ArgumentException("Account must be specified", nameof(account));
            Account = account;
            Type = type;
            Secret = ""; // TODO: Base32 encode
            if (Type == OtpType.Hotp)
                Counter = counterOrPeriod;
            else if (Type == OtpType.Totp)
                Period = (int)counterOrPeriod;
            Algorithm = algorithm;
            Digits = digits;
        }

        public OtpAuthUri(string uriString) : this(new Uri(uriString))
        {
        }

        public OtpAuthUri(Uri uri)
        {
            // defaults
            Parameters = new Dictionary<string, string>();
            Algorithm = OtpHmacAlgorithm.HmacSha1;
            Digits = 6;

            // parsing
            _uri = uri;
            if (_uri.Scheme != "otpauth")
                throw new ArgumentException("URI scheme must be 'otpauth'", nameof(uri));
            if (_uri.Authority != "hotp" && _uri.Authority != "totp")
                throw new ArgumentException("URI authority must be one of 'hotp' or totp'", nameof(uri));
            if (_uri.Authority == "hotp")
                Type = OtpType.Hotp;
            else if (_uri.Authority == "totp")
                Type = OtpType.Totp;

            if (_uri.Segments.Length != 2)
                throw new ArgumentException("URI must contain a label after the authority", nameof(uri));
            if (_uri.Segments[0] != "/")
                throw new ArgumentException("URI is missing separator between authority and label", nameof(uri));
            Label = HttpUtility.UrlDecode(_uri.Segments[1]);
            if (Label.Contains(":"))
            {
                var split = Label.Split(new char[] { ':' }, 2, StringSplitOptions.RemoveEmptyEntries);
                Issuer = split[0];
                Account = split[1];
            }
            else
            {
                Account = Label;
            }

            if (string.IsNullOrEmpty(_uri.Query))
                throw new ArgumentException("URI must contain a query string", nameof(uri));
            var nameValues = HttpUtility.ParseQueryString(_uri.Query);
            foreach (var key in nameValues.Keys)
            {
                Parameters[key.ToString().ToLower()] = nameValues[key.ToString()];
            }

            if (!Parameters.ContainsKey("secret"))
                throw new ArgumentException("URI must contain a parameter called 'secret'", nameof(uri));
            Secret = Parameters["secret"];
            Utilities.Base32Decode(Secret); // Test decoding

            if (Parameters.ContainsKey("issuer"))
            {
                if (string.IsNullOrEmpty(Issuer))
                    Issuer = Parameters["issuer"];
                else
                {
                    if (string.Compare(Issuer, Parameters["issuer"], StringComparison.Ordinal) != 0)
                        throw new ArgumentException("URI issuer from label must match issuer from query string",
                            nameof(uri));
                }
            }

            if (Parameters.ContainsKey("algorithm"))
            {
                if (string.Compare(Parameters["algorithm"], "SHA1", StringComparison.OrdinalIgnoreCase) == 0)
                    Algorithm = OtpHmacAlgorithm.HmacSha1;
                else if (string.Compare(Parameters["algorithm"], "SHA256", StringComparison.OrdinalIgnoreCase) == 0)
                    Algorithm = OtpHmacAlgorithm.HmacSha256;
                else if (string.Compare(Parameters["algorithm"], "SHA384", StringComparison.OrdinalIgnoreCase) == 0)
                    Algorithm = OtpHmacAlgorithm.HmacSha384;
                else if (string.Compare(Parameters["algorithm"], "SHA512", StringComparison.OrdinalIgnoreCase) == 0)
                    Algorithm = OtpHmacAlgorithm.HmacSha512;
                else
                    throw new ArgumentException(
                        "URI algorithm query parameter must be one of 'SHA1', 'SHA256', 'SHA384', 'SHA512'",
                        nameof(uri));
            }

            if (Parameters.ContainsKey("digits"))
            {
                if (!int.TryParse(Parameters["digits"], out var digits))
                    throw new ArgumentException("URI digits query parameter must be numeric", nameof(uri));
                Digits = digits;
                if (Digits < 6 || Digits > 8)
                    throw new ArgumentException("URI digits query parameter must be between 6 and 8");
            }

            if (Type == OtpType.Hotp && !Parameters.ContainsKey("counter"))
                throw new ArgumentException("URI of type 'hotp' must contain 'counter' query parameter");
            if (Parameters.ContainsKey("counter"))
            {
                if (!long.TryParse(Parameters["counter"], out var counter))
                    throw new ArgumentException("URI counter query parameter must be numeric", nameof(uri));
                Counter = counter;
            }

            if (Type == OtpType.Hotp && Parameters.ContainsKey("period"))
                throw new ArgumentException("URI of type 'hotp' must not contain 'period' query parameter");
            if (Parameters.ContainsKey("period"))
            {
                if (!int.TryParse(Parameters["period"], out var period))
                    throw new ArgumentException("URI digits query parameter must be numeric", nameof(uri));
                Period = period;
            }

            if (Type == OtpType.Totp && Period == null)
                Period = 30;
        }

        public OtpType Type { get; set; }
        public string Label { get; set; }
        public string Issuer { get; set; }
        public string Account { get; set; }
        
        public string Secret { get; set; }
        public byte[] SecretBuf => Utilities.Base32Decode(Secret);

        public OtpHmacAlgorithm Algorithm { get; set; }
        public int Digits { get; set; }
        public long? Counter { get; set; }
        public int? Period { get; set; }

        public Dictionary<string, string> Parameters { get; set; }
    }
}
