using System;
using System.Collections.Generic;
using System.Text;
using System.Web;

namespace Petrsnd.OtpCore
{
    public class OtpAuthUri
    {
        public OtpAuthUri(OtpType type, byte[] secret, string account, string issuer = null, long counterOrPeriod = 30,
            OtpHmacAlgorithm algorithm = OtpHmacAlgorithm.HmacSha1, int digits = 6)
        {
            if (string.IsNullOrEmpty(account))
                throw new ArgumentException("Account must be specified", nameof(account));
            if (secret == null || secret.Length == 0)
                throw new ArgumentException("Secret must not be empty or null", nameof(secret));
            if (type != OtpType.Hotp && type != OtpType.Totp)
                throw new ArgumentException("OTP type must be hotp or totp", nameof(type));
            Type = type;
            Account = account;
            Secret = Utilities.Base32Encode(secret);
            Algorithm = algorithm;
            Digits = digits;

            string uriString;
            if (!string.IsNullOrEmpty(issuer))
            {
                IssuerLabel = issuer;
                IssuerParameter = issuer;
                Label = $"{Issuer}:{Account}";
                uriString =
                    $"otpauth://{Type.ToString().ToLower()}/{Uri.EscapeDataString(Label)}?secret={Secret}&issuer={Issuer}&algorithm={Utilities.OtpHmacAlgorithmToString(Algorithm)}";
            }
            else
            {
                Label = Account;
                uriString =
                    $"otpauth://{Type.ToString().ToLower()}/{Uri.EscapeDataString(Label)}?secret={Secret}&algorithm={Utilities.OtpHmacAlgorithmToString(Algorithm)}";
            }
            
            if (Type == OtpType.Hotp)
            {
                Counter = counterOrPeriod;
                uriString += $"&counter={Counter}&digits={Digits}";
            }
            else if (Type == OtpType.Totp)
            {
                Period = (int)counterOrPeriod;
                uriString += $"&period={Period}&digits={Digits}";
            }

            Uri = new Uri(uriString);
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
            Uri = uri;
            if (Uri.Scheme != "otpauth")
                throw new ArgumentException("URI scheme must be 'otpauth'", nameof(uri));
            if (Uri.Authority != "hotp" && Uri.Authority != "totp")
                throw new ArgumentException("URI authority must be one of 'hotp' or totp'", nameof(uri));
            if (Uri.Authority == "hotp")
                Type = OtpType.Hotp;
            else if (Uri.Authority == "totp")
                Type = OtpType.Totp;

            if (Uri.Segments.Length != 2)
                throw new ArgumentException("URI must contain a label after the authority", nameof(uri));
            if (Uri.Segments[0] != "/")
                throw new ArgumentException("URI is missing separator between authority and label", nameof(uri));
            Label = Uri.UnescapeDataString(Uri.Segments[1]);
            if (Label.Contains(":"))
            {
                var split = Label.Split(new[] { ':' }, 2);
                IssuerLabel = split[0];
                Account = split[1].TrimStart(' ');
                SavedSpaces = new string(' ', split[1].Length - Account.Length);
            }
            else
            {
                Account = Label;
            }

            if (string.IsNullOrEmpty(Uri.Query))
                throw new ArgumentException("URI must contain a query string", nameof(uri));
            var nameValues = HttpUtility.ParseQueryString(Uri.Query);
            foreach (var key in nameValues.Keys)
            {
                Parameters[key.ToString().ToLower()] = nameValues[key.ToString()];
            }

            if (IssuerLabel != null && (IssuerLabel.Contains(":") || Account.Contains(":")))
            {
                if (!Parameters.ContainsKey("issuer"))
                {
                    throw new ArgumentException(
                        "URI label issuer and account may not contain colons, unless issuer parameter is present",
                        nameof(uri));
                }
                if (!Label.StartsWith(Parameters["issuer"] + ":"))
                {
                    throw new ArgumentException(
                        "URI label issuer and account may not contain colons, unless issuer parameter matches issuer in label",
                        nameof(uri));
                }

                IssuerLabel = Parameters["issuer"];
                IssuerParameter = IssuerLabel;
                Account = Label.Substring(Parameters["issuer"].Length + 1);
            }

            if (!Parameters.ContainsKey("secret"))
                throw new ArgumentException("URI must contain a parameter called 'secret'", nameof(uri));
            Secret = Parameters["secret"];
            if (string.IsNullOrEmpty(Secret))
                throw new ArgumentException("URI must contain a parameter called 'secret' that is not empty", nameof(uri));
            Utilities.Base32Decode(Secret); // Test decoding

            if (Parameters.ContainsKey("issuer"))
            {
                IssuerParameter = Parameters["issuer"];
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

        public override string ToString()
        {
            // Microsoft URI ToString support is not great.  By default, Uri.ToString() method only escapes some characters:
            // "The unescaped canonical representation of the Uri instance. All characters are unescaped except #, ?, and %."
            // see https://learn.microsoft.com/en-us/dotnet/api/system.uri.tostring
            // In order to get an example from the spec to pass unit tests, I have had to manually rebuild the string representation.
            //   Also,
            // HttpUtility.UrlEncode adds + for spaces (weird)
            var sb = new StringBuilder("otpauth://");
            sb.Append(Type.ToString().ToLower());
            sb.Append("/");
            if (!string.IsNullOrEmpty(IssuerLabel))
            {
                sb.Append(Uri.EscapeDataString(IssuerLabel));
                sb.Append(":");
            }
            if (!string.IsNullOrEmpty(SavedSpaces))
                sb.Append(Uri.EscapeDataString(SavedSpaces));
            sb.Append(Uri.EscapeDataString(Account));
            sb.Append(Uri.Query);
            return sb.ToString();
        }

        public Uri Uri { get; }

        public OtpType Type { get; }
        public string Label { get; }

        public string IssuerLabel { get; }
        public string IssuerParameter { get; }

        public string Issuer
        {
            get
            {
                if (!string.IsNullOrEmpty(IssuerParameter))
                    return IssuerParameter;
                if (!string.IsNullOrEmpty(IssuerLabel))
                    return IssuerLabel;
                return null;
                
            }
        }

        public string Account { get; }

        private string SavedSpaces { get; }

        public string Secret { get; }
        public byte[] SecretBuf => Utilities.Base32Decode(Secret);

        public OtpHmacAlgorithm Algorithm { get; }
        public int Digits { get; }
        public long? Counter { get; }
        public int? Period { get; }

        public Dictionary<string, string> Parameters { get; }
    }
}
