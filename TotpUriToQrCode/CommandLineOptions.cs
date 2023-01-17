using CommandLine;
using Petrsnd.OtpCore;


namespace Petrsnd.TotpUriToQrCode
{
    internal class CommandLineOptions
    {
        [Option('t', "Type", Required = true, SetName = "Params",
            HelpText = "OTP type (HOTP or TOTP)")]
        public OtpCore.OtpType Type { get; set; }

        [Option('s', "Secret", Required = true, SetName = "Params",
            HelpText = "Secret as base32 string")]
        public string? Secret { get; set; }

        [Option('a', "Account", Required = true, SetName = "Params",
            HelpText = "Name of the account")]
        public string? Account { get; set; }

        [Option('i', "Issuer", Required = false, Default = null, SetName = "Params",
            HelpText = "Issuer of the OTP")]
        public string? Issuer{ get; set; }

        [Option('c', "Counter", Required = false, Default = 0, SetName = "Params",
            HelpText = "Counter for HTOP")]
        public int Counter { get; set; }

        [Option('p', "Period", Required = false, Default = 30, SetName = "Params",
            HelpText = "Period for TOTP")]
        public int Period { get; set; }

        [Option('H', "HmacAlgorithm", Required = false, Default = OtpHmacAlgorithm.HmacSha1, SetName = "Params",
            HelpText = "HMAC algorithm to use")]
        public OtpHmacAlgorithm HmacAlgorithm { get; set; }

        [Option('d', "Digits", Required = false, Default = 6, SetName = "Params",
            HelpText = "Number of digits in codes")]
        public int Digits { get; set; }

        [Option('U', "Uri", Required = true, SetName = "Uri",
            HelpText = "URI for authenticator")]
        public string? Uri { get; set; }
    }
}
