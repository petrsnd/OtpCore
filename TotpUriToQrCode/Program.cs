using Petrsnd.OtpCore;
using CommandLine;
using QRCoder;

namespace Petrsnd.TotpUriToQrCode
{
    class Program
    {
        private static void Execute(CommandLineOptions opts)
        {
            OtpAuthUri uri;
            if (!string.IsNullOrEmpty(opts.Uri))
            {
                uri = new OtpAuthUri(opts.Uri);
            }
            else
            {
                uri = new OtpAuthUri(opts.Type, Utilities.Base32Decode(opts.Secret), opts.Account, opts.Issuer,
                    (opts.Type == OtpType.Hotp ? opts.Counter : opts.Period), opts.HmacAlgorithm, opts.Digits);
            }
            var qrGenerator = new QRCodeGenerator();
            var qrCodeData = qrGenerator.CreateQrCode(uri.ToString(), QRCodeGenerator.ECCLevel.Q);
            var qrCode = new AsciiQRCode(qrCodeData);
            Console.Out.Write(qrCode.GetGraphic(1));
        }

        private static void HandleParseError(IEnumerable<Error> errors)
        {
            Console.Error.WriteLine("Invalid command line options");
            Environment.Exit(1);
        }

        private static void Main(string[] args)
        {
            Parser.Default.ParseArguments<CommandLineOptions>(args)
                .WithParsed(Execute)
                .WithNotParsed(HandleParseError);
        }
    }
}