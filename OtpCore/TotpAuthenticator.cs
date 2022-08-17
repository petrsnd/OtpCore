using System;

namespace Petrsnd.OtpCore
{
    public class TotpAuthenticator
    {
        private readonly OtpAuthUri _uri;

        internal TotpAuthenticator(OtpAuthUri uri)
        {
            _uri = uri;
            if (_uri == null)
                throw new ArgumentNullException(nameof(uri), "OTP Auth URI cannot be null");
            if (_uri.Type != OtpType.Totp)
                throw new ArgumentException("OTP Auth URI must be of type TOTP", nameof(uri));
            if (_uri.Period == null)
                throw new Exception("Period was not set--should have defaulted to 30");
        }

        public OtpType Type => _uri.Type;
        public string Label => _uri.Label;
        public string Issuer => _uri.Issuer;
        public string Account => _uri.Account;
        public OtpHmacAlgorithm Algorithm => _uri.Algorithm;
        public int Digits => _uri.Digits;
        public int Period => _uri.Period.Value;

        public override string ToString()
        {
            return _uri.ToString();
        }

        public string GetCode()
        {
            return GetCode(DateTimeOffset.UtcNow);
        }

        public string GetCode(DateTimeOffset time)
        {
            if (_uri.Period == null)
                throw new Exception("Period was not set--should have defaulted to 30");
            return Totp.GetTotpCode(_uri.SecretBuf, time, _uri.Period.Value, _uri.Algorithm, _uri.Digits);
        }

        public TotpValue[] GetRange(TimeSpan range)
        {
            return GetRange(DateTimeOffset.UtcNow, range);
        }

        public TotpValue[] GetRange(DateTimeOffset time, TimeSpan range)
        {
            if (_uri.Period == null)
                throw new Exception("Period was not set--should have defaulted to 30");
            return Totp.GetTotpRange(_uri.SecretBuf, time, range, _uri.Period.Value, _uri.Algorithm, _uri.Digits);
        }
    }
}
