using System;

namespace Petrsnd.OtpCore
{
    public class HotpAuthenticator
    {
        private OtpAuthUri _uri;

        internal HotpAuthenticator(OtpAuthUri uri)
        {
            _uri = uri;
            if (_uri == null)
                throw new ArgumentNullException(nameof(uri), "OTP Auth URI cannot be null");
            if (_uri.Type != OtpType.Hotp)
                throw new ArgumentException("OTP Auth URI must be of type TOTP", nameof(uri));
            if (_uri.Counter == null)
                throw new Exception("Counter was not set");
        }

        public OtpType Type => _uri.Type;
        public string Label => _uri.Label;
        public string Issuer => _uri.Issuer;
        public string Account => _uri.Account;
        public OtpHmacAlgorithm Algorithm => _uri.Algorithm;
        public long Counter => _uri.Counter ?? 0;

        public override string ToString()
        {
            return _uri.ToString();
        }

        public void IncrementCounter()
        {
            if (_uri.Counter == null)
                throw new Exception("Counter was not set");
            SetCounter(unchecked(_uri.Counter.Value + 1));
        }

        public void SetCounter(long counter)
        {
            // Side effect -- modifies the underlying URI and previous formatting is overridden
            _uri = new OtpAuthUri(OtpType.Hotp, _uri.SecretBuf, _uri.Account, _uri.Issuer, counter, _uri.Algorithm,
                _uri.Digits);
        }

        public string GetCode()
        {
            if (_uri.Counter == null)
                throw new Exception("Counter was not set");
            return Hotp.GetHotpCode(_uri.SecretBuf, _uri.Counter.Value, _uri.Algorithm, _uri.Digits);
        }

        public HotpValue[] GetSequence(int sequenceLength)
        {
            if (_uri.Counter == null)
                throw new Exception("Counter was not set");
            return Hotp.GetHotpSequence(_uri.SecretBuf, _uri.Counter.Value, sequenceLength, _uri.Algorithm, _uri.Digits);
        }
    }
}
