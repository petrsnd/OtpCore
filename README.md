# OtpCore
HOTP, TOTP, OTP Auth URI, and Base32 .NET Standard library

HOTP and TOTP implementation in C# targeting .NET standard 2.0, compliant with:
- (RFC 4226)[https://datatracker.ietf.org/doc/html/rfc4226] (HOTP)
- (RFC 6238)[https://datatracker.ietf.org/doc/html/rfc6238] (TOTP)

It has been verified against test vectors supplied in the RFCs. The interface includes support for
multiple algorithms:
- HMAC-SHA1
- HMAC-SHA256
- HMAC-SHA384
- HMAC-SHA512

It supports variable code lengths (6 - 10) and an adjustable period, or time step, (1 second - 1 hour) for TOTP.

The reason for creating this library was to fetch multiple HOTP counters or a TOTP time range in
a single call.

A parser for OTP Auth URIs is also included that conforms to the documentation found at:
https://github.com/google/google-authenticator/wiki/Key-Uri-Format.

This implementation also includes a Base32 encoder and decoder. It is compliant with
(RFC 4648)[https://datatracker.ietf.org/doc/html/rfc4648],
using the standard alphabet from (section 6)[https://datatracker.ietf.org/doc/html/rfc4648#section-6],
and has been tested against the test vectors from
(section 10)[https://datatracker.ietf.org/doc/html/rfc4648#section-10].

# Examples
OtpCore is just a static utility library with static methods.  It does not track counters or
store secrets.

Fetch a simple code.

```C#
// Hotp
var secret = Encoding.ASCII.GetBytes("12345678901234567890");
long counter = 0;
int digits = 6;
var hotpCode = Hotp.GetHotpCode(secret, counter, OtpHmacAlgorithm.HmacSha1, digits));

// Totp
int period = 30;
digits = 8;
long unixTime = 1111111111; // 2005-03-18 01:58:31 +0:00
var totpCode = Totp.GetTotpCode(secret, unixTime, period, OtpHmacAlgorithm.HmacSha1, digits);

var timeFuture = DateTimeOffset.Parse("2033-05-18 03:33:20 -7:00");
var totpCode = Totp.GetTotpCode(secret, timeFuture, period, OtpHmacAlgorithm.HmacSha1, digits);

var totpCode = Totp.GetTotpCode(secret, DateTimeOffset.Now, period, OtpHmacAlgorithm.HmacSha1, digits);
```

Fetch multiple codes.

```C#
// Hotp
var secret = Encoding.ASCII.GetBytes("12345678901234567890");
long counter = 0;
int sequenceLength = 5; // next 5 codes
int digits = 6;
var hotpValues = Hotp.GetHotpCode(secret, counter, sequenceLength, OtpHmacAlgorithm.HmacSha1, digits));

// Totp
// Totp
int period = 30;
digits = 8;
var range = TimeSpan.FromSeconds(120); // two minutes worth of codes

var totpValues = Totp.GetTotpRange(secret, DateTimeOffset.Now, range, period, OtpHmacAlgorithm.HmacSha1, digits);
```

HOTP Values:
TOTP Values:

It's free. Enjoy!
