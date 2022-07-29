[![Build status](https://img.shields.io/appveyor/build/petrsnd/OtpCore)](https://ci.appveyor.com/project/petrsnd/otpcore)
[![nuget](https://img.shields.io/nuget/vpre/OtpCore)](https://www.nuget.org/packages/OtpCore)
[![License](https://img.shields.io/github/license/petrsnd/OtpCore)](https://github.com/petrnsd/OtpCore/blob/master/LICENSE)


# OtpCore
[HOTP](https://github.com/petrsnd/OtpCore#hotp), [TOTP](https://github.com/petrsnd/OtpCore#totp), OTP Auth URI, and 
[Base32]() implementation in C# targeting .NET standard 2.0, compliant with:
- [RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226) (HOTP)
- [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238) (TOTP)

It has been verified against test vectors supplied in the RFCs. The interface includes support for
multiple algorithms:
- HMAC-SHA1
- HMAC-SHA256
- HMAC-SHA384
- HMAC-SHA512

It supports variable code lengths (6 - 10) and an adjustable period, or time step, (1 second - 1 hour) for TOTP.

The reason for creating this library was to fetch multiple HOTP counters or a TOTP time range in
a single call.

A parser for OTP Auth URIs (otpauth://) is also included that conforms to the documentation found at:
https://github.com/google/google-authenticator/wiki/Key-Uri-Format.

This implementation also includes a Base32 encoder and decoder. It is compliant with
[RFC 4648](https://datatracker.ietf.org/doc/html/rfc4648),
using the standard alphabet from [section 6](https://datatracker.ietf.org/doc/html/rfc4648#section-6),
and has been tested against the test vectors from
[section 10](https://datatracker.ietf.org/doc/html/rfc4648#section-10).

It's free. Enjoy!

# Examples

## Authenticators
OtpCore provides `HotpAuthenticator` and `TotpAuthenticator` classes which can be instantiated from a
OTP Auth URI using the `GetAuthenticator()` method in the `Hotp` and `Totp` classes.

### HOTP
```C#
// Create from string
var uriString = "otpauth://hotp/NOBODY:petrsnd@gmail.com?issuer=NOBODY&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA1&digits=6&counter=0";
var authenticator = Hotp.GetAuthenticator(uriString);
// Create from Uri object
var uri = new Uri(uriString);
authenticator = Hotp.GetAuthenticator(uri);
// Create from scratch by supplying parameters
var secret = Encoding.ASCII.GetBytes("12345678901234567890");
var account = "bob@example.corp";
var issuer = "Example";
var counter = 0;
var otpAuthUri = new OtpAuthUri(OtpType.Hotp, secret, account, issuer, counter); // issuer is optional, digits defaults to 6
authenticator = Hotp.GetAuthenticator(otpAuthUri);
// Get a code or a sequence of codes
var code = authenticator.GetCode();
var sequence = authenticator.GetSequence(3);
// Increment or set the counter
authenticator.IncrementCounter();
authenticator.SetCounter(3);
// Revert back to a string for storage with updated counter in URI
// The URI is left unchanged unless IncrementCounter() or SetCounter() are called
uriString = authenticator.ToString();
```

### TOTP
```C#
// Create from string
var uriString = "otpauth://totp/NOBODY:petrsnd@gmail.com?issuer=NOBODY&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&algorithm=SHA256&digits=8";
var authenticator = Totp.GetAuthenticator(uriString);
// Create from Uri object
var uri = new Uri(uriString);
authenticator = Totp.GetAuthenticator(uri);
// Create from scratch by supplying parameters
var secret = Encoding.ASCII.GetBytes("12345678901234567890");
var account = "bob@example.corp";
var issuer = "Example";
var otpAuthUri = new OtpAuthUri(OtpType.Totp, secret, account, issuer); // issuer is optional, digits defaults to 6, period defaults to 30
authenticator = Totp.GetAuthenticator(otpAuthUri);
// Get a code or a range of codes
var code = authenticator.GetCode();
var range = authenticator.GetRange(TimeSpan.FromSeconds(90));
// No counter to manage with TOTP!!!
// Revert back to a string for storage if it was created from scratch
uriString = authenticator.ToString();
```

## Static Methods
OtpCore may also be used as a static utility library by only calling the static methods for HOTP and TOTP.
When used this way, no object tracks counters or store secrets.

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
int period = 30;
digits = 8;
var range = TimeSpan.FromSeconds(120); // two minutes worth of codes

var totpValues = Totp.GetTotpRange(secret, DateTimeOffset.Now, range, period, OtpHmacAlgorithm.HmacSha1, digits);
```

- HOTP Values format: [HotpValue.cs](OtpCore/HotpValue.cs)
- TOTP Values format: [TotpValue.cs](OtpCore/TotpValue.cs)

## Base32 Encoding and Decoding
You may just want a simple Base32 encoder/decoder, because it isn't supplied in the .NET SDK.

```C#
var buffer = Encoding.ASCII.GetBytes("12345678901234567890");
var encoded = Utilities.Base32Encode(buffer); // GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
var decoded = Utilities.Base32Decode(encoded);
```
