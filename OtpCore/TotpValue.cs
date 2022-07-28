using System;

namespace Petrsnd.OtpCore
{
    public class TotpValue
    {
        public DateTimeOffset TimeStamp { get; set; }
        public long UnixTime { get; set; }
        public long Counter { get; set; }
        public int Period { get; set; }
        public string Code { get; set; }
    }
}
