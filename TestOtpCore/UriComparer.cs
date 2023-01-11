using System;

namespace Petrsnd.OtpCore.Test
{
    internal static class UriComparer
    {
        public static bool AreEqual(Uri a, Uri b)
        {
            return Uri.Compare(a, b, UriComponents.AbsoluteUri, UriFormat.Unescaped,
                StringComparison.CurrentCulture) == 0;
        }

        public static bool AreEqual(string a, string b)
        {
            return AreEqual(new Uri(a), new Uri(b));
        }
    }
}
