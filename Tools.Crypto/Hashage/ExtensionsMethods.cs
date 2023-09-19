using System.Security.Cryptography;
using System.Text;

namespace Tools.Crypto.Hashage
{
    public static class ExtensionsMethods
    {
        public static string Hash(this string text)
        {
            byte[] byteArray = Encoding.Default.GetBytes(text);
            return byteArray.Hash();
        }

        public static string Hash(this byte[] array)
        {
            byte[] sha512 = SHA512.HashData(array);
            return Convert.ToBase64String(sha512);
        }
    }
}