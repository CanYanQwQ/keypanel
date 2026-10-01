using System;
using System.Security.Cryptography;

namespace CardKey.Unity
{
    /// <summary>RFC 5869 HKDF using HMAC-SHA256. This is only key derivation; it is not encryption.</summary>
    public static class HkdfSha256
    {
        public static byte[] Derive(byte[] ikm, byte[] salt, byte[] info, int length)
        {
            if (ikm == null) throw new ArgumentNullException(nameof(ikm));
            if (info == null) throw new ArgumentNullException(nameof(info));
            if (length < 0 || length > 255 * 32) throw new ArgumentOutOfRangeException(nameof(length));
            if (salt == null || salt.Length == 0) salt = new byte[32];

            byte[] prk;
            using (var hmac = new HMACSHA256(salt)) prk = hmac.ComputeHash(ikm);

            var output = new byte[length];
            var previous = new byte[0];
            var offset = 0;
            for (byte counter = 1; offset < length; counter++)
            {
                var input = new byte[previous.Length + info.Length + 1];
                Buffer.BlockCopy(previous, 0, input, 0, previous.Length);
                Buffer.BlockCopy(info, 0, input, previous.Length, info.Length);
                input[input.Length - 1] = counter;
                using (var hmac = new HMACSHA256(prk)) previous = hmac.ComputeHash(input);

                var copyLength = Math.Min(previous.Length, length - offset);
                Buffer.BlockCopy(previous, 0, output, offset, copyLength);
                offset += copyLength;
            }

            return output;
        }
    }
}
