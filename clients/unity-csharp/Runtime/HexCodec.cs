using System;
using System.Text;

namespace CardKey.Unity
{
    internal static class HexCodec
    {
        public static string EncodeLower(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            var builder = new StringBuilder(bytes.Length * 2);
            foreach (var value in bytes) builder.Append(value.ToString("x2"));
            return builder.ToString();
        }

        public static byte[] Decode(string value)
        {
            if (value == null) throw new ArgumentNullException(nameof(value));
            if ((value.Length & 1) != 0) throw new FormatException("Odd-length hexadecimal value.");
            var bytes = new byte[value.Length / 2];
            for (var i = 0; i < bytes.Length; i++)
            {
                var high = Value(value[i * 2]);
                var low = Value(value[i * 2 + 1]);
                bytes[i] = (byte)((high << 4) | low);
            }
            return bytes;
        }

        private static int Value(char value)
        {
            if (value >= '0' && value <= '9') return value - '0';
            if (value >= 'a' && value <= 'f') return value - 'a' + 10;
            if (value >= 'A' && value <= 'F') return value - 'A' + 10;
            throw new FormatException("Invalid hexadecimal value.");
        }
    }
}
