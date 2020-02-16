using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TrojanPlugin {
    public static class Extensions {
        private const string HexAlphabet = "0123456789abcdef";

        public static string ToHexString(this byte[] bytes) {
            var result = new StringBuilder(bytes.Length * 2);

            foreach (var b in bytes) {
                result.Append(HexAlphabet[b >> 4]);
                result.Append(HexAlphabet[b & 0xF]);
            }

            return result.ToString();
        }
    }
}
