using System.Linq;

namespace Wireguard.Code
{
    public class KeyData
    {
        public string PrivateKey;
        public string PublicKey;
        public string PresharedKey;

        public KeyData(string privateKey, string publicKey, string presharedKey)
        {
            PrivateKey = privateKey;
            PublicKey = publicKey;
            PresharedKey = presharedKey;
        }

        public static KeyData Generate()
        {
            var privateKey = Curve25519.GetPrivateKey();
            var publicKey = Curve25519.GetPublicKey(privateKey);
            var presharedKey = Curve25519.GetPresharedKey();

            return new KeyData(privateKey, publicKey, presharedKey);
        }

        public static KeyData[] Generate(int count)
        {
            return Enumerable.Range(0, count).Select(x => Generate()).ToArray();
        }
    }
}
