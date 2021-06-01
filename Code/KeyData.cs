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
    }
}
