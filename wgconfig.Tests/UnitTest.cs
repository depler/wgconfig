using NUnit.Framework;
using System.Collections.Generic;
using System.IO;
using Wireguard.Code;

namespace Wireguard
{
    public class Tests
    {
        public string wg = null;

        [OneTimeSetUp]
        public void Setup()
        {
            wg = Utils.SearchWireguard();
            if (string.IsNullOrEmpty(wg))
                throw new FileNotFoundException(nameof(wg));
        }

        [Test]
        public void TestCurve25519()
        {
            var kvps = new Dictionary<string, string>()
            {
                { "oB2yte8v6Edhi3t3DeHX+LEfpRGi1jVb6FYTeheQ9XI=", "HfqqvO1mk4gx2bLDO6tPxTNHl6oi7Z42YLUaLj/Oe0Y=" },
                { "YDYr+o/wLbovtba446v27X//NM4szFqXdij1dKLlPl8=", "oWX4rcyZHyQAwLRG7l4tZWgRamSPhXhfurx+y3bYAGY=" },
                { "GOYViPkGsghgYGdUCVaCqvp4qTkKQ3tfPEUdCv/NT14=", "YWeFxQabAS+sKyxqJGHothzNZxdyhEPXYyBx/DtLb24=" },
                { "oKNRZnxqn6uIpQDm58xsngQtuy8Ed0tzQbsfAUZYenQ=", "+UmPSdIVMLiIpe5WNngz5Gp85bAitD1aq0SW69D5WFU=" },
                { "QFGPYiCQE/l92/1Kea1RASI+N/wKrlFypgBNahpE438=", "drKPmk5gSAGr77Nd7/oCsahsHFZmKfFisfmzMpvmzFs=" },
                { "gFxQ2NGOJDjOww84Ye4x9Y5khSGTrTKfpJr7ODeOAEs=", "9y05bruujPguw4FFJ+JM5uHqn3IziMPTk8ag8Xpv/X8=" },
                { "aCaXfvXjUpsb9MEClv6F59XoC4/9xPvp7lCUfz0n00Y=", "np0SHP6UIjvEBhNs2yJrMlqAb0w5vw64KK0sjj+AcWE=" },
                { "yF+hep+SSWf3iVAD8AgFA7qV1KFOXprmFosh6h04Vlc=", "+T64sgnEGBsixpov0ovMNe11yThM2zkf09G8NTnbiAo=" },
                { "sOdE3Tm4af1c5AUL624wdNtAR/jwV+Fdb6UqWzMSnmQ=", "Da29TizW/FfqUb4RfaJDOFkRo97W78GslypQbKL7tDQ=" },
                { "OOzuuGFc6uug5gy/5GY5QDyqheWRYDAAJQz/LBcWZHI=", "nkqKSbuLFwYNY/2QA+C+gvRIOnc0aYowROwZmftD+Gc=" },
                { "iAMBbzRD8ThURLaD4zI/XTbEN8eGE0Hg4KOh0nrZqnI=", "m/4VkymgSpp8k8bBNQmKnYY0Y6at8ttNlr+Wm4v7gzc=" },
                { "YCfrE2SwOb4skiAFIFFpYA85WR1qR5nJmVySAHusilA=", "LATS8VywXK8813rVTdn1xfB/i3QFcY8/9BGloi++2ho=" },
                { "+I05d4noKVZ1sAopMLn3NBysHEPdmfWyGSuoR1GKj2g=", "g8UNfQYTOwhQ73XQRSdlOlsiXIY7Q4nscrdyZeHFjhQ=" },
                { "AAPEMoFI13vgwge4UhpTTnYQHAaHnYbgJHWoKjZ5Y28=", "+IU+ONtYsi4sVPNY4Xdcyoc9Q+YbTShMdZMt2+s9MRI=" },
                { "4DVgmYHhWdjieJY20VvWPocR7IIv0/HuPl1DXRTd4mU=", "UtPY7Cq7G38SXdg1l1UTzsdg48taFYetMZXoa4rmZAg=" },
            };

            foreach (var kv in kvps)
            {
                var publicKey = Curve25519.GetPublicKey(kv.Key);
                Assert.AreEqual(publicKey, kv.Value);
            }
        }

        [Test]
        public void TestExternal()
        {
            for (int i = 0; i < 1000; i++)
            {
                var privateKey = (i % 2 == 0) ? Utils.CreateProcess(wg, "genkey") : Curve25519.GetPrivateKey();
                var publicKey1 = Utils.CreateProcess(wg, "pubkey", privateKey);
                var publicKey2 = Curve25519.GetPublicKey(privateKey);

                Assert.AreEqual(publicKey1, publicKey2);
            }
        }
    }
}