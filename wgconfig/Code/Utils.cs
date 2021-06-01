using QRCoder;
using System.IO;

namespace Wireguard.Code
{
    public static class Utils
    {
        public static void GenerateQRCode(string text, string file)
        {
            using var generator = new QRCodeGenerator();
            using var data = generator.CreateQrCode(text, QRCodeGenerator.ECCLevel.L);
            using var png = new PngByteQRCode(data);

            File.WriteAllBytes(file, png.GetGraphic(5));
        }
    }
}
