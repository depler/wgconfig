using System;
using System.IO;
using Wireguard.QR;

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

        public static string ReadConsoleInput()
        {
            using var stream = Console.OpenStandardInput();
            using var reader = new StreamReader(stream);

            return reader.ReadToEnd();
        }

        public static string[] ReadConsoleLines(bool removeEmpty)
        {
            var options = removeEmpty ? StringSplitOptions.RemoveEmptyEntries : StringSplitOptions.None;
            return ReadConsoleInput().Split(new[] { '\r', '\n' }, options);
        }
    }
}
