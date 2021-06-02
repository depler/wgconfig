using Net.Codecrete.QrCodeGenerator;
using System;
using System.IO;
using System.Text;

namespace Wireguard.Code
{
    public static class Utils
    {
        public static void GenerateQrCode(string text, string file)
        {
            var qrCode =  QrCode.EncodeBinary(Encoding.UTF8.GetBytes(text), QrCode.Ecc.Low);
            var qrCodePng = new QrCodePng(qrCode, 5, 5);

            File.WriteAllBytes(file, qrCodePng.GetBytes());
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
