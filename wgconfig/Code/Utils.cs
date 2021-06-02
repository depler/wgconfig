using Net.Codecrete.QrCodeGenerator;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Wireguard.Code
{
    public static class Utils
    {
        public static void GenerateQrCode(string text, string file)
        {
            var qrSegment = QrSegment.MakeBytes(Encoding.UTF8.GetBytes(text));
            var qrCode =  QrCode.EncodeSegments(new List<QrSegment>() { qrSegment }, QrCode.Ecc.Low, 10, 40, 0, false);
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
