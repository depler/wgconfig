using QRCoder;
using System;
using System.Diagnostics;
using System.IO;

namespace Wireguard.Code
{
    public static class Utils
    {
        public static string CreateProcess(string file, string args, string stdin = null)
        {
            var info = new ProcessStartInfo(file, args)
            {
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };

            using var process = Process.Start(info);

            if (!string.IsNullOrEmpty(stdin))
            {
                process.StandardInput.Write(stdin);
                process.StandardInput.Close();
            }

            process.WaitForExit();
            if (process.ExitCode != 0)
                throw new Exception();

            return process.StandardOutput.ReadToEnd().Trim();
        }

        public static void GenerateQRCode(string text, string file)
        {
            using var generator = new QRCodeGenerator();
            using var data = generator.CreateQrCode(text, QRCodeGenerator.ECCLevel.L);
            using var png = new PngByteQRCode(data);

            File.WriteAllBytes(file, png.GetGraphic(5));
        }
    }
}
