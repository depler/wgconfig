using System;
using System.Diagnostics;
using System.IO;

namespace Wireguard;

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

    public static string SearchWireguard()
    {
        foreach (var file in new[]
        {
            @"c:\Program Files\WireGuard\wg.exe",
            "/usr/bin/wg"
        })
        {
            if (File.Exists(file))
                return file;
        }

        return null;
    }
}
