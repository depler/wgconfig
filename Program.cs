using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace wgconfig
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

    class Program
    {
        static string CreateProcess(string file, string args, string stdin = null)
        {
            var process = Process.Start(new ProcessStartInfo(file, args)
            {
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError= true,

            });

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

        static KeyData GenerateKeys(string wgExe)
        {
            var privateKey = CreateProcess(wgExe, "genkey");
            var publicKey = CreateProcess(wgExe, "pubkey", privateKey);
            var presharedKey = CreateProcess(wgExe, "genkey");
            return new KeyData(privateKey, publicKey, presharedKey);
        }

        static string GetClientConfig(KeyData clientKey, string serverKey, string serverIp, string serverPort, int ip)
        {
            var sb = new StringBuilder();

            sb.AppendLine("[Interface]");
            sb.AppendLine($"PrivateKey = {clientKey.PrivateKey}");
            sb.AppendLine($"Address = 10.8.0.{ip}/24");
            sb.AppendLine("DNS = 94.140.14.14,94.140.15.15");
            sb.AppendLine(string.Empty);
            sb.AppendLine("[Peer]");
            sb.AppendLine($"PublicKey = {serverKey}");
            sb.AppendLine($"PresharedKey = {clientKey.PresharedKey}");
            sb.AppendLine($"Endpoint = {serverIp}:{serverPort}");
            sb.AppendLine("PersistentKeepalive = 25");
            sb.AppendLine("AllowedIPs = 10.8.0.0/24");

            return sb.ToString();
        }

        static string GetServerConfig(string privateKey, KeyData[] clientKeys, string port)
        {
            var sb = new StringBuilder();

            sb.AppendLine("[Interface]");
            sb.AppendLine($"PrivateKey = {privateKey}");
            sb.AppendLine($"Address = 10.8.0.1/24");
            sb.AppendLine($"ListenPort = {port}");
            sb.AppendLine("PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE");
            sb.AppendLine("PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE");

            int ip = 2;
            for (int i = 0; i < clientKeys.Length; i++)
            {
                var clientKey = clientKeys[i];

                sb.AppendLine(string.Empty);
                sb.AppendLine("[Peer]");
                sb.AppendLine($"PublicKey = {clientKey.PublicKey}");
                sb.AppendLine($"PresharedKey = {clientKey.PresharedKey}");
                sb.AppendLine($"AllowedIPs = 10.8.0.{ip++}/32");
            }

            return sb.ToString();
        }

        static void ResolveDns(string[] hosts, out string ipstotal1, out string ipstotal2)
        {
            var ips = hosts
                .Select(x => Dns.GetHostAddresses(x))
                .SelectMany(x => x).Where(x => x.AddressFamily == AddressFamily.InterNetwork)
                .Select(x => x.ToString()).OrderBy(x => x).ToArray();

            ipstotal1 = ips.Select(x => x + "/32").Aggregate((x, y) => x + "," + y);
            ipstotal2 = ips.Select(x => $"route add {x} mask 255.255.255.255 10.8.0.1").Aggregate((x, y) => x + "\n" + y);
        }

        static string SearchWireguard()
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

        static string ReadConsoleInput()
        {
            using (var stream = Console.OpenStandardInput())
            using (var reader = new StreamReader(stream))
            {
                return reader.ReadToEnd();
            }
        }

        static void Main(string[] args)
        {
            try
            {
                var utf8 = new UTF8Encoding(false);

                var wgExe = SearchWireguard();
                Console.WriteLine("Wireguard path: " + wgExe);

                var configFolder = Path.Combine(Directory.GetCurrentDirectory(), "config");
                Console.WriteLine("Config folder: " + configFolder);

                if (args.Length == 0)
                {
                    Console.WriteLine("Usage:");
                    Console.WriteLine("--config <server_ip> <server_port> <clients_count>: generate wg config");
                    Console.WriteLine("--routes <stdin>: resolve hosts to IPs");
                    Console.WriteLine("--wg <wg path override>");
                    Console.WriteLine("--folder <config folder override>");
                    return;
                }

                for (int i = 0; i < args.Length; i++)
                {
                    var arg = args[i];

                    switch (arg)
                    {
                        case "--wg":
                            {
                                wgExe = args[++i];
                                Console.WriteLine("Wireguard path override: " + wgExe);
                                break;
                            }
                        case "--folder":
                            {
                                configFolder = args[++i];
                                Console.WriteLine("configFolder folder override: " + configFolder);
                                break;
                            }
                        case "--routes":
                            {
                                if (!Directory.Exists(configFolder))
                                    Directory.CreateDirectory(configFolder);

                                Console.WriteLine("Resolving dns...");
                                var hosts = ReadConsoleInput().Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                                ResolveDns(hosts, out string ipstotal1, out string ipstotal2);

                                Console.WriteLine("Saving resolved to files...");
                                File.WriteAllText(Path.Combine(configFolder, "routes1.txt"), ipstotal1);
                                File.WriteAllText(Path.Combine(configFolder, "routes2.txt"), ipstotal2);
                                break;
                            }
                        case "--config":
                            {
                                if (!Directory.Exists(configFolder))
                                    Directory.CreateDirectory(configFolder);

                                var serverIp = args[++i];
                                var serverPort = args[++i];

                                int clients = int.Parse(args[++i]);
                                if (clients > 254)
                                    throw new Exception("No more than 254 clients");

                                Console.WriteLine("Generating configs...");
                                var serverKeys = GenerateKeys(wgExe);
                                var clientKeys = Enumerable.Range(0, clients).Select(x => GenerateKeys(wgExe)).ToArray();

                                for (int j = 0; j < clientKeys.Length; j++)
                                {
                                    var configPath = Path.Combine(configFolder, $"client{j + 1:D3}.conf");
                                    var configData = GetClientConfig(clientKeys[j], serverKeys.PublicKey, serverIp, serverPort, j + 2);
                                    File.WriteAllText(configPath, configData, utf8);
                                }

                                var serverConfigPath = Path.Combine(configFolder, "server.conf");
                                var serverConfigData = GetServerConfig(serverKeys.PrivateKey, clientKeys, serverPort);
                                File.WriteAllText(serverConfigPath, serverConfigData, utf8);

                                break;
                            }
                        default: throw new Exception("Unknown argument: " + arg);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
        }
    }
}
