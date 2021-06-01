using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Wireguard.Code
{
    class Program
    {
        static KeyData GenerateKeys()
        {
            var privateKey = Curve25519.GetPrivateKey();
            var publicKey = Curve25519.GetPublicKey(privateKey);
            var presharedKey = Curve25519.GetPresharedKey();

            return new KeyData(privateKey, publicKey, presharedKey);
        }

        static string GetSubnetIp(string subnet, int ip)
        {
            var dot = subnet.LastIndexOf('.');
            var part = subnet.Substring(0, dot + 1);
            return string.Concat(part, ip);
        }

        static string GetClientConfig(KeyData clientKey, string serverKey, string serverIp, string serverPort, string subnet, int ip)
        {
            var sb = new StringBuilder();

            sb.AppendLine("[Interface]");
            sb.AppendLine($"PrivateKey = {clientKey.PrivateKey}");
            sb.AppendLine($"Address = {GetSubnetIp(subnet, ip++)}/24");
            sb.AppendLine("DNS = 94.140.14.14,94.140.15.15");
            sb.AppendLine(string.Empty);
            sb.AppendLine("[Peer]");
            sb.AppendLine($"PublicKey = {serverKey}");
            sb.AppendLine($"PresharedKey = {clientKey.PresharedKey}");
            sb.AppendLine($"Endpoint = {serverIp}:{serverPort}");
            sb.AppendLine("PersistentKeepalive = 25");
            sb.AppendLine($"AllowedIPs = {subnet}/24");

            return sb.ToString();
        }

        static string GetServerConfig(string privateKey, KeyData[] clientKeys, string subnet, string port)
        {
            var sb = new StringBuilder();

            sb.AppendLine("[Interface]");
            sb.AppendLine($"PrivateKey = {privateKey}");
            sb.AppendLine($"Address = {GetSubnetIp(subnet, 1)}/24");
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
                sb.AppendLine($"AllowedIPs = {GetSubnetIp(subnet, ip++)}/32");
            }

            return sb.ToString();
        }

        static void ResolveDns(string[] hosts, out string ips_cidr, out string ips_mask)
        {
            var ips = hosts
                .Select(x => Dns.GetHostAddresses(x))
                .SelectMany(x => x).Where(x => x.AddressFamily == AddressFamily.InterNetwork)
                .Select(x => x.ToString()).OrderBy(x => x).ToArray();

            ips_cidr = ips.Select(x => x + "/32").Aggregate((x, y) => x + "," + y);
            ips_mask = ips.Select(x => $"route add {x} mask 255.255.255.255 0.0.0.0").Aggregate((x, y) => x + "\n" + y);
        }


        static string GetSubnetMask(int bits)
        {
            if (bits > 32)
                throw new Exception("32 bits maximum for IP");

            var mask = new int[4];
            int conter = 0;

            for (int i = 0; i < 4; i++)
                for (int j = 7; j >= 0; j--)
                {
                    if (++conter > bits)
                        break;

                    mask[i] |= 1 << j;
                }

            return $"{mask[0]}.{mask[1]}.{mask[2]}.{mask[3]}";
        }

        static string[] ConvertCIDR(string[] subnets)
        {
            var converted = new List<string>(subnets.Length);

            foreach (var subnet in subnets)
            {
                var slash = subnet.LastIndexOf('/');
                var ip = subnet.Substring(0, slash);
                var bitsCount = int.Parse(subnet.Substring(++slash, subnet.Length - slash));
                var mask = GetSubnetMask(bitsCount);

                converted.Add($"route add {ip} mask {mask} 0.0.0.0");
            }

            return converted.ToArray();
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
            using var stream = Console.OpenStandardInput();
            using var reader = new StreamReader(stream);

            return reader.ReadToEnd();
        }

        static void Main(string[] args)
        {
            var q = string.Join("\n", Enumerable.Range(0, 15).Select(x =>
             {
                 var k1 = Curve25519.GetPrivateKey();
                 var k2 = Curve25519.GetPublicKey(k1);
                 return $"{{ \"{k1}\", \"{k2}\" }}";
 
             }));



            try
            {
                var utf8 = new UTF8Encoding(false);

                var configFolder = Path.Combine(Directory.GetCurrentDirectory(), "config");
                Console.WriteLine("Config folder: " + configFolder);

                if (args.Length == 0)
                {
                    Console.WriteLine("Usage:");
                    Console.WriteLine("--config <server_ip> <server_port> <subnet> <clients_count>: generate wg config");
                    Console.WriteLine("--folder <config folder override>");
                    return;
                }

                for (int i = 0; i < args.Length; i++)
                {
                    var arg = args[i];

                    switch (arg)
                    {
                        case "--folder":
                            {
                                configFolder = args[++i];
                                Console.WriteLine("configFolder folder override: " + configFolder);
                                break;
                            }
                        case "--routes":
                            {
                                Directory.CreateDirectory(configFolder);
                                var fileName = args[++i];

                                Console.WriteLine("Resolving dns...");
                                var hosts = ReadConsoleInput().Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                                ResolveDns(hosts, out string ips_cidr, out string ips_mask);

                                Console.WriteLine("Saving resolved to files...");
                                File.WriteAllText(Path.Combine(configFolder, $"cidr_{fileName}.txt"), ips_cidr);
                                File.WriteAllText(Path.Combine(configFolder, $"mask_{fileName}.txt"), ips_mask);

                                Console.WriteLine("Done");
                                break;
                            }
                        case "--cidr-convert":
                            {
                                Directory.CreateDirectory(configFolder);
                                var fileName = args[++i];

                                Console.WriteLine("Converting cidr subnets...");
                                var cidrSubnets = ReadConsoleInput().Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                                var converted = ConvertCIDR(cidrSubnets);

                                Console.WriteLine("Saving converted to file...");
                                File.WriteAllLines(Path.Combine(configFolder, $"{fileName}.txt"), converted);

                                Console.WriteLine("Done");
                                break;
                            }
                        case "--config":
                            {
                                Directory.CreateDirectory(configFolder);

                                var serverIp = args[++i];
                                var serverPort = args[++i];
                                var subnet = args[++i];

                                int clients = int.Parse(args[++i]);
                                if (clients > 254)
                                    throw new Exception("No more than 254 clients");

                                Console.WriteLine("Generating configs...");
                                var serverKeys = GenerateKeys();
                                var clientKeys = Enumerable.Range(0, clients).Select(x => GenerateKeys()).ToArray();

                                for (int j = 0; j < clientKeys.Length; j++)
                                {
                                    var configName = $"client{j + 1:D3}";
                                    var configData = GetClientConfig(clientKeys[j], serverKeys.PublicKey, serverIp, serverPort, subnet, j + 2);

                                    var configPath = Path.Combine(configFolder, $"{configName}.conf");
                                    File.WriteAllText(configPath, configData, utf8);

                                    var configQRPath = Path.Combine(configFolder, $"{configName}.png");
                                    Utils.GenerateQRCode(configData, configQRPath);
                                }

                                var serverConfigPath = Path.Combine(configFolder, "server.conf");
                                var serverConfigData = GetServerConfig(serverKeys.PrivateKey, clientKeys, subnet, serverPort);
                                File.WriteAllText(serverConfigPath, serverConfigData, utf8);

                                Console.WriteLine("Done");
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
