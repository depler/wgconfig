using System;
using System.IO;
using System.Text;

namespace Wireguard.Code;

class Program
{
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
        sb.AppendLine("DNS = 1.1.1.1,1.0.0.1");
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
        sb.AppendLine("PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o ens3 -j MASQUERADE");
        sb.AppendLine("PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o ens3 -j MASQUERADE");

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

    static void Main(string[] args)
    {
        try
        {
            bool needQrCode = false;
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
                    case "--qrcode":
                        {
                            needQrCode = true;
                            Console.WriteLine("Generating QR codes enabled");
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
                            var serverKeys = KeyData.Generate();
                            var clientKeys = KeyData.Generate(clients);

                            for (int j = 0; j < clientKeys.Length; j++)
                            {
                                var configName = $"client{j + 1:D3}";
                                var configData = GetClientConfig(clientKeys[j], serverKeys.PublicKey, serverIp, serverPort, subnet, j + 2);

                                var configPath = Path.Combine(configFolder, $"{configName}.conf");
                                File.WriteAllText(configPath, configData, utf8);

                                if (needQrCode)
                                {
                                    var configQRPath = Path.Combine(configFolder, $"{configName}.png");
                                    Utils.GenerateQrCode(configData, configQRPath);
                                }
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
