# wgconfig
Generation wireguard config files for multiple clients. Features:

- Cross-platform .NET 5.0 binary
- Zero dependencies (no external libs, wireguard is not required)
- Optional QR code generation for each client

## Usage
dotnet wgconfig.dll --config <server_ip> <server_port> <subnet> <clients_count>

## Example
This will generate ready-to-use config files for server and 200 clients (including QR code for each client):

**dotnet wgconfig.dll --qrcode --config 195.201.201.32 51820 10.8.0.0 200**

## Help wanted
Need fast and tiny replacement for QR coder. Currently based on https://github.com/codebude/QRCoder, which is too slow.
