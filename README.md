# wgconfig
Generation wireguard config files for multiple clients (with QR images). Cross-platform .NET 5.0 binary without dependencies (wireguard is not required).

## Usage
dotnet wgconfig.dll --config <server_ip> <server_port> <subnet> <clients_count>

## Example
This will generate ready-to-use config files for server and 200 clients (including QR code for each client):

**dotnet wgconfig.dll --config 195.201.201.32 51820 10.8.0.0 200**

