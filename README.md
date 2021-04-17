![Build](https://github.com/depler/wgconfig/actions/workflows/build.yml/badge.svg)

# wgconfig
Generation wireguard config files for multiple clients (with QR images). Cross-platform binary (tested on Windows and Linux), dotnet 5.0 and wg binary required.

## Usage
dotnet wgconfig.dll --config <server_ip> <server_port> <subnet> <clients_count>

## Example
This will generate ready-to-use config files for server and 200 clients (including QR code for each client):

**dotnet wgconfig.dll --config 195.201.201.32 51820 10.8.0.0 200**
