![Build](https://github.com/depler/wgconfig/actions/workflows/dotnet.yml/badge.svg)

# wgconfig
Program for generation wireguard config with multiple clients. Cross-platform binary (tested on Windows and Linux), dotnet 5.0 and wg binary required. 

## Usage
dotnet wgconfig.dll --config <server_ip> <server_port> <clients_count>

## Example
This will generate ready-to-use config files for server and 200 clients:

**dotnet wgconfig.dll --config 195.201.201.32 51820 200**
