# Ovpngen: OpenVPN Configuration Generator

Ovpngen is an OpenVPN Configuration Generator command line tool, designed to make generating secure server and client configurations for OpenVPN servers and [Viscosity](https://www.sparklabs.com/viscosity/) super simple and fast. It handles the automatic generation and management of configuration files, certificates, and keys, without the need for complex commands or manual editing. macOS, Windows, and Linux are all supported.

<p align="center">
	<img src="demo.gif" alt="Demo" width="50%">
</p>

Developed by [SparkLabs](https://www.sparklabs.com)

## Download & Installation

### macOS
Download the macOS installer for the [latest release](https://github.com/thesparklabs/openvpn-configuration-generator/releases/latest), run it, and follow the prompts. Both Intel and Apple Silicon Macs are natively supported.

### Windows
Download the Windows installer for the [latest release](https://github.com/thesparklabs/openvpn-configuration-generator/releases/latest), run it, and follow the prompts. Both x64 and ARM64 machines are natively supported.

### Linux

**Debian/Ubuntu**: Download the .deb package for the [latest release](https://github.com/thesparklabs/openvpn-configuration-generator/releases/latest) for your machine's architecture (x86_64/arm64). If using a GUI, simply double click the .deb file to start the installer. If using the command line use a command like `sudo dpkg -i ovpngen-2.0-linux-x86_64.deb`.

**RedHat/Fedora**: Download the .rpm package for the [latest release](https://github.com/thesparklabs/openvpn-configuration-generator/releases/latest) for your machine's architecture (x86_64/arm64). If using a GUI, simply double click the .rpm file to start the installer. If using the command line use a command like `sudo dnf install ./ovpngen-2.0-linux-x86_64.rpm`.

**Other**: Download the portable Linux generic binary archive file for the [latest release](https://github.com/thesparklabs/openvpn-configuration-generator/releases/latest) for your machine's architecture (x86_64/arm64) and decompress it. You can then run it directly using `./ovpngen`. Virtually all Linux distributions are supported (including those above). 

## Documentation & Tutorials

Documentation and tutorials for using Ovpngen [can be found here](https://www.sparklabs.com/support/kb/article/creating-certificates-and-keys-for-your-openvpn-server/).

OpenVPN server setup guides for most popular OS distributions, routers, and devices [can be found here](https://www.sparklabs.com/support/kb/category/vpn-server-setup-guides/).

## Usage
To get started, create a new directory, cd into it and run the following then follow the prompts:

`ovpngen init`

To create a client, cd into the directory where you ran init, run the following and follow the prompts:

`ovpngen client`

```
Usage: ovpngen init
Initialise configuration, creates server configuration
Optional:
  --path DIR      Directory configurations are stored (Current Directory default)
  --keysize size  RSA key size (2048 default when using RSA)
  --days days     Days certificates are valid (3650 default)
  --algorithm (rsa|ecdsa|eddsa) Algorithm to use (ECDSA default)
                                ECDSA defaults to secp384r1. EdDSA defaults to Ed25519
  --curve curve_name            ECDSA/EdDSA curve to use
  --server-san san_list         Server certificate SAN entries (comma separated, e.g. DNS:vpn.example.com,IP:1.2.3.4)
                                Leave blank to force no SAN. If omitted, SAN is auto-derived from server address.
  --suffix suffix  Appends suffix to server file names. Simplifies running multiple servers slightly.

Usage: ovpngen client
Creates client configurations
Optional:
  --path DIR      Directory configurations are stored (Current Directory default)
  --name NAME     Prefill Common Name

Usage: ovpngen revoke
Revoke a client and create/update the CRL
Optional:
  --path DIR      Directory configurations are stored (Current Directory default)
  --name NAME     Prefill Common Name

Usage: ovpngen --show-curves
Show available ECDSA/EdDSA curves

Usage: ovpngen --help
Displays this information

Usage: ovpngen --about
Displays information about this tool

Usage: ovpngen --version
Displays this tool's version
```
