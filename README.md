# OpenVPN Configuration Generator

Developed by [SparkLabs](https://www.sparklabs.com)

Further documentation and tutorials [can be found here](https://www.sparklabs.com/support/kb/article/creating-certificates-and-keys-for-your-openvpn-server/).

## Overview
The OpenVPN Configuration Generator is designed to make generating server and 
client configurations for an OpenVPN server and Viscosity easier.

## Download
Releases for macOS, Windows, and Linux can be [downloaded here](https://github.com/thesparklabs/openvpn-configuration-generator/releases/latest).

## Usage
To get started, create a new directory, cd into it and run the following then follow the prompts:

`openvpn-generate init`

To create a client, cd into the directory where you ran init, run the following and follow the prompts:

`openvpn-generate client`

```
Usage: openvpn-generate init
Initialise configuration, creates server configuration
Optional:
  --path DIR      Directory configurations are stored (Current Directory default)
  --keysize size  Change Keysize (2048 default)
  --days days     Days certificates are valid (3650 default)
  --algorithm (rsa|ecdsa|eddsa) Algorithm to use (RSA default)
                                ECDSA defaults to secp384r1. EDDSA defaults to ED25519
  --curve curve_name            ECDSA/EDDSA curve to use
  --curve suffix  Appends suffix to server file names. Simplifies running multiple servers slightly.

Usage: openvpn-generate client
Creates client configurations
Optional:
  --path DIR      Directory configurations are stored (Current Directory default)
  --name NAME     Prefill Common Name

Usage: openvpn-generate revoke
Revoke a client and create/update the CRL
Optional:
  --path DIR      Directory configurations are stored (Current Directory default)
  --name NAME     Prefill Common Name

Usage: openvpn-generate --show-curves
Show available ECDSA curves

Usage: openvpn-generate --help
Displays this information

Usage: openvpn-generate --about
Displays information about this tool
```

## Installation

### macOS
Extract the tar.gz archive and run

### Ubuntu
`sudo dpkg -i openvpn-configuration-generator_1.0-1.deb`

### Windows
Download and run the MSI installer. The install location is added to the system path by default for easy use and installs all prerequisites automatically.
