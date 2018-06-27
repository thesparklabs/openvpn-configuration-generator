# OpenVPN Configuration Generator
### Developed by SparkLabs Pty Ltd (https://www.sparklabs.com)
### [Download Here](https://github.com/thesparklabs/openvpn-configuration-generator/releases/latest)


## Overview
The OpenVPN Configuration Generator is designed to make generating server and 
client configurations for an OpenVPN server easier.

## Usage
To get started, create a new directory, cd into it and run the following then follow the prompts:

`openvpn-generate init`

To create a client, cd into the directory where you ran init, run the following and follow the prompts:

`openvpn-generate client`

```
Usage: openvpn-generate init
Optional:
  --path DIR      Directory configurations are stored (Current Directory default)
  --keysize size  Change Keysize (2048 default)
  --days days     Days certificates are valid (3650 default)

Usage: openvpn-generate client
Optional:
  --path DIR      Directory configurations are stored (Current Directory default)
  --name NAME     Prefill Common Name
```

## Installation

### macOS
Extract the tar.gz archive and run

### Ubuntu
`sudo dpkg -i openvpn-configuration-generator_1.0-1.deb`

### Windows
Download and run the MSI installer. The install location is added to the system path by default for easy use and installs all prerequisites automatically.