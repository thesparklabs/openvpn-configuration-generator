// Copyright SparkLabs Pty Ltd 2026

import Foundation
import SparkLabsCrypto

class CLI {
    class func printUsage() {
        let exename = URL(fileURLWithPath: CommandLine.arguments[0] as String).deletingPathExtension().lastPathComponent
        let usage = """
        Usage: \(exename) init
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

        Usage: \(exename) client
        Creates client configurations
        Optional:
          --path DIR      Directory configurations are stored (Current Directory default)
          --name NAME     Prefill Common Name

        Usage: \(exename) revoke
        Revoke a client and create/update the CRL
        Optional:
          --path DIR      Directory configurations are stored (Current Directory default)
          --name NAME     Prefill Common Name

        Usage: \(exename) --show-curves
        Show available ECDSA/EdDSA curves

        Usage: \(exename) --help
        Displays this information

        Usage: \(exename) --about
        Displays information about this tool

        Usage: \(exename) --version
        Displays this tool's version
        """
        print(usage)
    }
    class func aboutText(exename: String) -> String {
        return """
        \(exename) Tool
        Version \(VersionInfo.displayVersion)
        Using \(OpenSSL.version)

        Copyright SparkLabs Pty Ltd 2026
        Licensed under Creative Commons Attribution-NoDerivatives 4.0 International (CC BY-ND 4.0)
        Portions of the code included in or with this tool may contain, or may be derived from, third-party code, including without limitation, open source software. All use of third-party software is subject to and governed by the respective licenses for the third-party software. These licenses are available at https://github.com/thesparklabs/openvpn-configuration-generator/blob/master/LICENSE
        """
    }
    class func printAbout() {
        let exename = URL(fileURLWithPath: CommandLine.arguments[0] as String).deletingPathExtension().lastPathComponent
        print(aboutText(exename: exename))
    }
    class func printVersion() {
        print(VersionInfo.shortVersion)
    }
    class func showCurves() {
        let edCurves = Key.supportedCurves().filter {
            switch $0 {
            case .ed25519, .ed448:
                return true
            default:
                return false
            }
        }
        print("EdDSA Curves:")
        for ed in edCurves {
            print("\t" + ed.rawValue.uppercased())
        }
        print()

        let ecCurves = Key.supportedOpenSSLECCurveNames()

        print("ECDSA Curves:")
        for ec in ecCurves {
            print("\t" + ec)
        }
        print("NOTE: Not all curves may be supported.")
        print("Check 'openvpn --show-curves' on your server and ensure you are using the latest verison of Viscosity.")
    }
    func getOption(_ option: String) -> (option: OptionType, value: String) {
        return (OptionType(rawValue: option) ?? .unknown, option)
    }
    func getMode(_ option: String) -> Mode {
        return Mode(rawValue: option) ?? Mode.unknown
    }
    static func getAlgorithm(_ option:String) -> CertificateAlgorithm? {
        switch option {
            case "rsa":
                return .rsa
            case "ecdsa":
                return .ecdsa
            case "eddsa":
                return .eddsa
            default:
                return nil
        }
    }
}

enum CertificateAlgorithm: String {
    case rsa
    case ecdsa
    case eddsa
}

enum OptionType: String {
    case commonName = "--name"
    case path = "--path"
    case keysize = "--keysize"
    case validdays = "--days"
    case algorithm = "--algorithm"
    case curve = "--curve"
    case serverSAN = "--server-san"
    case suffix = "--suffix"
    case unknown
}
enum Mode: String {
    case CreateClient = "client"
    case InitSetup = "init"
    case Revoke = "revoke"
    case ShowCurves = "--show-curves"
    case Help = "--help"
    case About = "--about"
    case Version = "--version"
    case unknown
}
