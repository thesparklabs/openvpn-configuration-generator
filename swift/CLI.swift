// Copyright SparkLabs Pty Ltd 2018

import Foundation
import SparkLabsCore

class CLI {
    class func printUsage() {
        let exename = URL(fileURLWithPath: CommandLine.arguments[0] as String).deletingPathExtension().lastPathComponent
        print("Usage: \(exename) init")
        print("Initialise configuration, creates server configuration")
        print("Optional:")
        print("  --path DIR      Directory configurations are stored (Current Directory default)")
        print("  --keysize size  Change Keysize (2048 default)")
        print("  --days days     Days certificates are valid (3650 default)")
        print("")
        print("Usage: \(exename) client")
        print("Creates client configurations")
        print("Optional:")
        print("  --path DIR      Directory configurations are stored (Current Directory default)")
        print("  --name NAME     Prefill Common Name")
        print("")
        print("Usage: \(exename) revoke")
        print("Revoke a client and create/update the CRL")
        print("Optional:")
        print("  --path DIR      Directory configurations are stored (Current Directory default)")
        print("  --name NAME     Prefill Common Name")
        print("")
        print("Usage: \(exename) --help")
        print("Displays this information")
        print("")
        print("Usage: \(exename) --about")
        print("Displays information about this tool")
    }
    class func printAbout() {
        let exename = URL(fileURLWithPath: CommandLine.arguments[0] as String).deletingPathExtension().lastPathComponent
        print("\(exename) Tool")
        print("Using \(Utilities.OpenSSLVersion())")
        print()
	    print("Copyright SparkLabs Pty Ltd 2019");
	    print("Licensed under Creative Commons Attribution-NoDerivatives 4.0 International (CC BY-ND 4.0)");
	    print("Portions of the code included in or with this tool may container, or may be derived from, third-party code, including without limitation, open source software. All use of third-party software is subject to and governed by the respective licenses for the third-party software. These licenses are available at https://github.com/thesparklabs/openvpn-configuration-generator/blob/master/LICENSE");
    }
    func getOption(_ option: String) -> (option: OptionType, value: String) {
        return (OptionType(rawValue: option) ?? .unknown, option)
    }
    func getMode(_ option: String) -> Mode {
        return Mode(rawValue: option) ?? Mode.unknown
    }
}

enum OptionType: String {
    case commonName = "--name"
    case path = "--path"
    case keysize = "--keysize"
    case validdays = "--days"
    case unknown
}
enum Mode: String {
    case CreateClient = "client"
    case InitSetup = "init"
    case Revoke = "revoke"
    case Help = "--help"
    case About = "--about"
    case unknown
}