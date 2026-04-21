// Copyright SparkLabs Pty Ltd 2026

import Foundation
import SparkLabsCore

var argc = Int(CommandLine.argc)

if argc < 2 {
    CLI.printUsage()
    exit(1)
}

let cli = CLI()
let modestr = CommandLine.arguments[1]
let mode = cli.getMode(modestr)
if (mode == .unknown) {
    print("Unknown Mode")
    CLI.printUsage()
    exit(1)
}
if mode == .ShowCurves {
    CLI.showCurves()
    exit(0)
}
if mode == .Help {
    CLI.printUsage()
    exit(0)
}
if mode == .About {
    CLI.printAbout()
    exit(0)
}
if mode == .Version {
    CLI.printVersion()
    exit(0)
}

// Parse args
var op = 2
var options:[OptionType:String] = [:]
while op < argc {
    let (option, str) = cli.getOption(CommandLine.arguments[op])
    op += 1
    if (op < argc) {
        options[option] = CommandLine.arguments[op]
        op += 1
    } else {
        // Option missing its value
        print("Option \(str) missing argument. Exiting.")
        CLI.printUsage()
        exit(1)
    }
}

// Check valid path
let path: URL
if let pp = options[.path] {
    path = URL(fileURLWithPath: pp, isDirectory: true)
} else {
    // Get CWD
    path = URL(fileURLWithPath: FileManager.default.currentDirectoryPath, isDirectory: true)
}

// Determine the path exists and is a dir
if !path.isDirectoryAndExists {
    print("Path \(path.path) not found.")
    exit(1)
}

if mode == .InitSetup {
    let interactive = Interactive(path: path)
    if let kSize = options[.keysize] {
        if let int = Int(kSize) {
            interactive.keySize = int
            print("Using Key Size \(int)")
        } else {
            print("\(OptionType.keysize) does not have a valid value.")
            exit(1)
        }
    }
    if let vDays = options[.validdays] {
        if let int = Int(vDays) {
            interactive.validDays = int
            print("Certs will be valid for \(int) days")
        } else {
            print("\(OptionType.validdays) does not have a valid value.")
            exit(1)
        }
    }
    if let sAlg = options[.algorithm] {
        if let alg = CLI.getAlgorithm(sAlg) {
            interactive.keyAlg = alg
        } else {
            print("'\(sAlg)' is not a valid \(OptionType.algorithm)")
            exit(1)
        }
    }
    if let curve = options[.curve] {
        interactive.curveName = curve
    } else if interactive.keyAlg == .eddsa {
        interactive.curveName = "ED25519"
    }
    if let suffix = options[.suffix] {
        interactive.suffix = suffix
    }
    if let serverSAN = options[.serverSAN] {
        if !interactive.setServerSANsFromOption(serverSAN) {
            exit(1)
        }
    }

    if !interactive.generateNewConfig() {
        exit(1)
    }
    print("")
    print("Generating new server configuration...")
    guard interactive.createNewIssuer() else {
        exit(1)
    }
    if interactive.keyAlg == .rsa {
        guard interactive.createDH() else {
            exit(1)
        }
    }
    guard interactive.createServerConfig() else {
        exit(1)
    }
    guard interactive.saveConfig() else {
        exit(1)
    }
    print("Successfully initialised config.")
    exit(0)
} else if mode == .CreateClient {
    let interactive = Interactive(path: path)
    guard interactive.loadConfig() else {
        exit(1)
    }
    guard interactive.createNewClientConfig(name: options[.commonName]) else {
        exit(1)
    }
    guard interactive.saveConfig() else {
        exit(1)
    }
    print("Successfully created new client")
    exit(0)
} else if mode == .Revoke {
    let interactive = Interactive(path: path)
    guard interactive.loadConfig() else {
        exit(1)
    }
    guard interactive.revokeCert(name: options[.commonName]) else {
        exit(1)
    }
    exit(0)

} else {
    print("Unknown Mode")
    CLI.printUsage()
    exit(1)
}
