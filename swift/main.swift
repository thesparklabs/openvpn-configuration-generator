// Copyright SparkLabs Pty Ltd 2018

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
if mode == .Help {
    CLI.printUsage()
    exit(0)
}
if mode == .About {
    CLI.printAbout()
    exit(0)
}

//Parse args
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

//Check valid path
let path:String
if let pp = options[.path] {
    path = pp
} else {
    //Get CWD
    path = FileManager.default.currentDirectoryPath
}

//Determine the path exists and is a dir
if !Utilities.dirExists(path) {
    print("Path \(path) not found.")
    exit(1)
}

//Init OpenSSL
Utilities.initOpenSSL()

if mode == .InitSetup {
    let interactive = Interactive(path:path)
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
    if !interactive.generateNewConfig() {
        exit(1)
    }
    print("")
    print("Generating new server configuration...")
    guard interactive.createNewIssuer() else {
        exit(1)
    }
    guard interactive.createDH() else {
        exit(1)
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
    let interactive = Interactive(path:path)
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
    let interactive = Interactive(path:path)
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