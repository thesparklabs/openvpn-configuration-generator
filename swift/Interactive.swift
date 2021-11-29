// Copyright SparkLabs Pty Ltd 2018

import Foundation
import SparkLabsCore

import SWCompression

class Interactive {
    var defaultCountry = "AU"
    var defaultState = "NSW"
    var defaultLocale = "Sydney"
    var defaultON = "My Company"
    var defaultOU = "Networks"
    var defaultCN = "My OpenVPN Server"
    var defaultEmail = "me@host.domain"

    var defaultProtocol = "UDP"
    var defaultPort = "1194"

    var cloudflareDNS = ["1.1.1.1", "1.0.0.1"]
    var googleDNS = ["8.8.8.8", "8.8.4.4"]
    var openDNS = ["208.67.222.222", "208.67.220.220"]
    var localDNS = "10.8.0.1"

    let path:URL
    let configPath:URL
    let pkiPath:URL
    let caPath:URL
    let keyPath:URL
    let crlPath:URL
    let clientsPath:URL
    let tlscryptv2Path:URL

    var keySize:Int
    var validDays:Int
    var _serial:Int = 0
    var Serial:Int {
        get {
            let ss = _serial + 1
            _serial = ss
            return ss
        }
    }
    var keyAlg:Key.KeyType
    var curveName:String
    var suffix:String

    var tlscryptv2: Bool

    let protectedCNs = ["server", "ca"]

    var cSubject:CertificateSubject? = nil
    var config:[String:Any] = [:]
    fileprivate var Issuer:Identity? = nil
    
    let defaultCurves = ["secp256r1", "secp521r1", "secp384r1"]

    init(path:String, keySize:Int = 2048, validDays:Int = 3650) {
        self.path = URL(fileURLWithPath: path)
        self.configPath = self.path.appendingPathComponent("config.conf")
        self.pkiPath = self.path.appendingPathComponent("pki")
        self.caPath = self.pkiPath.appendingPathComponent("ca.crt")
        self.keyPath = self.pkiPath.appendingPathComponent("ca.key")
        self.crlPath = self.pkiPath.appendingPathComponent("crl.crt")
        self.clientsPath = self.path.appendingPathComponent("clients")
        self.tlscryptv2Path = self.pkiPath.appendingPathComponent("server-tc2.key")
        self.keySize = keySize
        self.validDays = validDays
        self.keyAlg = .RSA
        self.curveName = "secp384r1"
        self.suffix = ""
        self.tlscryptv2 = false
    }
    fileprivate func askQuestion(_ question:String, allowedBlank:Bool = true) -> String? {
        while true {
            print(question, terminator: " ")
            if let input = readLine() {
                if input.isEmpty {
                    return nil
                }
                if input == "." && !allowedBlank {
                    print("This field cannot be left blank.")
                }
                return input;
            } else {
                return nil;
            }
        }
    }
    func loadConfig() -> Bool {
        if !FileManager.default.fileExists(atPath: configPath.path) {
            return false;
        }
        let dict:[String:Any]
        do {
            let json = try String(contentsOf: configPath, encoding: .utf8)
            if let temp = json.toJSON() as? [String:Any] {
                dict = temp
            } else {
                print("ERROR: Failed to load config")
                return false;
            }
        } catch {
            print("ERROR: Failed to load config at \(configPath.path). \(error)")
            return false
        }

        //Pull the subject
        guard let cc = CertificateSubject(fromDict: dict) else {
            print("ERROR: Failed to load subject from config")
            return false
        }
        self.cSubject = cc
        self.config = dict

        //Load in "fixed" defaults
        if let ks = self.config["keysize"] as? Int {
            self.keySize = ks
        }
        if let vd = self.config["validdays"] as? Int {
            self.validDays = vd
        }
        if let ser = self.config["serial"] as? Int {
            self._serial = ser
        }
        if let sAlg = self.config["algorithm"] as? String, let alg = CLI.getAlgorithm(sAlg) {
            self.keyAlg = alg
        }
        if let curveName = self.config["eccurve"] as? String {
            self.curveName = curveName
        }
        if let suffix = self.config["suffix"] as? String {
            self.suffix = suffix
        }
        if let useTC = self.config["tlscryptv2"] as? Bool {
            self.tlscryptv2 = useTC
        }
        
        //Find and load CA/Key
        guard let cert = Certificate(withFileURL: caPath), let key = Key(withFilePath: keyPath.path) else {
            print("ERROR: Failed to load issuing identity.")
            return false
        }
        self.Issuer = Identity(withCertificate: cert, andKey: key, isIssuer: true)

        return true
    }
    func saveConfig() -> Bool {
        //Update the serial
        self.config["serial"] = self._serial
        guard let data = try? JSONSerialization.data(withJSONObject: self.config, options: []),
        let json = String(data: data, encoding: .utf8) else {
            print("ERROR: Failed to construct config")
            return false
        }
        //Save to file
        do {
        #if os(Windows)
            try json.write(to: self.configPath, atomically: false, encoding: .utf8)
        #else
            try json.write(to: self.configPath, atomically: true, encoding: .utf8)
        #endif
        } catch {
            print("ERROR: Failed to write config to \(configPath.path). \(error)")
            return false
        }
        return true;
    }
    fileprivate func saveIdentity(_ identity:Identity, name:String) -> Bool {
        //Create dir if not exists
        do {
            if !FileManager.default.fileExists(atPath: self.pkiPath.path) {
                try FileManager.default.createDirectory(atPath: self.pkiPath.path, withIntermediateDirectories: false, attributes: nil)
            }
        } catch {
            print("ERROR: Failed to create PKI dir. \(error)")
            return false
        }
        //Save to disk
        let certpath = self.pkiPath.appendingPathComponent(name + ".crt")
        let keypath = self.pkiPath.appendingPathComponent(name + ".key")
        let cert = identity.Certificate.certificateAsPEM
        do {
        #if os(Windows)
            try cert.write(to: certpath, atomically:false, encoding: .utf8)
        #else
            try cert.write(to: certpath, atomically:true, encoding: .utf8)
        #endif
        } catch {
            print("ERROR: Failed to save Certificate to \(certpath). \(error)")
        }
        guard let key = identity.Key.KeyAsPEM else {
            print("ERROR: Failed to create CA Key")
            return false
        }
        do {
        #if os(Windows)
            try key.write(to: keypath, atomically:false, encoding: .utf8)
        #else
            try key.write(to: keypath, atomically:true, encoding: .utf8)
        #endif
        } catch {
            print("ERROR: Failed to save Key to \(keypath). \(error)")
            return false
        }
        //Le-done
        return true
    }

    func createNewIssuer() -> Bool {
        guard let subject = cSubject else {
            print("ERROR: No Subject available.")
            return false;
        }
        guard let identity = Identity.createCAAndKey(subject: subject, keyType:self.keyAlg, bitLength: keySize, curve:self.curveName, daysValid: self.validDays, serial: self.Serial) else {
            print("ERROR: Failed to create CA")
            return false
        }
        self.Issuer = identity
        //Save to disk
        guard saveIdentity(identity, name: "ca") else {
            return false
        }
        // The TC2 key effectively acts as an issuer, so generate it with the issuer
        return createNewTC2ServerKey()
    }
    func createNewTC2ServerKey() -> Bool {
        do {
            guard let serverkey = try Key.CreateTlsCryptV2ServerKey() else {
                print("ERROR: Failed to generate tls-crypt-v2 server key")
                return false
            }
        #if os(Windows)
            try serverkey.write(to: self.tlscryptv2Path, atomically:false, encoding: .utf8)
        #else
            try serverkey.write(to: self.tlscryptv2Path, atomically:true, encoding: .utf8)
        #endif
        } catch {
            print("ERROR: Failed to save tls-crypt-v2 server key to \(self.tlscryptv2Path.path). \(error)")
            return false
        }
        return true
    }
    func createDH() -> Bool {
        print("Creating DH Params. This will take a while...")
        let genCallback:GeneratorCallback = { p, n, cb -> Int32 in
			switch p {
			case 0:
				print(".", terminator: "")
			case 1:
				print("+", terminator: "")
			case 2:
				print("*", terminator: "")
			case 3:
				print("")
			default:
				break
			}
			fflush(stdout) //Force a flush
			return 1
        }
        guard let dhPem = Utilities.createDH(keySize: keySize, gencb: genCallback) else {
            print("ERROR: Failed to generate DH Params.")
            return false
        }
        //Save to disk
        let dhPath = self.pkiPath.appendingPathComponent("dh.pem")
        do {
        #if os(Windows)
            try dhPem.write(to: dhPath, atomically: false, encoding: .utf8)
        #else
            try dhPem.write(to: dhPath, atomically: true, encoding: .utf8)
        #endif
        } catch {
            print("ERROR: Failed to save DH Params to \(dhPath.path). \(error)")
            return false
        }
        return true
    }
    func createNewServerIdentity() -> Bool {
        print("Creating Server Identity...")
        guard let issuer = self.Issuer else {
            print("ERROR: No issuer available")
            return false
        }
        guard var subject = cSubject else {
            print("ERROR: No subject available.")
            return false
        }
        //Update the CN
        subject.CommonName = "server"
        //Create ID
        guard let identity = issuer.createNewServerBundle(subject: subject, keyType:self.keyAlg, bitLength: keySize, curve:self.curveName, daysValid: self.validDays, serial: self.Serial) else {
            print("ERROR: Failed to create server identity")
            return false
        }
        return saveIdentity(identity, name:"server")
    }
    func createServerConfig() -> Bool {
        let caName = "ca\(self.suffix).crt"
        let crlName = "crl\(self.suffix).crt"
        let certName = "server\(self.suffix).crt"
        let keyName = "server\(self.suffix).key"
        let dhName = "dh\(self.suffix).pem"
        let tc2Name = "server-tc2\(self.suffix).key"
        let certpath = self.pkiPath.appendingPathComponent("server.crt")
        let keypath = self.pkiPath.appendingPathComponent("server.key")
        let dhPath = self.pkiPath.appendingPathComponent("dh.pem")
        guard FileManager.default.fileExists(atPath: self.caPath.path) else {
            print("ERROR: Missing CA. Please regenerate config")
            return false
        }
        if self.keyAlg == .RSA {
            guard FileManager.default.fileExists(atPath: dhPath.path) else {
                print("ERROR: Missing DH. Please regenerate config")
                return false
            }
        }
        guard let _ = config["server"] as? String,
            let port = config["port"] as? String,
            var proto = config["proto"] as? String
        else {
            print("ERROR: Invalid config. Please regenerate config")
            return false;
        }
        if proto == "tcp" || proto == "tcp-client" { // tcp-client for legacy support
            proto = "tcp-server"
        } else {
            proto = "udp"
        }
        //Generate Identity
        guard createNewServerIdentity() else {
            return false
        }
        guard FileManager.default.fileExists(atPath: certpath.path) else {
            print("ERROR: Missing Cert. Please regenerate config")
            return false
        }
        guard FileManager.default.fileExists(atPath: keypath.path) else {
            print("ERROR: Missing Key. Please regenerate config")
            return false
        }
        //Form the config
        var file = "#-- Config Auto Generated by SparkLabs OpenVPN Configuration Generator --#\n"
        file +=    "#--                   Config for OpenVPN 2.5 Server                    --#\n\n"
        file += "proto \(proto)\n"
        file += "ifconfig-pool-persist ipp\(self.suffix).txt\n"
        file += "keepalive 10 120\n"
        file += "user nobody\ngroup nogroup\n"
        file += "persist-key\npersist-tun\n"
        file += "status openvpn-status\(self.suffix).log\n"
        file += "verb 3\n"
        file += "mute 10\n"
        file += "ca \"\(caName)\"\ncert \"\(certName)\"\nkey \"\(keyName)\"\n"
        if FileManager.default.fileExists(atPath: self.crlPath.path) {
            file += "crl-verify \"\(crlName)\"\n"
        }
        if self.tlscryptv2 {
            file += "tls-crypt-v2 \"\(tc2Name)\"\n"
        }
        if self.keyAlg == .RSA {
            file += "dh \(dhName)\n"
        } else if self.keyAlg == .EdDSA {
            file += "dh none\n";
            if !["ED25519", "ED448"].contains(self.curveName) {
                file += "tls-groups \(self.curveName):X25519:X448\n"
            } else {
                if self.curveName == "ED25519" {
                    file += "tls-groups X25519:X448\n"
                } else {
                    file += "tls-groups X448:X25519\n"
                }
            }
        } else { // ECDSA
            file += "dh none\n";
            if !defaultCurves.contains(self.curveName) {
                file += "tls-groups \(self.curveName):secp256r1:secp521r1:secp384r1\n"
            } else {
                file += "tls-groups \(curveName)"
                for curve in defaultCurves {
                    if curve != self.curveName {
                        file += ":\(curve)"
                    }
                }
                file += "\n"
            }
        }
        file += "tls-version-min 1.2\n"
        file += "data-ciphers AES-256-GCM:AES-256-CBC\n"
        file += "cipher AES-256-GCM\n"
        file += "auth SHA256\n"
        file += "remote-cert-tls client\n"
        file += "port \(port)\n"
        file += "dev tun0\n"
        file += "topology subnet\n"
        file += "server 10.8.0.0 255.255.255.0\n"
        if let dns = config["dns"] as? [String] {
            for ss in dns { //TODO - validate ipv4/ipv6 for DNS6?
                file += "push \"dhcp-option DNS \(ss)\"\n"
            }
        }
        if let redirect = config["redirect"] as? Bool, redirect {
            file += "push \"redirect-gateway def1\"\n"
        }
        //Optional values for a user to modify
        file += "#Uncomment the below to allow client to client communication\n#client-to-client\n"
        file += "#Uncomment the below and modify the command to allow access to your internal network\n#push \"route 192.168.0.0 255.255.255.0\"\n"

        //Make a new directory for the server
        let serverPath = self.path.appendingPathComponent("server")
        do {
            if FileManager.default.fileExists(atPath: serverPath.path) {
                try FileManager.default.removeItem(at: serverPath)
            }
            try FileManager.default.createDirectory(atPath: serverPath.path, withIntermediateDirectories: false, attributes: nil)
        } catch {
            print("ERROR: Failed to make directory for server configuration. \(error)")
            return false
        }
        //Write server config
        do {
        #if os(Windows)
            try file.write(to: serverPath.appendingPathComponent("server\(self.suffix).conf"), atomically:false, encoding: .utf8)
        #else
            try file.write(to: serverPath.appendingPathComponent("server\(self.suffix).conf"), atomically:true, encoding: .utf8)
        #endif
        } catch {
            print("ERROR: Failed to write server config. \(error)")
            return false
        }
        //Copy files
        do {
			try FileManager.default.copyItem(at:self.caPath, to:serverPath.appendingPathComponent(caName))
        } catch {
            print("ERROR: Failed to copy CA. \(error)")
            return false
        }
        do {
			try FileManager.default.copyItem(at:certpath, to:serverPath.appendingPathComponent(certName))
        } catch {
            print("ERROR: Failed to copy Cert. \(error)")
            return false
        }
        do {
            if self.keyAlg == .RSA {
			    try FileManager.default.copyItem(at:dhPath, to:serverPath.appendingPathComponent(dhName))
            }
        } catch {
            print("ERROR: Failed to copy DH. \(error)")
            return false
        }
        do {
			try FileManager.default.copyItem(at:keypath, to:serverPath.appendingPathComponent(keyName))
        } catch {
            print("ERROR: Failed to copy key. \(error)")
            return false
        }
        do {
            if FileManager.default.fileExists(atPath: self.crlPath.path) {
			    try FileManager.default.copyItem(at:self.crlPath, to:serverPath.appendingPathComponent(crlName))
            }
        } catch {
            print("ERROR: Failed to copy CRL. \(error)")
            return false
        }
        do {
            if self.tlscryptv2 {
			    try FileManager.default.copyItem(at:self.tlscryptv2Path, to:serverPath.appendingPathComponent(tc2Name))
            }
        } catch {
            print("ERROR: Failed to copy tls-crypt-v2. \(error)")
            return false
        }
        print("Successfully generated server configuration at \(serverPath.path).")
        return true
    }
    func createNewClientIdentity(name:String) -> Bool {
        guard let issuer = self.Issuer else {
            print("ERROR: No issuer available")
            return false
        }
        guard var subject = cSubject else {
            print("ERROR: No subject available.")
            return false
        }
        subject.CommonName = name
        //Create ID
        guard let identity = issuer.createNewUserBundle(subject: subject, keyType:self.keyAlg, bitLength: keySize, curve:self.curveName, daysValid: self.validDays, serial: self.Serial) else {
            print("ERROR: Failed to create client identity")
            return false
        }
        guard saveIdentity(identity, name:name) else {
            print("ERROR: Failed to write new client PKI to disk")
            return false
        }
        if !self.tlscryptv2 {
            return true
        }
        func deleteID() {
            // Delete PKI for this user if we need to
            let certpath = self.pkiPath.appendingPathComponent(name + ".crt")
            let keypath = self.pkiPath.appendingPathComponent(name + ".key")
            do {
                try FileManager.default.removeItem(at: certpath)
            } catch {
                print("ERROR: Failed to remove revoked PKI data. \(error)")
            }
            do {
                try FileManager.default.removeItem(at: keypath)
            } catch {
                print("ERROR: Failed to remove revoked PKI data. \(error)")
            }
        }
        // Create client tlscrypt
        let servertc2: String
        do {
            servertc2 = try String(contentsOf: self.tlscryptv2Path) 
        } catch {
            print("ERROR: Failed to read tls-crypt-v2 server key from \(self.tlscryptv2Path.path). \(error)")
            deleteID()
            return false
        }
        let clienttc2Path = self.pkiPath.appendingPathComponent(name + "-tc2.key")
        do {
            // Create client key
            guard let clientKey = try Key.CreateTlsCryptV2ClientKey(serverKey: servertc2) else {
                print("ERROR: Failed to generate client tls-crypt-v2 key")
                deleteID()
                return false
            }
            // Write client key
            #if os(Windows)
                try clientKey.write(to: clienttc2Path, atomically:false, encoding: .utf8)
            #else
                try clientKey.write(to: clienttc2Path, atomically:true, encoding: .utf8)
            #endif
        } catch {
            print("ERROR: Failed to generate client tls-crypt-v2 key. \(error)")
            deleteID()
            return false
        }
        return true

    }
    func createNewClientConfig(name:String? = nil) -> Bool {
        //Confirm we have everything
        guard self.Issuer != nil else {
            print("ERROR: No issuer available")
            return false
        }
        guard cSubject != nil else {
            print("ERROR: No subject available.")
            return false
        }
        guard FileManager.default.fileExists(atPath: self.caPath.path) else {
            print("ERROR: Missing CA. Please regenerate config")
            return false
        }
        guard let address = config["server"] as? String,
            let port = config["port"] as? String,
            var proto = config["proto"] as? String
        else {
            print("ERROR: Invalid config. Please regenerate config")
            return false;
        }
        if proto == "tcp" || proto == "tcp-client" { // tcp-client for legacy support
            proto = "tcp-client"
        } else {
            proto = "udp"
        }
        //Try and make dir for all clients if not exists
        do {
            if !FileManager.default.fileExists(atPath: self.clientsPath.path) {
                try FileManager.default.createDirectory(atPath: self.clientsPath.path, withIntermediateDirectories: false, attributes: nil)
            }
        } catch {
            print("ERROR: Failed to make clients directory. \(error)")
            return false
        }

        let CN:String
        if let name = name {
            CN = name
        } else {
            if let input = askQuestion("Common Name. This should be unique, for example a username [client1]:", allowedBlank: false) {
                CN = input
            } else {
                CN = "client1";
            }
        }
        var clientPath = self.path.appendingPathComponent(CN)
        if FileManager.default.fileExists(atPath: clientPath.path) {
            var i = 0
            repeat {
                i += 1
                clientPath = self.path.appendingPathComponent("\(CN)_\(i)")
            } while FileManager.default.fileExists(atPath: clientPath.path)
        }
        do {
            try FileManager.default.createDirectory(atPath: clientPath.path, withIntermediateDirectories: false, attributes: nil)
        } catch {
            print("ERROR: Failed to make directory for client configuration. \(error)")
            return false
        }
        defer {
            //Remove the config folder
            if FileManager.default.fileExists(atPath: clientPath.path) {
                try? FileManager.default.removeItem(at: clientPath)
            }
        }
        if !createNewClientIdentity(name: CN) {
            return false
        }
        //Copy files
        let certName = "\(CN).crt"
        let certpath = self.pkiPath.appendingPathComponent(certName)
        let keyName = "\(CN).key"
        let keypath = self.pkiPath.appendingPathComponent(keyName)
        let tc2Name = "\(CN)-tc2.key"
        let tc2Path = self.pkiPath.appendingPathComponent(tc2Name)
        do {
			try FileManager.default.copyItem(at:self.caPath, to:clientPath.appendingPathComponent("ca.crt"))
        } catch {
            print("ERROR: Failed to copy CA. \(error)")
            return false
        }
        do {
			try FileManager.default.copyItem(at:certpath, to:clientPath.appendingPathComponent(certName))
        } catch {
            print("ERROR: Failed to copy Cert. \(error)")
            return false
        }
        do {
			try FileManager.default.copyItem(at:keypath, to:clientPath.appendingPathComponent(keyName))
        } catch {
            print("ERROR: Failed to copy Key. \(error)")
            return false
        }
        do {
            if self.tlscryptv2 {
			    try FileManager.default.copyItem(at:tc2Path, to:clientPath.appendingPathComponent(tc2Name))
            }
        } catch {
            print("ERROR: Failed to copy CA. \(error)")
            return false
        }

        //Create config
        var file = "#-- Config Auto Generated By SparkLabs OpenVPN Configuration Generator--#\n\n"
        file += "#viscosity name \(CN)@\(address)\n"
        file += "remote \(address) \(port) \(proto)\n"
        file += "dev tun\ntls-client\n"
        //Certs
        file += "ca \"ca.crt\"\n"
        file += "cert \"\(certName)\"\n"
        file += "key \"\(keyName)\"\n"
        if self.tlscryptv2 {
            file += "tls-crypt-v2 \"\(tc2Name)\"\n"
        }
        file += "tls-version-min 1.2\n"
        file += "data-ciphers AES-256-GCM:AES-256-CBC\n"
        file += "cipher AES-256-GCM\n"
        file += "auth SHA256\n"
        file += "remote-cert-tls server\n"
        file += "persist-tun\npersist-key\nnobind\npull\n"
        //Write config
        do {
        #if os(Windows)
            try file.write(to: clientPath.appendingPathComponent("config.conf"), atomically:false, encoding: .utf8)
        #else
            try file.write(to: clientPath.appendingPathComponent("config.conf"), atomically:true, encoding: .utf8)
        #endif
        } catch {
            print("ERROR: Failed to write server config. \(error)")
            return false
        }

        //Generate .visz
        let outPath = self.clientsPath.appendingPathComponent("\(CN).visz")
        do {
            try createVisz(at: clientPath, out: outPath)
        } catch {
            print("Failed to create client config. \(error)")
        }
        return true
    }

    func createVisz(at inputPath: URL, out outputPath: URL) throws {
        func createEntries(_ inputPath: String, _ verbose: Bool, basePath: String) throws -> [TarEntry] {
            let inputURL = URL(fileURLWithPath: inputPath)
            let fileManager = FileManager.default

            let fileAttributes = try fileManager.attributesOfItem(atPath: inputPath)

            // NOTE - This is a massive hack and probably isn't safe
            // TODO - Make this betterererer
            let itemloc = inputURL.relativePath
            var name = itemloc.replacingOccurrences(of: basePath, with: "")
            let slashset = CharacterSet(charactersIn: "/\\")
            name = name.trimmingCharacters(in: slashset)

            let entryType: ContainerEntryType
            if let typeFromAttributes = fileAttributes[.type] as? FileAttributeType {
                switch typeFromAttributes {
                case .typeBlockSpecial:
                    entryType = .blockSpecial
                case .typeCharacterSpecial:
                    entryType = .characterSpecial
                case .typeDirectory:
                    entryType = .directory
                case .typeRegular:
                    entryType = .regular
                case .typeSocket:
                    entryType = .socket
                case .typeSymbolicLink:
                    entryType = .symbolicLink
                case .typeUnknown:
                    entryType = .unknown
                default:
                    entryType = .unknown
                }
            } else {
                entryType = .unknown
            }

            var info = TarEntryInfo(name: name, type: entryType)
            info.creationTime = fileAttributes[.creationDate] as? Date
            info.groupID = (fileAttributes[.groupOwnerAccountID] as? NSNumber)?.intValue
            info.ownerGroupName = fileAttributes[.groupOwnerAccountName] as? String
            info.modificationTime = fileAttributes[.modificationDate] as? Date
            info.ownerID = (fileAttributes[.ownerAccountID] as? NSNumber)?.intValue
            info.ownerUserName = fileAttributes[.ownerAccountName] as? String
            if let posixPermissions = (fileAttributes[.posixPermissions] as? NSNumber)?.intValue {
                info.permissions = Permissions(rawValue: UInt32(truncatingIfNeeded: posixPermissions))
            }

            var entryData = Data()
            if entryType == .symbolicLink {
                info.linkName = try fileManager.destinationOfSymbolicLink(atPath: inputPath)
            } else if entryType != .directory {
                entryData = try Data(contentsOf: URL(fileURLWithPath: inputPath))
            }

            if verbose {
                var log = ""
                switch entryType {
                case .regular:
                    log += "f: "
                case .directory:
                    log += "d: "
                case .symbolicLink:
                    log += "l:"
                default:
                    log += "u: "
                }
                log += name
                if entryType == .symbolicLink {
                    log += " -> " + info.linkName
                }
                print(log)
            }

            let entry = TarEntry(info: info, data: entryData)

            var entries = [TarEntry]()
            entries.append(entry)

            if entryType == .directory {
                for subPath in try fileManager.contentsOfDirectory(atPath: inputPath) {
                    entries.append(contentsOf: try createEntries(inputURL.appendingPathComponent(subPath).relativePath,
                                                                    verbose, basePath: basePath))
                }
            }

            return entries
        }
        let base = inputPath.appendingPathComponent("..").relativePath.normalisePath()
        var fileName = outputPath.lastPathComponent
        if fileName.hasSuffix(".visz") {
            fileName.removeLast(5)
        } else {
            print("Invalid config name.")
            return
        }

        let entries = try createEntries(inputPath.path, false, basePath: base)
        let containerData = try TarContainer.create(from: entries)


        let compressedData = try GzipArchive.archive(data: containerData,
                                                    fileName: fileName.isEmpty ? nil : fileName,
                                                    writeHeaderCRC: true)
        try compressedData.write(to: outputPath)
        //try containerData.write(to: URL(fileURLWithPath: outputPath))
    }

    func generateNewConfig() -> Bool {
        //First up, let's check a config isn't already in place
        if loadConfig() {
            print("ERROR: Config already exists, please choose another directory")
            return false
        }

        print("Please fill in the information below that will be incorporated into your certificate.")
        print("Some fields have a default value in square brackets, simply press Enter to use these values without entering anything.")
        print("Some fields can be left blank if desired. Enter a '.' only for a field to be left blank.")
        print("---")

        if self.keyAlg == .EdDSA {
            while true {
                print("IMPORTANT!!!");
                print("You have selected to use EdDSA. EdDSA support is currently experimental and requires the latest versions of OpenVPN, OpenSSL and Viscosity.");

                if let input = askQuestion("Continue? [Y/n]:")?.lowercased() {
                    if input == "y" {
                        break
                    } else if input == "n" {
                        exit(0)
                    }
                    print("Invalid input, try again.")
                } else {
                    break
                }
            }
        } else if self.keyAlg == .ECDSA {
            while true {
                if !defaultCurves.contains(self.curveName) {
                    print("IMPORTANT!!!");
                    print("You have selected a curve OpenVPN may not support.")
                } else {
                    break
                }
                if let input = askQuestion("Continue? [Y/n]:")?.lowercased() {
                    if input == "y" {
                        break
                    } else if input == "n" {
                        exit(0)
                    }
                    print("Invalid input, try again.")
                } else {
                    break
                }
            }
        }

        guard let address = askQuestion("Server address, e.g. myserver.mydomain.com:", allowedBlank:false) else {
            print("ERROR: Failed to get address from command line")
            return false;
        }
        var port:String = defaultPort
        while true {
            if let input = askQuestion("Server Port [\(defaultPort)]:", allowedBlank:false) {
                if let value = Int(input), value > 0, value < 65535 {
                    port = input;
                    break
                } else {
                    print("Invalid input, try again.")
                }
            } else {
                port = defaultPort
                break
            }
        }
        var proto:String = defaultProtocol
        while true {
            if let input = askQuestion("Protocol, 1=UDP, 2=TCP [\(defaultProtocol)]:", allowedBlank:false) {
                if let value = Int(input) {
                    if value == 1 {
                        proto = "udp"
                        break
                    } else if value == 2 {
                        proto = "tcp"
                        break
                    } else {
                        print ("Invalid input, try again.")
                    }
                } else {
                    print ("Invalid input, try again.")
                }
            } else {
                proto = defaultProtocol.lowercased()
                break
            }
        }

        var redirectTraffic:Bool = true
        while true {
            if let input = askQuestion("Redirect all traffic through VPN? [Y/n]:")?.lowercased() {
                if input == "y" {
                    redirectTraffic = true
                    break
                } else if input == "n" {
                    redirectTraffic = false
                    break
                }
                print("Invalid input, try again.")
            } else {
                redirectTraffic = true
                break
            }
        }

        var dns:[String] = []
        let defaultDNSChoice:Int
        var customDNS = false
        if redirectTraffic {
            defaultDNSChoice = 1
        } else {
            defaultDNSChoice = 4
        }
        print("Please specify DNS servers to push to connecting clients:")
        print("\t1 - CloudFlare (\(cloudflareDNS.joined(separator: " & ")))")
        print("\t2 - Google (\(googleDNS.joined(separator: " & ")))")
        print("\t3 - OpenDNS (\(openDNS.joined(separator: " & ")))")
        print("\t4 - Local Server (\(localDNS)). You will need a DNS server running beside your VPN server")
        print("\t5 - Custom")
        print("\t6 - None")
        while true {
            if let input = askQuestion("Please select an option [\(defaultDNSChoice)]:") {
                switch input {
                case "1":
                    dns.append(contentsOf: cloudflareDNS)
                case "2":
                    dns.append(contentsOf: googleDNS)
                case "3":
                    dns.append(contentsOf: openDNS)
                case "4":
                    dns.append(localDNS)
                case "5":
                    customDNS = true
                case "6", ".":
                    break
                default:
                    print("\(input) is not a valid choice")
                    continue
                }
                // Default will continue, so we can break here
                break
            } else {
                if defaultDNSChoice == 1 {
                    dns.append(contentsOf: cloudflareDNS)
                } else {
                    dns.append(localDNS)
                }
                break
            }
        }
        if customDNS {
            while true {
                if let input = askQuestion("Enter Custom DNS Servers, comma separated for multiple:", allowedBlank:false) {
                    //Validate
                    var finalVal:[String] = []
                    let vals = input.components(separatedBy: ",")
                    var valid = true
                    for v in vals {
                        let val = v.trim()
                        if IPAddress(ipAddress: val) != nil {
                            finalVal.append(val)
                        } else {
                            print("\(v) is not a valid IP Address.")
                            valid = false
                        }
                    }
                    if valid {
                        dns = finalVal
                        break
                    }
                }
            }
        }

        while true {
            if let input = askQuestion("Would you like to use tls-crypt-v2 with this configuration? [Y/n]:")?.lowercased() {
                if input == "y" {
                    self.tlscryptv2 = true
                    break
                } else if input == "n" {
                    self.tlscryptv2 = false
                    break
                }
                print("Invalid input, try again.")
            } else {
                self.tlscryptv2 = true
                break
            }
        }

        var cs:CertificateSubject

        var useDefaults:Bool = true
        while true {
            if let input = askQuestion("Would you like to use anonymous defaults for certificate details? [Y/n]:")?.lowercased() {
                if input == "y" {
                    useDefaults = true
                    break
                } else if input == "n" {
                    useDefaults = false
                    break
                }
                print("Invalid input, try again.")
            } else {
                useDefaults = true
                break
            }
        }
        
        if useDefaults {
            //Empty CS with server address as CN
            cs = CertificateSubject(withCommonName: address)
        } else {
            let CN:String
            if let input = askQuestion("Common Name, e.g. your servers name [\(address)]:", allowedBlank: false) {
                CN = input
            } else {
                CN = address;
            }
                
            //Create CS
            cs = CertificateSubject(withCommonName: CN)

            //Country
            if let input = askQuestion("Country Name, 2 letter ISO code [\(defaultCountry)]:") {
                if input != "." {
                    cs.Country = input
                }
            } else {
                cs.Country = defaultCountry
            }

            //State
            if let input = askQuestion("State or Province [\(defaultState)]:") {
                if input != "." {
                    cs.State = input
                }
            } else {
                cs.State = defaultState
            }

            //Locality
            if let input = askQuestion("Locality Name, e.g. a City [\(defaultLocale)]:") {
                if input != "." {
                    cs.Location = input
                }
            } else {
                cs.Location = defaultLocale
            }

            //ON
            if let input = askQuestion("Organisation Name [\(defaultON)]:") {
                if input != "." {
                    cs.Organisation = input
                }
            } else {
                cs.Organisation = defaultON
            }

            //OU
            if let input = askQuestion("Organisation Unit, e.g department [\(defaultOU)]:") {
                if input != "." {
                    cs.OrganisationUnit = input
                }
            } else {
                cs.OrganisationUnit = defaultOU
            }

            //Email
            if let input = askQuestion("Email Address [\(defaultEmail)]:") {
                if input != "." {
                    cs.Email = input
                }
            } else {
                cs.Email = defaultEmail
            }
        }

        //Save the config
        var config = cs.toDict()
        config["proto"] = proto
        config["port"] = port
        config["dns"] = dns
        config["tlscryptv2"] = self.tlscryptv2
        config["server"] = address
        config["redirect"] = redirectTraffic
        config["keysize"] = self.keySize
        config["validdays"] = self.validDays
        config["algorithm"] = self.keyAlg.rawValue
        config["eccurve"] = self.curveName
        config["suffix"] = self.suffix

        self.config = config;
        self.cSubject = cs

        //Save to file
        return self.saveConfig()
    }
    func revokeCert(name: String? = nil) -> Bool {

        if !FileManager.default.fileExists(atPath: self.pkiPath.path) {
            print("ERROR: There are no certificates to revoke.")
            return false
        }
        guard let issuer = self.Issuer else {
            print("ERROR: No issuer available")
            return false
        }
        let CN:String
        if let n = name {
            CN = n
        } else {
            if let input = askQuestion("Common Name of certificate to revoke:", allowedBlank: false) {
                CN = input
            } else {
                return false
            }
        }
        // Make sure we dont try to revoke ourself
        if (CN == "cert") {
            print("ERROR: Cannot revoke this.")
            return false
        }

        // FInd the certificate
        let certname = "\(CN).crt"
        let certpath = self.pkiPath.appendingPathComponent(certname)
        guard let clientcert = Certificate(withFileURL: certpath) else {
            print("ERROR: Failed to load certificate")
            return false
        }
        // Check for existing CRL
        let crlData = try? String(contentsOfFile: self.crlPath.path)

        // Create/Update CRL
        guard let newCrl = issuer.createCRL(crlData:crlData, revokeCert:clientcert, daysValid:self.validDays) else {
            return false
        }
        // Write CRL
        do {
        #if os(Windows)
            try newCrl.write(to: self.crlPath, atomically:false, encoding: .utf8)
        #else
            try newCrl.write(to: self.crlPath, atomically:true, encoding: .utf8)
        #endif
        } catch {
            print("ERROR: Failed to write CRL to disk. \(error)")
            return false
        }

        // Delete PKI and configuration for this user
        do {
            try FileManager.default.removeItem(at: certpath)
        } catch {
            print("ERROR: Failed to remove revoked PKI data. \(error)")
        }
        let keypath = self.pkiPath.appendingPathComponent("\(CN).key")
        do {
            try FileManager.default.removeItem(at: keypath)
        } catch {
            print("ERROR: Failed to remove revoked PKI data. \(error)")
        }
        let confpath = self.clientsPath.appendingPathComponent("\(CN).visz")
        do {
            try FileManager.default.removeItem(at: confpath)
        } catch {
            print("ERROR: Failed to remove revoked PKI data. \(error)")
        }
        print()
        print("\"\(CN)\" has been successfully revoked. The CRL file has been saved to \"\(self.crlPath)\".")
        print("Please leave a copy of the CRL file in place if you wish to update it in the future.")
        print()
        if let input = askQuestion("Regenerate Server configuration? [Y/n]:", allowedBlank: false)?.lowercased(), 
            input == "y" {
            _ = self.createServerConfig()
        } else {
            // Blank, so Y
            _ = self.createServerConfig()
        }

        return true
    }
}
