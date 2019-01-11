// Copyright SparkLabs Pty Ltd 2018

import Foundation
import SparkLabsCore

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
    let clientsPath:URL

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

    let protectedCNs = ["server", "ca"]

    var cSubject:CertificateSubject? = nil
    var config:[String:Any] = [:]
    fileprivate var Issuer:Identity? = nil

    init(path:String, keySize:Int = 2048, validDays:Int = 3650) {
        self.path = URL(fileURLWithPath: path)
        self.configPath = self.path.appendingPathComponent("config.conf")
        self.pkiPath = self.path.appendingPathComponent("pki")
        self.caPath = self.pkiPath.appendingPathComponent("ca.crt")
        self.keyPath = self.pkiPath.appendingPathComponent("ca.key")
        self.clientsPath = self.path.appendingPathComponent("clients")
        self.keySize = keySize
        self.validDays = validDays
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
        
        //Find and load CA/Key
        guard let cert = Certificate(withCertificateFile: caPath.path), let key = Key(withFilePath: keyPath.path) else {
            print("ERROR: Failed to load issuing identity.")
            return false
        }
        self.Issuer = Identity(withCertificate: cert, andKey: key, isIssuer: true)

        return true
    }
    func saveConfig() -> Bool {
        //Update the serial
        self.config["serial"] = self._serial
        guard let json = Utilities.jsonToString(self.config) else {
            print("ERROR: Failed to construct config")
            return false
        }
        //Save to file
        do {
            try json.write(to: self.configPath, atomically: true, encoding: .utf8)
        } catch {
            print("ERROR: Failed to write config to \(path.path). \(error)")
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
        let capath = self.pkiPath.appendingPathComponent(name + ".crt")
        let keypath = self.pkiPath.appendingPathComponent(name + ".key")
        guard let cert = identity.Certificate.CertificateAsPEM else {
            print("ERROR: Failed to create CA Certificate")
            return false
        }
        do {
            try cert.write(to: capath, atomically:true, encoding: .utf8)
        } catch {
            print("ERROR: Failed to save CA Certificate to \(capath). \(error)")
        }
        guard let key = identity.Key.KeyAsPEM else {
            print("ERROR: Failed to create CA Key")
            return false
        }
        do {
            try key.write(to: keypath, atomically:true, encoding: .utf8)
        } catch {
            print("ERROR: Failed to save CA Key to \(keypath). \(error)")
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
        guard let identity = Identity.createCAAndKey(subject: subject, bitLength: keySize, daysValid: self.validDays, serial: self.Serial) else {
            print("ERROR: Failed to create CA")
            return false
        }
        self.Issuer = identity
        //Save to disk
        return saveIdentity(identity, name: "ca")
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
            try dhPem.write(to: dhPath, atomically: true, encoding: .utf8)
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
        guard let identity = issuer.createNewServerBundle(subject: subject, bitLength: keySize, daysValid: self.validDays, serial: self.Serial) else {
            print("ERROR: Failed to create server identity")
            return false
        }
        return saveIdentity(identity, name:"server")
    }
    func createServerConfig() -> Bool {
        let certpath = self.pkiPath.appendingPathComponent("server.crt")
        let keypath = self.pkiPath.appendingPathComponent("server.key")
        let dhPath = self.pkiPath.appendingPathComponent("dh.pem")
        guard FileManager.default.fileExists(atPath: self.caPath.path) else {
            print("ERROR: Missing CA. Please regenerate config")
            return false
        }
        guard FileManager.default.fileExists(atPath: dhPath.path) else {
            print("ERROR: Missing DH. Please regenerate config")
            return false
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
        var file = "#-- Config Auto Generated by SparkLabs OpenVPN Certificate Generator --#\n"
        file +=    "#--                   Config for OpenVPN 2.4 Server                  --#\n\n"
        file += "dh dh.crt\n"
        file += "proto \(proto)\n"
        file += "ifconfig-pool-persist ipp.txt\n"
        file += "keepalive 10 120\n"
        file += "user nobody\ngroup nogroup\n"
        file += "persist-key\npersist-tun\n"
        file += "status openvpn-status.log\n"
        file += "verb 3\n"
        file += "mute 10\n"
        file += "ca ca.crt\ncert server.crt\nkey server.key\n"
        file += "port \(port)\n"
        file += "dev tun0\n"
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
            try file.write(to: serverPath.appendingPathComponent("server.conf"), atomically:true, encoding: .utf8)
        } catch {
            print("ERROR: Failed to write server config. \(error)")
            return false
        }
        //Copy files
        do {
            try Utilities.copyItem(at: self.caPath, to: serverPath.appendingPathComponent("ca.crt"))
        } catch {
            print("ERROR: Failed to copy CA. \(error)")
            return false
        }
        do {
            try Utilities.copyItem(at: certpath, to: serverPath.appendingPathComponent("server.crt"))
        } catch {
            print("ERROR: Failed to copy Cert. \(error)")
            return false
        }
        do {
            try Utilities.copyItem(at: dhPath, to: serverPath.appendingPathComponent("dh.crt"))
        } catch {
            print("ERROR: Failed to copy DH. \(error)")
            return false
        }
        do {
            try Utilities.copyItem(at: keypath, to: serverPath.appendingPathComponent("server.key"))
        } catch {
            print("ERROR: Failed to copy key. \(error)")
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
        guard let identity = issuer.createNewUserBundle(subject: subject, bitLength: keySize, daysValid: self.validDays, serial: self.Serial) else {
            print("ERROR: Failed to create client identity")
            return false
        }
        return saveIdentity(identity, name:name)
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
        let clientPath = self.path.appendingPathComponent(CN)
        do {
            if FileManager.default.fileExists(atPath: clientPath.path) {
                try FileManager.default.removeItem(at: clientPath)
            }
            try FileManager.default.createDirectory(atPath: clientPath.path, withIntermediateDirectories: false, attributes: nil)
        } catch {
            print("ERROR: Failed to make directory for server configuration. \(error)")
            return false
        }
        if !createNewClientIdentity(name: CN) {
            return false
        }
        //Copy files
        let certpath = self.pkiPath.appendingPathComponent("\(CN).crt")
        let keypath = self.pkiPath.appendingPathComponent("\(CN).key")
        do {
            try Utilities.copyItem(at: self.caPath, to: clientPath.appendingPathComponent("ca.crt"))
        } catch {
            print("ERROR: Failed to copy CA. \(error)")
            return false
        }
        do {
            try Utilities.copyItem(at: certpath, to: clientPath.appendingPathComponent("\(CN).crt"))
        } catch {
            print("ERROR: Failed to copy Cert. \(error)")
            return false
        }
        do {
            try Utilities.copyItem(at: keypath, to: clientPath.appendingPathComponent("\(CN).key"))
        } catch {
            print("ERROR: Failed to copy Key. \(error)")
            return false
        }

        //Create config
        var file = "#-- Config Auto Generated By SparkLabs OpenVPN Certificate Generator--#\n\n"
        file += "#viscosity name \(CN)@\(address)\n"
        file += "remote \(address) \(port) \(proto)\n"
        file += "dev tun\ntls-client\n"
        //Certs
        file += "ca ca.crt\n"
        file += "cert \(CN).crt\n"
        file += "key \(CN).key\n"
        file += "persist-tun\npersist-key\nnobind\npull\n"
        //Write config
        do {
            try file.write(to: clientPath.appendingPathComponent("config.conf"), atomically:true, encoding: .utf8)
        } catch {
            print("ERROR: Failed to write server config. \(error)")
            return false
        }

        //Generate .visz
        let proc = Process()
        #if os(Linux)
            proc.launchPath = "/bin/tar"
        #else
            proc.launchPath = "/usr/bin/tar"
        #endif
        let pp = Utilities.normalisePath(self.path.path)
        let archive = self.clientsPath.appendingPathComponent("\(CN).visz")
        proc.arguments = ["-czf", archive.path, "-C", pp, CN]
        proc.launch()
        proc.waitUntilExit()

        //Remove the config folder
        if FileManager.default.fileExists(atPath: clientPath.path) {
            try? FileManager.default.removeItem(at: clientPath)
        }

        return true
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
                        if IPAddress.isValidIP(val, family: .AnyFamily) {
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
        config["server"] = address
        config["redirect"] = redirectTraffic
        config["keysize"] = self.keySize
        config["validdays"] = self.validDays

        self.config = config;
        self.cSubject = cs

        //Save to file
        return self.saveConfig()
    }
}
