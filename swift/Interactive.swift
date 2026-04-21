// Copyright SparkLabs Pty Ltd 2026

import Foundation
import SparkLabsCore
import SparkLabsCrypto
import SWCompression

fileprivate enum ViszArchiveError: LocalizedError {
    case inputPathIsNotDirectory(URL)
    case invalidOutputExtension(URL)
    case emptyArchivePath(URL)
    case unsupportedFileType(URL, FileAttributeType?)

    var errorDescription: String? {
        switch self {
        case .inputPathIsNotDirectory(let url):
            return "Client package directory not found at \(url.path)."
        case .invalidOutputExtension(let url):
            return "Output path must end with .visz: \(url.path)."
        case .emptyArchivePath(let url):
            return "Failed to derive a non-empty archive path for \(url.path)."
        case .unsupportedFileType(let url, let type):
            if let type {
                return "Unsupported file type \(type.rawValue) at \(url.path)."
            }
            return "Unsupported file type at \(url.path)."
        }
    }
}

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

    let path: URL
    let configPath: URL
    let pkiPath: URL
    let caPath: URL
    let keyPath: URL
    let crlPath: URL
    let clientsPath: URL
    let tlscryptv2Path: URL

    var keySize: Int
    var validDays: Int
    var _serial: Int = 0
    var Serial: Int {
        get {
            let next = _serial + 1
            _serial = next
            return next
        }
    }
    var keyAlg: CertificateAlgorithm
    var curveName: String
    var suffix: String

    var tlscryptv2: Bool
    var serverSANs: [String]
    fileprivate var serverSANOverrideProvided: Bool

    let protectedCNs = ["server", "ca"]

    var certificateSubject: DistinguishedName? = nil
    var config: [String: Any] = [:]
    fileprivate var issuerCA: CertificateAuthority? = nil

    let defaultCurves = ["secp256r1", "secp521r1", "secp384r1"]
    let modernDataCiphers = "AES-256-GCM:AES-128-GCM:?CHACHA20-POLY1305"

    init(path: URL, keySize: Int = 2048, validDays: Int = 3650) {
        self.path = path
        self.configPath = self.path.appendingPathComponent("config.conf")
        self.pkiPath = self.path.appendingPathComponent("pki")
        self.caPath = self.pkiPath.appendingPathComponent("ca.crt")
        self.keyPath = self.pkiPath.appendingPathComponent("ca.key")
        self.crlPath = self.pkiPath.appendingPathComponent("crl.crt")
        self.clientsPath = self.path.appendingPathComponent("clients")
        self.tlscryptv2Path = self.pkiPath.appendingPathComponent("server-tc2.key")
        self.keySize = keySize
        self.validDays = validDays
        self.keyAlg = .ecdsa
        self.curveName = "secp384r1"
        self.suffix = ""
        self.tlscryptv2 = false
        self.serverSANs = []
        self.serverSANOverrideProvided = false
    }

    fileprivate func writeStdout(_ text: String) {
        guard let data = text.data(using: .utf8) else {
            return
        }
        FileHandle.standardOutput.write(data)
    }

    fileprivate func askQuestion(_ question: String, allowedBlank: Bool = true) -> String? {
        while true {
            writeStdout(question + " ")
            if let input = readLine() {
                if input.isEmpty {
                    return nil
                }
                if input == "." && !allowedBlank {
                    print("This field cannot be left blank.")
                }
                return input
            }
            return nil
        }
    }

    func subject(from dict: [String: Any]) -> DistinguishedName? {
        guard let commonName = dict["CommonName"] as? String else {
            return nil
        }
        return DistinguishedName(
            commonName: commonName,
            localityName: dict["Location"] as? String,
            stateOrProvinceName: dict["State"] as? String,
            organizationName: dict["Organisation"] as? String,
            organizationalUnitName: dict["OrganisationUnit"] as? String,
            countryName: dict["Country"] as? String,
            email: dict["Email"] as? String
        )
    }

    func subjectDictionary(from subject: DistinguishedName) -> [String: Any] {
        var dict: [String: Any] = [:]
        if let commonName = subject.commonName?.strip(), !commonName.isEmpty {
            dict["CommonName"] = commonName
        }
        if let country = subject.countryName?.strip(), !country.isEmpty {
            dict["Country"] = country
        }
        if let state = subject.stateOrProvinceName?.strip(), !state.isEmpty {
            dict["State"] = state
        }
        if let locality = subject.localityName?.strip(), !locality.isEmpty {
            dict["Location"] = locality
        }
        if let organization = subject.organizationName?.strip(), !organization.isEmpty {
            dict["Organisation"] = organization
        }
        if let organizationalUnit = subject.organizationalUnitName?.strip(), !organizationalUnit.isEmpty {
            dict["OrganisationUnit"] = organizationalUnit
        }
        if let email = subject.email?.strip(), !email.isEmpty {
            dict["Email"] = email
        }
        return dict
    }

    func subject(_ subject: DistinguishedName, withCommonName commonName: String) -> DistinguishedName? {
        let trimmedCommonName = commonName.strip()
        guard !trimmedCommonName.isEmpty else {
            return nil
        }
        return DistinguishedName(
            commonName: trimmedCommonName,
            localityName: subject.localityName,
            stateOrProvinceName: subject.stateOrProvinceName,
            organizationName: subject.organizationName,
            organizationalUnitName: subject.organizationalUnitName,
            countryName: subject.countryName,
            email: subject.email
        )
    }

    private func normalizedCurveName(_ curve: String) -> String {
        let trimmed = curve.strip()
        if trimmed.compare("prime256v1", options: .caseInsensitive) == .orderedSame {
            return "secp256r1"
        }
        if trimmed.compare("ed25519", options: .caseInsensitive) == .orderedSame {
            return "ED25519"
        }
        if trimmed.compare("ed448", options: .caseInsensitive) == .orderedSame {
            return "ED448"
        }
        return trimmed
    }

    private func resolveOpenSSLECCurveName(_ curveName: String) -> String? {
        let trimmed = curveName.strip()
        guard !trimmed.isEmpty else {
            return nil
        }

        var candidates = [trimmed]
        if trimmed.compare("prime256v1", options: .caseInsensitive) == .orderedSame {
            candidates.append("secp256r1")
        } else if trimmed.compare("secp256r1", options: .caseInsensitive) == .orderedSame {
            candidates.append("prime256v1")
        }

        let supportedCurves = Key.supportedOpenSSLECCurveNames()
        for candidate in candidates {
            if let supported = supportedCurves.first(where: { $0.compare(candidate, options: .caseInsensitive) == .orderedSame }) {
                return supported
            }
        }
        for candidate in candidates where Key.supports(openSSLECCurveName: candidate) {
            return candidate
        }
        return nil
    }

    private func selectedKeyAlgorithm() -> KeyAlgorithm? {
        switch keyAlg {
        case .rsa:
            if keySize < 2048 {
                print("ERROR: RSA key size must be at least 2048 bits.")
                return nil
            }
            return .rsa(bits: keySize)
        case .ecdsa:
            let requestedCurve = normalizedCurveName(curveName)
            guard let curve = resolveOpenSSLECCurveName(requestedCurve) ?? resolveOpenSSLECCurveName(curveName) else {
                print("ERROR: Unsupported ECDSA curve '\(curveName)'. Run '--show-curves' to list supported ECDSA curves for this OpenSSL build.")
                return nil
            }
            self.curveName = normalizedCurveName(curve)
            return .ecOpenSSL(named: curve)
        case .eddsa:
            let normalized = normalizedCurveName(curveName).lowercased()
            if normalized == "ed25519" {
                guard Key.supports(curveName: normalized) else {
                    print("ERROR: EdDSA curve Ed25519 is not supported by this OpenSSL build/provider.")
                    return nil
                }
                self.curveName = "ED25519"
                return .ed25519
            }
            if normalized == "ed448" {
                guard Key.supports(curveName: normalized) else {
                    print("ERROR: EdDSA curve Ed448 is not supported by this OpenSSL build/provider.")
                    return nil
                }
                self.curveName = "ED448"
                return .ed448
            }
            print("ERROR: Unsupported EdDSA curve '\(curveName)'. Supported curves are Ed25519 and Ed448.")
            return nil
        }
    }

    private func defaultServerSANs(for serverAddress: String) -> [String] {
        let trimmed = serverAddress.strip()
        guard !trimmed.isEmpty else {
            return []
        }
        if let ip = IPAddress(string: trimmed) {
            return ["IP:\(ip.addressWithScope)"]
        }
        if let host = IPHost(trimmed) {
            return ["DNS:\(host.safeDomain)"]
        }
        return ["DNS:\(trimmed)"]
    }

    private func normalizeServerSANEntry(_ entry: String) -> String? {
        let trimmed = entry.strip()
        guard !trimmed.isEmpty else {
            return nil
        }

        if let separator = trimmed.firstIndex(of: ":") {
            let type = String(trimmed[..<separator]).strip().uppercased()
            let value = String(trimmed[trimmed.index(after: separator)...]).strip()
            guard !value.isEmpty else {
                return nil
            }
            switch type {
            case "IP":
                guard let ip = IPAddress(string: value) else {
                    return nil
                }
                return "IP:\(ip.addressWithScope)"
            case "DNS":
                guard let host = IPHost(value) else {
                    return nil
                }
                return "DNS:\(host.safeDomain)"
            default:
                return nil
            }
        }

        if let ip = IPAddress(string: trimmed) {
            return "IP:\(ip.addressWithScope)"
        }
        if let host = IPHost(trimmed) {
            return "DNS:\(host.safeDomain)"
        }
        return nil
    }

    private func parseServerSANList(_ input: String) -> [String]? {
        let entries = input.split(separator: ",", omittingEmptySubsequences: false).map(String.init)
        return parseServerSANArray(entries)
    }

    private func parseServerSANArray(_ values: [String]) -> [String]? {
        var normalized: [String] = []
        var seen: Set<String> = []
        for value in values {
            let trimmed = value.strip()
            if trimmed.isEmpty {
                continue
            }
            guard let entry = normalizeServerSANEntry(trimmed) else {
                return nil
            }
            let key = entry.lowercased()
            if seen.insert(key).inserted {
                normalized.append(entry)
            }
        }
        return normalized
    }

    private func splitServerSANsForProfile() -> (dnsNames: [String], ipAddresses: [String]) {
        var dnsNames: [String] = []
        var ipAddresses: [String] = []
        for entry in serverSANs {
            guard let separator = entry.firstIndex(of: ":") else {
                continue
            }
            let type = entry[..<separator].uppercased()
            let value = String(entry[entry.index(after: separator)...])
            if type == "DNS" {
                dnsNames.append(value)
            } else if type == "IP" {
                ipAddresses.append(value)
            }
        }
        return (dnsNames, ipAddresses)
    }

    func setServerSANsFromOption(_ option: String) -> Bool {
        self.serverSANOverrideProvided = true
        let trimmed = option.strip()
        if trimmed.isEmpty {
            self.serverSANs = []
            return true
        }
        guard let parsed = parseServerSANList(option) else {
            print("ERROR: Invalid --server-san value '\(option)'. Use comma-separated DNS:/IP: entries.")
            return false
        }
        self.serverSANs = parsed
        return true
    }

    func loadConfig() -> Bool {
        guard configPath.isFileAndExists else {
            return false
        }

        let dict: [String: Any]
        do {
            let data = try Data(contentsOf: configPath)
            guard let temp = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any] else {
                print("ERROR: Failed to load config")
                return false
            }
            dict = temp
        } catch {
            print("ERROR: Failed to load config at \(configPath.path). \(error)")
            return false
        }

        // Pull the subject
        guard let loadedSubject = subject(from: dict) else {
            print("ERROR: Failed to load subject from config")
            return false
        }
        self.certificateSubject = loadedSubject
        self.config = dict

        // Load in "fixed" defaults
        if let ks = self.config["keysize"] as? Int {
            self.keySize = ks
        }
        if let vd = self.config["validdays"] as? Int {
            self.validDays = vd
        }
        if let ser = self.config["serial"] as? Int {
            self._serial = ser
        }
        if let sAlg = self.config["algorithm"] as? String,
           let alg = CLI.getAlgorithm(sAlg) {
            self.keyAlg = alg
        }
        if let curve = self.config["eccurve"] as? String {
            self.curveName = normalizedCurveName(curve)
        } else if self.keyAlg == .eddsa {
            self.curveName = "ED25519"
        }
        if let suffix = self.config["suffix"] as? String {
            self.suffix = suffix
        }
        if let useTC = self.config["tlscryptv2"] as? Bool {
            self.tlscryptv2 = useTC
        }
        if let configuredSANs = self.config["serverSANs"] as? [String] {
            guard let parsedSANs = parseServerSANArray(configuredSANs) else {
                print("ERROR: Invalid serverSANs in config. Expected DNS:/IP: entries.")
                return false
            }
            self.serverSANs = parsedSANs
        } else if let serverAddress = self.config["server"] as? String {
            self.serverSANs = defaultServerSANs(for: serverAddress)
            self.config["serverSANs"] = self.serverSANs
        } else {
            self.serverSANs = []
        }

        // Find and load CA/Key
        guard let cert = Certificate(withURL: caPath, preferredBacking: .openSSL),
              let key = Key(withURL: keyPath, format: .pem, preferredBacking: .openSSL) else {
            print("ERROR: Failed to load issuing identity.")
            return false
        }

        do {
            let identity = try Identity(validating: cert, privateKey: key)
            self.issuerCA = try CertificateAuthority(identity: identity)
        } catch {
            print("ERROR: Failed to load issuing identity. \(error)")
            return false
        }

        return true
    }

    func saveConfig() -> Bool {
        // Update the serial
        for key in ["CommonName", "Country", "Location", "State", "Organisation", "OrganisationUnit", "Email", "SubjectAlt"] {
            self.config.removeValue(forKey: key)
        }
        if let subject = self.certificateSubject {
            for (key, value) in subjectDictionary(from: subject) {
                self.config[key] = value
            }
        }
        self.config["serial"] = self._serial
        self.config["serverSANs"] = self.serverSANs
        guard let data = try? JSONSerialization.data(withJSONObject: self.config, options: []),
              let json = String(data: data, encoding: .utf8) else {
            print("ERROR: Failed to construct config")
            return false
        }
        // Save to file
        do {
            try json.write(to: self.configPath, atomically: false, encoding: .utf8)
        } catch {
            print("ERROR: Failed to write config to \(configPath.path). \(error)")
            return false
        }
        return true
    }

    private func isUDPProtocol(_ proto: String) -> Bool {
        return !proto.lowercased().contains("tcp")
    }

    private func tlsGroupsDirective() -> String? {
        guard self.keyAlg == .ecdsa,
              !defaultCurves.contains(self.curveName) else {
            return nil
        }
        return "tls-groups \(self.curveName):secp256r1:secp521r1:secp384r1\n"
    }

    private func pushedDNSDirectives(_ dnsEntries: [String]) -> String {
        var lines = ""
        for (index, entry) in dnsEntries.enumerated() {
            lines += "push \"dns server \(index) address \(entry)\"\n"
        }
        return lines
    }

    func serverConfigContents(proto: String, port: String, dnsEntries: [String], redirectTraffic: Bool, includeCRL: Bool) -> String {
        let caName = "ca\(self.suffix).crt"
        let crlName = "crl\(self.suffix).crt"
        let certName = "server\(self.suffix).crt"
        let keyName = "server\(self.suffix).key"
        let dhName = "dh\(self.suffix).pem"
        let tc2Name = "server-tc2\(self.suffix).key"

        var file = """
        #-- Config Auto Generated by SparkLabs OpenVPN Configuration Generator --#
        #--                     Config for OpenVPN Server                      --#

        proto \(proto)
        ifconfig-pool-persist ipp\(self.suffix).txt
        keepalive 10 120
        
        """
        if isUDPProtocol(proto) {
            file += "explicit-exit-notify 1\n"
        }
        file += """
        persist-key
        persist-tun
        status openvpn-status\(self.suffix).log
        verb 3
        mute 10
        ca "\(caName)"
        cert "\(certName)"
        key "\(keyName)"
        
        """
        if includeCRL {
            file += "crl-verify \"\(crlName)\"\n"
        }
        if self.tlscryptv2 {
            file += "tls-crypt-v2 \"\(tc2Name)\"\n"
        }
        if self.keyAlg == .rsa {
            file += "dh \(dhName)\n"
        } else {
            file += "dh none\n"
        }
        if let tlsGroupsDirective = tlsGroupsDirective() {
            file += tlsGroupsDirective
        }
        file += """
        tls-version-min 1.2
        data-ciphers \(self.modernDataCiphers)
        auth SHA256
        remote-cert-tls client
        port \(port)
        dev tun0
        topology subnet
        server 10.8.0.0 255.255.255.0
        """
        file += pushedDNSDirectives(dnsEntries)
        if redirectTraffic {
            file += "push \"redirect-gateway def1\"\n"
        }
        file += """
        #Uncomment the below to allow client to client communication
        #client-to-client
        #Uncomment the below and modify the command to allow access to your internal network
        #push "route 192.168.0.0 255.255.255.0"
        """
        return file
    }

    func clientConfigContents(name: String, address: String, port: String, proto: String) -> String {
        let certName = "\(name).crt"
        let keyName = "\(name).key"
        let tc2Name = "\(name)-tc2.key"

        var file = """
        #-- Config Auto Generated By SparkLabs OpenVPN Configuration Generator--#

        #viscosity name \(name)@\(address)
        remote \(address) \(port) \(proto)
        dev tun
        tls-client
        ca "ca.crt"
        cert "\(certName)"
        key "\(keyName)"
        
        """
        if self.tlscryptv2 {
            file += "tls-crypt-v2 \"\(tc2Name)\"\n"
        }
        file += """
        tls-version-min 1.2
        data-ciphers \(self.modernDataCiphers)
        auth SHA256
        remote-cert-tls server
        
        """
        if isUDPProtocol(proto) {
            file += "explicit-exit-notify 1\n"
        }
        file += """
        persist-tun
        persist-key
        nobind
        pull
        """
        return file
    }

    fileprivate func saveIdentity(_ identity: Identity, name: String) -> Bool {
        // Create dir if not exists
        do {
            if !self.pkiPath.isDirectoryAndExists {
                try FileManager.default.createDirectory(at: self.pkiPath, withIntermediateDirectories: false, attributes: nil)
            }
        } catch {
            print("ERROR: Failed to create PKI dir. \(error)")
            return false
        }
		
        // Save to disk
        let certPath = self.pkiPath.appendingPathComponent(name + ".crt")
        let keyPath = self.pkiPath.appendingPathComponent(name + ".key")

        do {
            try identity.certificate.certificateAsPEM.write(to: certPath, atomically: false, encoding: .utf8)
        } catch {
            print("ERROR: Failed to save Certificate to \(certPath.path). \(error)")
            return false
        }

        let keyPEM: String
        if let pem = identity.key.keyAsPEM {
            keyPEM = pem
        } else if let pkcs8 = identity.key.keyAsPKCS8,
                  let pkcs8PEM = String(data: pkcs8, encoding: .utf8) {
            keyPEM = pkcs8PEM
        } else {
            print("ERROR: Failed to create key PEM for \(name)")
            return false
        }

        do {
            try keyPEM.write(to: keyPath, atomically: false, encoding: .utf8)
        } catch {
            print("ERROR: Failed to save Key to \(keyPath.path). \(error)")
            return false
        }

        return true
    }

    func createNewIssuer() -> Bool {
        guard let subject = self.certificateSubject else {
            print("ERROR: No Subject available.")
            return false
        }
        guard let algorithm = selectedKeyAlgorithm() else {
            return false
        }
		
        // Save to disk
        do {
            let ca = try CertificateAuthority.createRoot(
                subject: subject,
                keyAlgorithm: algorithm,
                validity: .days(validDays),
                serial: .integer(UInt64(Serial))
            )
            self.issuerCA = ca
            guard saveIdentity(ca.identity, name: "ca") else {
                return false
            }
			
            // The TC2 key effectively acts as an issuer, so generate it with the issuer
            return createNewTC2ServerKey()
        } catch {
            print("ERROR: Failed to create CA. \(error)")
            return false
        }
    }

    func createNewTC2ServerKey() -> Bool {
        do {
            let serverKey = try OpenVPNTLSCryptV2ServerKey.generate()
            try serverKey.pemString.write(to: self.tlscryptv2Path, atomically: false, encoding: .utf8)
        } catch {
            print("ERROR: Failed to save tls-crypt-v2 server key to \(self.tlscryptv2Path.path). \(error)")
            return false
        }
        return true
    }

    func createDH() -> Bool {
        print("Creating DH Params. This will take a while...")
        let dhPath = self.pkiPath.appendingPathComponent("dh.pem")
        let genCallback: OpenVPNDiffieHellmanParameters.GenerationCallback = { p, _ in
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
            fflush(stdout)
            return 1
        }
		
        // Save to disk
        do {
            let params = try Key.generateOpenVPNDiffieHellmanParameters(
                bitLength: keySize,
                callback: genCallback
            )
            try params.pemString.write(to: dhPath, atomically: false, encoding: .utf8)
        } catch {
            print("ERROR: Failed to generate DH Params. \(error)")
            return false
        }
        return true
    }

    func createNewServerIdentity() -> Bool {
        print("Creating Server Identity...")
        guard let issuer = self.issuerCA else {
            print("ERROR: No issuer available")
            return false
        }
        guard let baseSubject = self.certificateSubject,
              let subject = subject(baseSubject, withCommonName: "server") else {
            print("ERROR: No subject available.")
            return false
        }
		
        // Create ID
        guard let algorithm = selectedKeyAlgorithm() else {
            return false
        }
        let sanValues = splitServerSANsForProfile()

        do {
            let identity = try issuer.issueIdentity(
                subject: subject,
                keyAlgorithm: algorithm,
                profile: .openVPNServer(
                    dnsNames: sanValues.dnsNames,
                    ipAddresses: sanValues.ipAddresses,
                    includeLegacyNetscapeCertType: true
                ),
                validity: .days(validDays),
                serial: .integer(UInt64(Serial))
            )
            return saveIdentity(identity, name: "server")
        } catch {
            print("ERROR: Failed to create server identity. \(error)")
            return false
        }
    }

    func createServerConfig() -> Bool {
        let caName = "ca\(self.suffix).crt"
        let crlName = "crl\(self.suffix).crt"
        let certName = "server\(self.suffix).crt"
        let keyName = "server\(self.suffix).key"
        let dhName = "dh\(self.suffix).pem"
        let tc2Name = "server-tc2\(self.suffix).key"
        let certPath = self.pkiPath.appendingPathComponent("server.crt")
        let keyPath = self.pkiPath.appendingPathComponent("server.key")
        let dhPath = self.pkiPath.appendingPathComponent("dh.pem")

        guard self.caPath.isFileAndExists else {
            print("ERROR: Missing CA. Please regenerate config")
            return false
        }
        if self.keyAlg == .rsa {
            guard dhPath.isFileAndExists else {
                print("ERROR: Missing DH. Please regenerate config")
                return false
            }
        }

        guard let _ = config["server"] as? String,
              let port = config["port"] as? String,
              var proto = config["proto"] as? String else {
            print("ERROR: Invalid config. Please regenerate config")
            return false
        }
        if proto == "tcp" || proto == "tcp-client" { // tcp-client for legacy support
            proto = "tcp-server"
        } else {
            proto = "udp"
        }
		
        // Generate Identity
        guard createNewServerIdentity() else {
            return false
        }
        guard certPath.isFileAndExists else {
            print("ERROR: Missing Cert. Please regenerate config")
            return false
        }
        guard keyPath.isFileAndExists else {
            print("ERROR: Missing Key. Please regenerate config")
            return false
        }
		
        let dnsEntries = config["dns"] as? [String] ?? []
        let redirectTraffic = (config["redirect"] as? Bool) ?? false
        let includeCRL = self.crlPath.isFileAndExists
        let file = serverConfigContents(
            proto: proto,
            port: port,
            dnsEntries: dnsEntries,
            redirectTraffic: redirectTraffic,
            includeCRL: includeCRL
        )

        // Make a new directory for the server
        let serverPath = self.path.appendingPathComponent("server")
        do {
            if serverPath.exists {
                try FileManager.default.removeItem(at: serverPath)
            }
            try FileManager.default.createDirectory(at: serverPath, withIntermediateDirectories: false, attributes: nil)
        } catch {
            print("ERROR: Failed to make directory for server configuration. \(error)")
            return false
        }
        // Write server config
        do {
            try file.write(to: serverPath.appendingPathComponent("server\(self.suffix).conf"), atomically: false, encoding: .utf8)
        } catch {
            print("ERROR: Failed to write server config. \(error)")
            return false
        }
        // Copy files
        do {
            try FileManager.default.copyItem(at: self.caPath, to: serverPath.appendingPathComponent(caName))
        } catch {
            print("ERROR: Failed to copy CA. \(error)")
            return false
        }
        do {
            try FileManager.default.copyItem(at: certPath, to: serverPath.appendingPathComponent(certName))
        } catch {
            print("ERROR: Failed to copy Cert. \(error)")
            return false
        }
        do {
            if self.keyAlg == .rsa {
                try FileManager.default.copyItem(at: dhPath, to: serverPath.appendingPathComponent(dhName))
            }
        } catch {
            print("ERROR: Failed to copy DH. \(error)")
            return false
        }
        do {
            try FileManager.default.copyItem(at: keyPath, to: serverPath.appendingPathComponent(keyName))
        } catch {
            print("ERROR: Failed to copy key. \(error)")
            return false
        }
        do {
            if self.crlPath.isFileAndExists {
                try FileManager.default.copyItem(at: self.crlPath, to: serverPath.appendingPathComponent(crlName))
            }
        } catch {
            print("ERROR: Failed to copy CRL. \(error)")
            return false
        }
        do {
            if self.tlscryptv2 {
                try FileManager.default.copyItem(at: self.tlscryptv2Path, to: serverPath.appendingPathComponent(tc2Name))
            }
        } catch {
            print("ERROR: Failed to copy tls-crypt-v2. \(error)")
            return false
        }

        print("Successfully generated server configuration at \(serverPath.path).")
        return true
    }

    func createNewClientIdentity(name: String) -> Bool {
        guard let issuer = self.issuerCA else {
            print("ERROR: No issuer available")
            return false
        }
        guard let baseSubject = self.certificateSubject,
              let subject = subject(baseSubject, withCommonName: name) else {
            print("ERROR: No subject available.")
            return false
        }
        // Create ID
        guard let algorithm = selectedKeyAlgorithm() else {
            return false
        }

        let identity: Identity
        do {
            identity = try issuer.issueIdentity(
                subject: subject,
                keyAlgorithm: algorithm,
                profile: .openVPNClient(includeLegacyNetscapeCertType: true),
                validity: .days(validDays),
                serial: .integer(UInt64(Serial))
            )
        } catch {
            print("ERROR: Failed to create client identity. \(error)")
            return false
        }

        guard saveIdentity(identity, name: name) else {
            print("ERROR: Failed to write new client PKI to disk")
            return false
        }
        if !self.tlscryptv2 {
            return true
        }

        func deleteID() {
            // Delete PKI for this user if we need to
            let certPath = self.pkiPath.appendingPathComponent(name + ".crt")
            let keyPath = self.pkiPath.appendingPathComponent(name + ".key")
            do {
                try FileManager.default.removeItem(at: certPath)
            } catch {
                print("ERROR: Failed to remove revoked PKI data. \(error)")
            }
            do {
                try FileManager.default.removeItem(at: keyPath)
            } catch {
                print("ERROR: Failed to remove revoked PKI data. \(error)")
            }
        }
        // Create client tlscrypt
        let serverTC2Pem: String
        do {
            serverTC2Pem = try String(contentsOf: self.tlscryptv2Path)
        } catch {
            print("ERROR: Failed to read tls-crypt-v2 server key from \(self.tlscryptv2Path.path). \(error)")
            deleteID()
            return false
        }

        let clientTC2Path = self.pkiPath.appendingPathComponent(name + "-tc2.key")
        do {
            // Create client key
            let serverKey = try OpenVPNTLSCryptV2ServerKey(pem: serverTC2Pem)
            let clientKey = try serverKey.generateClientKey()
            try clientKey.pemString.write(to: clientTC2Path, atomically: false, encoding: .utf8)
        } catch {
            print("ERROR: Failed to generate client tls-crypt-v2 key. \(error)")
            deleteID()
            return false
        }

        return true
    }

    func createClientConfigDirectory(name: String? = nil) -> (name: String, path: URL)? {
        // Confirm we have everything
        guard self.issuerCA != nil else {
            print("ERROR: No issuer available")
            return nil
        }
        guard self.certificateSubject != nil else {
            print("ERROR: No subject available.")
            return nil
        }
        guard self.caPath.isFileAndExists else {
            print("ERROR: Missing CA. Please regenerate config")
            return nil
        }

        guard let address = config["server"] as? String,
              let port = config["port"] as? String,
              var proto = config["proto"] as? String else {
            print("ERROR: Invalid config. Please regenerate config")
            return nil
        }
        if proto == "tcp" || proto == "tcp-client" { // tcp-client for legacy support
            proto = "tcp-client"
        } else {
            proto = "udp"
        }
        // Try and make dir for all clients if not exists
        do {
            if !self.clientsPath.isDirectoryAndExists {
                try FileManager.default.createDirectory(at: self.clientsPath, withIntermediateDirectories: false, attributes: nil)
            }
        } catch {
            print("ERROR: Failed to make clients directory. \(error)")
            return nil
        }

        let CN: String
        if let name {
            CN = name
        } else if let input = askQuestion("Common Name. This should be unique, for example a username [client1]:", allowedBlank: false) {
            CN = input
        } else {
            CN = "client1"
        }

        var clientPath = self.path.appendingPathComponent(CN)
        if clientPath.exists {
            var i = 0
            repeat {
                i += 1
                clientPath = self.path.appendingPathComponent("\(CN)_\(i)")
            } while clientPath.exists
        }

        do {
            try FileManager.default.createDirectory(at: clientPath, withIntermediateDirectories: false, attributes: nil)
        } catch {
            print("ERROR: Failed to make directory for client configuration. \(error)")
            return nil
        }

        if !createNewClientIdentity(name: CN) {
            try? FileManager.default.removeItem(at: clientPath)
            return nil
        }
        // Copy files
        let certName = "\(CN).crt"
        let certPath = self.pkiPath.appendingPathComponent(certName)
        let keyName = "\(CN).key"
        let keyPath = self.pkiPath.appendingPathComponent(keyName)
        let tc2Name = "\(CN)-tc2.key"
        let tc2Path = self.pkiPath.appendingPathComponent(tc2Name)

        do {
            try FileManager.default.copyItem(at: self.caPath, to: clientPath.appendingPathComponent("ca.crt"))
        } catch {
            print("ERROR: Failed to copy CA. \(error)")
            try? FileManager.default.removeItem(at: clientPath)
            return nil
        }
        do {
            try FileManager.default.copyItem(at: certPath, to: clientPath.appendingPathComponent(certName))
        } catch {
            print("ERROR: Failed to copy Cert. \(error)")
            try? FileManager.default.removeItem(at: clientPath)
            return nil
        }
        do {
            try FileManager.default.copyItem(at: keyPath, to: clientPath.appendingPathComponent(keyName))
        } catch {
            print("ERROR: Failed to copy Key. \(error)")
            try? FileManager.default.removeItem(at: clientPath)
            return nil
        }
        do {
            if self.tlscryptv2 {
                try FileManager.default.copyItem(at: tc2Path, to: clientPath.appendingPathComponent(tc2Name))
            }
        } catch {
            print("ERROR: Failed to copy tls-crypt-v2 key. \(error)")
            try? FileManager.default.removeItem(at: clientPath)
            return nil
        }

        let file = clientConfigContents(name: CN, address: address, port: port, proto: proto)
			
        // Write config
        do {
            try file.write(to: clientPath.appendingPathComponent("config.conf"), atomically: false, encoding: .utf8)
        } catch {
            print("ERROR: Failed to write client config. \(error)")
            try? FileManager.default.removeItem(at: clientPath)
            return nil
        }

        return (CN, clientPath)
    }

    func packageClientConfigDirectory(name: String, at clientPath: URL) -> Bool {
        let outPath = self.clientsPath.appendingPathComponent("\(name).visz")
        do {
            try createVisz(at: clientPath, out: outPath)
        } catch {
            print("Failed to create client config. \(error.localizedDescription)")
            return false
        }
        return true
    }

    func createNewClientConfig(name: String? = nil) -> Bool {
        guard let clientConfig = createClientConfigDirectory(name: name) else {
            return false
        }

        defer {
            if clientConfig.path.exists {
                try? FileManager.default.removeItem(at: clientConfig.path)
            }
        }

        guard packageClientConfigDirectory(name: clientConfig.name, at: clientConfig.path) else {
            return false
        }

        return true
    }

    private func viszEntryType(for fileAttributes: [FileAttributeKey: Any], at inputURL: URL) throws -> ContainerEntryType? {
        guard let typeFromAttributes = fileAttributes[.type] as? FileAttributeType else {
            throw ViszArchiveError.unsupportedFileType(inputURL, nil)
        }

        switch typeFromAttributes {
        case .typeDirectory:
            return .directory
        case .typeRegular:
            return .regular
        case .typeSymbolicLink:
            return nil
        default:
            throw ViszArchiveError.unsupportedFileType(inputURL, typeFromAttributes)
        }
    }

    private func makeViszEntry(for inputURL: URL, archivePath: String) throws -> TarEntry? {
        let fileManager = FileManager.default
        let fileAttributes = try fileManager.attributesOfItem(atPath: inputURL.path)
        guard let entryType = try viszEntryType(for: fileAttributes, at: inputURL) else {
            return nil
        }

        guard !archivePath.isEmpty else {
            throw ViszArchiveError.emptyArchivePath(inputURL)
        }

        var info = TarEntryInfo(name: archivePath, type: entryType)
        info.modificationTime = fileAttributes[.modificationDate] as? Date
        if let posixPermissions = (fileAttributes[.posixPermissions] as? NSNumber)?.intValue {
            info.permissions = Permissions(rawValue: UInt32(truncatingIfNeeded: posixPermissions))
        }

        let entryData: Data?
        if entryType == .regular {
            entryData = try Data(contentsOf: inputURL)
        } else {
            entryData = nil
        }

        return TarEntry(info: info, data: entryData)
    }

    private func collectViszEntries(from inputURL: URL, archivePath: String) throws -> [TarEntry] {
        guard let entry = try makeViszEntry(for: inputURL, archivePath: archivePath) else {
            return []
        }

        var entries = [entry]
        guard entry.info.type == .directory else {
            return entries
        }

        let childURLs = try FileManager.default.contentsOfDirectory(at: inputURL,
                                                                    includingPropertiesForKeys: nil,
                                                                    options: [])
            .sorted {
                if $0.lastPathComponent == $1.lastPathComponent {
                    return $0.path < $1.path
                }
                return $0.lastPathComponent < $1.lastPathComponent
            }

        for childURL in childURLs {
            let childArchivePath = archivePath + "/" + childURL.lastPathComponent
            entries.append(contentsOf: try collectViszEntries(from: childURL, archivePath: childArchivePath))
        }

        return entries
    }

    func createVisz(at inputPath: URL, out outputPath: URL) throws {
        guard inputPath.isDirectoryAndExists else {
            throw ViszArchiveError.inputPathIsNotDirectory(inputPath)
        }
        guard outputPath.pathExtension.lowercased() == "visz" else {
            throw ViszArchiveError.invalidOutputExtension(outputPath)
        }

        let rootArchivePath = inputPath.lastPathComponent
        let entries = try collectViszEntries(from: inputPath, archivePath: rootArchivePath)
        let containerData = TarContainer.create(from: entries, force: .pax)
        let fileName = outputPath.deletingPathExtension().lastPathComponent

        let compressedData = try GzipArchive.archive(
            data: containerData,
            fileName: fileName.isEmpty ? nil : fileName,
            writeHeaderCRC: true
        )
        try compressedData.write(to: outputPath)
    }

    func generateNewConfig() -> Bool {
        // First up, let's check a config isn't already in place
        if loadConfig() {
            print("ERROR: Config already exists, please choose another directory")
            return false
        }

        self.curveName = normalizedCurveName(self.curveName)

        print("Please fill in the information below that will be incorporated into your certificate.")
        print("Some fields have a default value in square brackets, simply press Enter to use these values without entering anything.")
        print("Some fields can be left blank if desired. Enter a '.' only for a field to be left blank.")
        print("---")

        if self.keyAlg == .ecdsa {
            while true {
                if !defaultCurves.contains(self.curveName) {
                    print("WARNING: You have selected a curve OpenVPN may not support.")
                } else {
                    break
                }
                if let input = askQuestion("Continue? [Y/n]:")?.lowercased() {
                    if input == "y" {
                        break
                    }
                    if input == "n" {
                        exit(0)
                    }
                    print("Invalid input, try again.")
                } else {
                    break
                }
            }
        }

        guard let address = askQuestion("Server address, e.g. myserver.mydomain.com:", allowedBlank: false) else {
            print("ERROR: Failed to get address from command line")
            return false
        }
        if !self.serverSANOverrideProvided {
            self.serverSANs = defaultServerSANs(for: address)
        }

        var port: String = defaultPort
        while true {
            if let input = askQuestion("Server Port [\(defaultPort)]:", allowedBlank: false) {
                if let value = Int(input), value > 0, value < 65535 {
                    port = input
                    break
                }
                print("Invalid input, try again.")
            } else {
                port = defaultPort
                break
            }
        }

        var proto: String = defaultProtocol
        while true {
            if let input = askQuestion("Protocol, 1=UDP, 2=TCP [\(defaultProtocol)]:", allowedBlank: false) {
                if let value = Int(input) {
                    if value == 1 {
                        proto = "udp"
                        break
                    }
                    if value == 2 {
                        proto = "tcp"
                        break
                    }
                }
                print("Invalid input, try again.")
            } else {
                proto = defaultProtocol.lowercased()
                break
            }
        }

        var redirectTraffic: Bool = true
        while true {
            if let input = askQuestion("Redirect all traffic through VPN? [Y/n]:")?.lowercased() {
                if input == "y" {
                    redirectTraffic = true
                    break
                }
                if input == "n" {
                    redirectTraffic = false
                    break
                }
                print("Invalid input, try again.")
            } else {
                redirectTraffic = true
                break
            }
        }

        var dns: [String] = []
        let defaultDNSChoice: Int = redirectTraffic ? 1 : 4
        var customDNS = false

        print("Please specify DNS servers to push to connecting clients:")
        print("\t1 - Cloudflare (\(cloudflareDNS.joined(separator: " & ")))")
        print("\t2 - Google (\(googleDNS.joined(separator: " & ")))")
        print("\t3 - OpenDNS (\(openDNS.joined(separator: " & ")))")
        print("\t4 - Local Server (\(localDNS)). A DNS server must run on the VPN server.")
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
                if let input = askQuestion("Enter Custom DNS Servers, comma separated for multiple:", allowedBlank: false) {
                    // Validate
                    var finalValues: [String] = []
                    let values = input.components(separatedBy: ",")
                    var valid = true
                    for value in values {
                        let trimmed = value.strip()
                        if IPAddress(string: trimmed) != nil {
                            finalValues.append(trimmed)
                        } else {
                            print("\(value) is not a valid IP Address.")
                            valid = false
                        }
                    }
                    if valid {
                        dns = finalValues
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
                }
                if input == "n" {
                    self.tlscryptv2 = false
                    break
                }
                print("Invalid input, try again.")
            } else {
                self.tlscryptv2 = true
                break
            }
        }

        var useDefaults: Bool = true
        while true {
            if let input = askQuestion("Would you like to use anonymous defaults for certificate details? [Y/n]:")?.lowercased() {
                if input == "y" {
                    useDefaults = true
                    break
                }
                if input == "n" {
                    useDefaults = false
                    break
                }
                print("Invalid input, try again.")
            } else {
                useDefaults = true
                break
            }
        }

        let subjectForConfig: DistinguishedName?
        if useDefaults {
            subjectForConfig = DistinguishedName(commonName: address)
        } else {
            let CN: String
            if let input = askQuestion("Common Name, e.g. your servers name [\(address)]:", allowedBlank: false) {
                CN = input
            } else {
                CN = address
            }

            // Country
            var country: String?
            if let input = askQuestion("Country Name, 2 letter ISO code [\(defaultCountry)]:") {
                if input != "." {
                    country = input
                }
            } else {
                country = defaultCountry
            }

            // State
            var state: String?
            if let input = askQuestion("State or Province [\(defaultState)]:") {
                if input != "." {
                    state = input
                }
            } else {
                state = defaultState
            }

            // Locality
            var locality: String?
            if let input = askQuestion("Locality Name, e.g. a City [\(defaultLocale)]:") {
                if input != "." {
                    locality = input
                }
            } else {
                locality = defaultLocale
            }

            // ON
            var organization: String?
            if let input = askQuestion("Organisation Name [\(defaultON)]:") {
                if input != "." {
                    organization = input
                }
            } else {
                organization = defaultON
            }

            // OU
            var organizationalUnit: String?
            if let input = askQuestion("Organisation Unit, e.g department [\(defaultOU)]:") {
                if input != "." {
                    organizationalUnit = input
                }
            } else {
                organizationalUnit = defaultOU
            }

            // Email
            var email: String?
            if let input = askQuestion("Email Address [\(defaultEmail)]:") {
                if input != "." {
                    email = input
                }
            } else {
                email = defaultEmail
            }

            subjectForConfig = DistinguishedName(
                commonName: CN,
                localityName: locality,
                stateOrProvinceName: state,
                organizationName: organization,
                organizationalUnitName: organizationalUnit,
                countryName: country,
                email: email
            )
        }
        guard let subjectForConfig else {
            print("ERROR: Failed to create certificate subject.")
            return false
        }

        if !useDefaults && !self.serverSANOverrideProvided {
            while true {
                let suggested = defaultServerSANs(for: address).joined(separator: ",")
                writeStdout("Server certificate SAN entries (comma separated, e.g. DNS:vpn.example.com,IP:203.0.113.10). Suggested: \(suggested). Leave blank for none: ")
                guard let input = readLine() else {
                    self.serverSANs = []
                    break
                }
                let trimmed = input.strip()
                if trimmed.isEmpty || trimmed == "." {
                    self.serverSANs = []
                    break
                }
                guard let parsed = parseServerSANList(trimmed) else {
                    print("Invalid SAN input. Use comma-separated DNS:/IP: values.")
                    continue
                }
                self.serverSANs = parsed
                break
            }
        }

        // Save the config
        var config = subjectDictionary(from: subjectForConfig)
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
        config["serverSANs"] = self.serverSANs
        config["suffix"] = self.suffix

        self.config = config
        self.certificateSubject = subjectForConfig

        // Save to file
        return self.saveConfig()
    }

    func revokeCert(name: String? = nil) -> Bool {
        if !self.pkiPath.isDirectoryAndExists {
            print("ERROR: There are no certificates to revoke.")
            return false
        }
        guard let issuer = self.issuerCA else {
            print("ERROR: No issuer available")
            return false
        }

        let CN: String
        if let name {
            CN = name
        } else if let input = askQuestion("Common Name of certificate to revoke:", allowedBlank: false) {
            CN = input
        } else {
            return false
        }
		
        // Make sure we dont try to revoke ourself
        if CN == "cert" {
            print("ERROR: Cannot revoke this.")
            return false
        }

        // Find the certificate
        let certPath = self.pkiPath.appendingPathComponent("\(CN).crt")
        guard let clientCert = Certificate(withURL: certPath, preferredBacking: .openSSL) else {
            print("ERROR: Failed to load certificate")
            return false
        }

        // Create/Update CRL
        let existingCRL: CertificateRevocationList?
        if self.crlPath.isFileAndExists,
           let crlData = try? String(contentsOf: self.crlPath) {
            do {
                existingCRL = try CertificateRevocationList(pem: crlData)
            } catch {
                print("ERROR: Failed to parse existing CRL. \(error)")
                return false
            }
        } else {
            existingCRL = nil
        }

        let newCRL: CertificateRevocationList
        do {
            newCRL = try issuer.revoke(
                certificate: clientCert,
                existingCRL: existingCRL,
                validity: .days(self.validDays)
            )
        } catch {
            print("ERROR: Failed to create/update CRL. \(error)")
            return false
        }
		
        // Write CRL
        do {
            try newCRL.crlAsPEM.write(to: self.crlPath, atomically: false, encoding: .utf8)
        } catch {
            print("ERROR: Failed to write CRL to disk. \(error)")
            return false
        }

        // Delete PKI and configuration for this user
        do {
            try FileManager.default.removeItem(at: certPath)
        } catch {
            print("ERROR: Failed to remove revoked PKI data. \(error)")
        }
        let keyPath = self.pkiPath.appendingPathComponent("\(CN).key")
        do {
            try FileManager.default.removeItem(at: keyPath)
        } catch {
            print("ERROR: Failed to remove revoked PKI data. \(error)")
        }
        let confPath = self.clientsPath.appendingPathComponent("\(CN).visz")
        if confPath.isFileAndExists {
            do {
                try FileManager.default.removeItem(at: confPath)
            } catch {
                print("ERROR: Failed to remove revoked PKI data. \(error)")
            }
        }

        print()
        print("\"\(CN)\" has been successfully revoked. The CRL file has been saved to \"\(self.crlPath)\".")
        print("Please leave a copy of the CRL file in place if you wish to update it in the future.")
        print()

        if name == nil {
            if let input = askQuestion("Regenerate Server configuration? [Y/n]:", allowedBlank: false)?.lowercased(), input == "y" {
                _ = self.createServerConfig()
            } else {
                _ = self.createServerConfig()
            }
        } else {
            // Blank, so Y
            _ = self.createServerConfig()
        }

        return true
    }
}
