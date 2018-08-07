// Copyright SparkLabs Pty Ltd 2018

#pragma once

#include "OpenSSLHelper.h"

using namespace System;
using namespace System::Collections::Generic;
using namespace ICSharpCode::SharpZipLib::GZip;
using namespace ICSharpCode::SharpZipLib::Tar;
using namespace Newtonsoft::Json;
using namespace System::IO;


ref class Interactive
{
public:
	Interactive(String^ path, int keySize, int validDays);

	bool LoadConfig();
	bool SaveConfig();
	bool CreateNewIssuer();
	bool CreateDH();
	bool CreateServerConfig();
	bool CreateNewClientConfig(String^ name);
	bool GenerateNewConfig();

private:
	String ^ defaultCountry = "AU";
	String ^ defaultState = "NSW";
	String ^ defaultLocale = "Sydney";
	String ^ defaultON = "My Company";
	String ^ defaultOU = "Networks";
	String ^ defaultCN = "My OpenVPN Server";
	String ^ defaultEmail = "me@host.domain";

	String ^ defaultProtocol = "UDP";
	String ^ defaultDNS = "10.8.0.1";
	String ^ defaultPort = "1194";

	String ^ path;
	String ^ configPath;
	String ^ pkiPath;
	String ^ caPath;
	String ^ keyPath;
	String ^ clientsPath;

	CertificateSubject^ cSubject;
	Dictionary<String^, Object^>^ config;
	Identity^ Issuer;

	static array<String^>^ protectedCNs = gcnew array<String^>(2) { "server", "ca" };

	int keySize;
	int validDays;
	int _serial = 0;
	property int Serial {
		int get() {
			int ss = _serial + 1;
			_serial = ss;
			return ss;
		}
	}

	String^ askQuestion(String^ question, bool allowedBlank);
	String^ askQuestion(String^ question, bool allowedBlank, bool hasDefault);
	bool saveIdentity(Identity^ identity, String^ name);
	bool createNewClientIdentity(String^ name);
	bool createNewServerIdentity();
	bool createVisz(String^ fileName, String^ folder);
	bool verifyRequirements();
};


