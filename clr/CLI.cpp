// Copyright SparkLabs Pty Ltd 2018

#include "stdafx.h"
#include "CLI.h"

CLI::CLI()
{
	OptionTypeStrings = gcnew List<String^>(7);
	OptionTypeStrings->Add("--name");
	OptionTypeStrings->Add("--path");
	OptionTypeStrings->Add("--keysize");
	OptionTypeStrings->Add("--days");
	OptionTypeStrings->Add("--algorithm");
	OptionTypeStrings->Add("--curve");
	OptionTypeStrings->Add("--suffix");

	ModeStrings = gcnew List<String^>(7);
	ModeStrings->Add("client");
	ModeStrings->Add("init");
	ModeStrings->Add("revoke");
	ModeStrings->Add("--show-curves");
	ModeStrings->Add("--help");
	ModeStrings->Add("--about");

	AlgStrings = gcnew List<String^>(3);
	AlgStrings->Add("rsa");
	AlgStrings->Add("ecdsa");
	AlgStrings->Add("eddsa");
}

CLI::~CLI()
{
}

CLI::OptionType CLI::getOption(String ^ option)
{
	if (OptionTypeStrings->Contains(option)) {
		int raw = OptionTypeStrings->IndexOf(option);
		return static_cast<OptionType>(raw);
	}
	return OptionType::Unknown;
}

CLI::Mode CLI::getMode(String ^ mode)
{
	if (ModeStrings->Contains(mode)) {
		int raw = ModeStrings->IndexOf(mode);
		return static_cast<Mode>(raw);
	}
	return Mode::Unknown;
}

OpenSSLHelper::Algorithm CLI::getAlgorithm(String^ alg)
{
	if (AlgStrings->Contains(alg)) {
		int raw = AlgStrings->IndexOf(alg);
		return static_cast<OpenSSLHelper::Algorithm>(raw);
	}
	throw gcnew Exception("Unknown Algorithm: " + alg);
}

void CLI::printUsage()
{
	String^ name = System::Reflection::Assembly::GetEntryAssembly()->GetName()->Name;
	Console::WriteLine("");
	Console::WriteLine(String::Format("Usage: {0} init", name));
	Console::WriteLine("Initialise configuration, creates server configuration");
	Console::WriteLine("Optional:");
	Console::WriteLine("  --path DIR      Directory configurations are stored (Current Directory default)");
	Console::WriteLine("  --keysize size  Change Keysize (2048 default)");
	Console::WriteLine("  --days days     Days certificates are valid (3650 default)");
	Console::WriteLine("  --algorithm (rsa|ecdsa|eddsa) Algorithm to use (RSA default)");
	Console::WriteLine("                                ECDSA defaults to secp384r1. EDDSA defaults to ED25519");
	Console::WriteLine("  --curve curve_name            ECDSA/EDDSA curve to use");
	Console::WriteLine("  --suffix suffix  Appends suffix to server file names. Simplifies running multiple servers slightly.");
	Console::WriteLine("");
	Console::WriteLine(String::Format("Usage: {0} client", name));
	Console::WriteLine("Creates client configurations");
	Console::WriteLine("Optional:");
	Console::WriteLine("  --path DIR      Directory configurations are stored (Current Directory default)");
	Console::WriteLine("  --name NAME     Prefill Common Name");
	Console::WriteLine("");
	Console::WriteLine(String::Format("Usage: {0} revoke", name));
	Console::WriteLine("Revoke a client and create/update the CRL");
	Console::WriteLine("Optional:");
	Console::WriteLine("  --path DIR      Directory configurations are stored (Current Directory default)");
	Console::WriteLine("  --name NAME     Prefill Common Name");
	Console::WriteLine("");
	Console::WriteLine(String::Format("Usage: {0} --show-curves", name));
	Console::WriteLine("Show available ECDSA/EdDSA curves");
	Console::WriteLine("");
	Console::WriteLine(String::Format("Usage: {0} --help", name));
	Console::WriteLine("Displays this information");
	Console::WriteLine("");
	Console::WriteLine(String::Format("Usage: {0} --about", name));
	Console::WriteLine("Displays information about this tool");
}

void CLI::printAbout() 
{
	String^ name = System::Reflection::Assembly::GetEntryAssembly()->GetName()->Name;
	Console::WriteLine("");
	Console::WriteLine(String::Format("{0} Tool", name));
	Console::WriteLine("Using " + OpenSSLHelper::OpenSSLVersion());
	Console::WriteLine("");
	Console::WriteLine("Copyright SparkLabs Pty Ltd 2018");
	Console::WriteLine("Licensed under Creative Commons Attribution-NoDerivatives 4.0 International (CC BY-ND 4.0)");
	Console::WriteLine("Portions of the code included in or with this tool may contain, or may be derived from, third-party code, including without limitation, open source software. All use of third-party software is subject to and governed by the respective licenses for the third-party software. These licenses are available at https://github.com/thesparklabs/openvpn-configuration-generator/blob/master/LICENSE");
}

void CLI::showCurves()
{
	List<String^>^ edCurves = OpenSSLHelper::GetEdCurves();
	Console::WriteLine("EdDSA Curves:");
	for each (String ^ ed in edCurves) {
		Console::WriteLine("\t" + ed);
	}
	Console::WriteLine("NOTE: EdDSA support requires OpenVPN 2.4.7+, OpenSSL 1.1.1+ and Viscosity 1.8.2+.");
	Console::WriteLine();

	List<String^>^ ecCurves = OpenSSLHelper::GetECCurves();

	Console::WriteLine("ECDSA Curves:");
	for each (String ^ ec in ecCurves) {
		Console::WriteLine("\t" + ec);
	}
	Console::WriteLine("NOTE: Not all curves may be supported.");
	Console::WriteLine("Check 'openvpn --show-curves' on your server and ensure you are using the latest verison of Viscosity.");
}
