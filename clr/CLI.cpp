// Copyright SparkLabs Pty Ltd 2018

#include "stdafx.h"
#include "CLI.h"

CLI::CLI()
{
	OptionTypeStrings = gcnew List<String^>(5);
	OptionTypeStrings->Add("--name");
	OptionTypeStrings->Add("--path");
	OptionTypeStrings->Add("--keysize");
	OptionTypeStrings->Add("--days");

	ModeStrings = gcnew List<String^>(2);
	ModeStrings->Add("client");
	ModeStrings->Add("init");
	ModeStrings->Add("revoke");
	ModeStrings->Add("--help");
	ModeStrings->Add("--about");
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
	Console::WriteLine("Portions of the code included in or with this tool may container, or may be derived from, third-party code, including without limitation, open source software. All use of third-party software is subject to and governed by the respective licenses for the third-party software. These licenses are available at https://github.com/thesparklabs/openvpn-configuration-generator/blob/master/LICENSE");
}
