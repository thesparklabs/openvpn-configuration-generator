// Copyright SparkLabs Pty Ltd 2018

#pragma once

using namespace System;
using namespace System::Collections::Generic;

ref class CLI
{
public:
	CLI();
	~CLI();

	enum class OptionType {
		CommonName, Path, KeySize, ValidDays, Unknown
	};
	enum class Mode {
		CreateClient, InitSetup, Help, About, Unknown
	};

	OptionType getOption(String^ option);
	Mode getMode(String^ mode);
	void printUsage();
	void printAbout();

private:
	List<String^>^ OptionTypeStrings;
	List<String^>^ ModeStrings;
};

