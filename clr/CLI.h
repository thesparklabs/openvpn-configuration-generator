// Copyright SparkLabs Pty Ltd 2018

#pragma once

#include "OpenSSLHelper.h"

using namespace System;
using namespace System::Collections::Generic;

ref class CLI
{
public:
	CLI();
	~CLI();

	enum class OptionType {
		CommonName, Path, KeySize, ValidDays, Algorithm, Curve, Suffix, Unknown
	};
	enum class Mode {
		CreateClient, InitSetup, Revoke, ShowCurves, Help, About, Unknown
	};

	OptionType getOption(String^ option);
	Mode getMode(String^ mode);
	OpenSSLHelper::Algorithm getAlgorithm(String^ alg);
	void printUsage();
	void printAbout();
	void showCurves();

private:
	List<String^>^ OptionTypeStrings;
	List<String^>^ ModeStrings;
	List<String^>^ AlgStrings;
};

