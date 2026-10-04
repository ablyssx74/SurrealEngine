
#include "Precomp.h"
#include "UnrealURL.h"
#include "Engine.h"
#include "Package/PackageManager.h"
#include "Utils/StrTools.h"
#include <cstdlib>

UnrealURL::UnrealURL(const UnrealURL& baseURL, const UnrealURL& nextURL)
{
	// To do: this also needs to be able to handle fully qualified URLs for network support

	*this = baseURL;

	// Pass options from the nextURL to the base one
	Map = nextURL.Map;
	Portal = nextURL.Portal;

	for (auto& option : nextURL.Options)
		AddOrReplaceOption(option);

	/*
	// Unreal uses relative urls
	if (Map.size() > 8 && Map.substr(0, 8) == "..\\maps\\")
		Map = Map.substr(8);
	*/
}

UnrealURL::UnrealURL(std::string urlString)
{
	// Expected url format on a local game:
	// mapname[#teleporttag][?key1=value1[?key2=value2]...]
	// Or in case of Klingon Honor Guard
	// mapname[/teleporttag][?key1=value1[?key2=value2]...]
	// Note that the options and the teleport tag can be in arbitrary places, as long as the map name comes first.

	// Trim the url string of whitespaces
	// Fixes the crash during the transition from Temple of Vandora to The Trench in Unreal
	// Due to the exit teleporter pointing to " trench" (with the whitespace at the beginning)
	urlString.erase(urlString.find_last_not_of(' ') + 1);
	urlString.erase(0, urlString.find_first_not_of(' '));

	// Bug: this never parsed a "protocol://host[:port]" prefix at all - a real join URL like
	// "unreal://45.59.162.13:7778?Name=ablyss?Class=..." (built by
	// UBrowserServerGrid.JoinServer() when double-clicking a server in the browser) got treated
	// as one giant bare map name up to the first '/', '?' or '#' it contained - which is the
	// FIRST '/' of "unreal://" itself, so Map ended up as literally "unreal:" and the actual
	// host/port got swallowed into Portal instead of ever reaching Host/Port. That's exactly why
	// joining any server crashed with "Could not open .../Maps/unreal:.unr" - it tried to load a
	// local map file literally named that instead of connecting anywhere.
	size_t schemePos = urlString.find("://");
	if (schemePos != std::string::npos)
	{
		Protocol = urlString.substr(0, schemePos);

		std::string rest = urlString.substr(schemePos + 3);
		size_t hostEndPos = StrTools::find_first_of_any(rest, "?/#");
		std::string hostPort = rest.substr(0, hostEndPos);

		size_t colonPos = hostPort.find(':');
		if (colonPos != std::string::npos)
		{
			Host = hostPort.substr(0, colonPos);
			Port = std::atoi(hostPort.substr(colonPos + 1).c_str());
		}
		else
		{
			Host = hostPort;
		}

		urlString = (hostEndPos != std::string::npos) ? rest.substr(hostEndPos) : std::string();
	}

	size_t mapNamePos = StrTools::find_first_of_any(urlString, "?/#");

	Map = urlString.substr(0, mapNamePos);

	if (mapNamePos != std::string::npos)
	{
		// We need to parse all options individually
		char paramType = urlString[mapNamePos]; // Can be '/', '#' or '?'
		std::string allParams = urlString.substr(mapNamePos + 1);

		auto nextParamPos = StrTools::find_first_of_any(allParams, "?/#");

		do
		{
			if (paramType == '#' || paramType == '/')
				Portal = allParams.substr(0, nextParamPos);
			else if (paramType == '?')
			{
				auto optionStr = allParams.substr(0, nextParamPos);
				AddOrReplaceOption(optionStr);
			}

			if (nextParamPos != std::string::npos)
				paramType = allParams[nextParamPos];

			allParams = allParams.substr(nextParamPos + 1);
			nextParamPos = StrTools::find_first_of_any(allParams, "?/#");
		} while (nextParamPos != std::string::npos);
	}
}

void UnrealURL::AddOrReplaceOption(const std::string& newvalue)
{
	size_t pos = newvalue.find('=');
	if (pos != std::string::npos)
	{
		std::string name = newvalue.substr(0, pos);
		for (char& c : name) c = std::tolower(c);
		for (std::string& option : Options)
		{
			if (option.size() >= name.size() + 1 && option[name.size()] == '=')
			{
				std::string key = option.substr(0, name.size());
				for (char& c : key) c = std::tolower(c);
				if (key == name)
				{
					option = newvalue;
					return;
				}
			}
		}
		Options.push_back(newvalue);
	}
	else
	{
		std::string name = newvalue;
		for (char& c : name) c = std::tolower(c);
		for (std::string& option : Options)
		{
			if (option.size() == name.size())
			{
				std::string key = option;
				for (char& c : key) c = std::tolower(c);
				if (key == name)
				{
					option = newvalue;
					return;
				}
			}
		}
		Options.push_back(newvalue);
	}
}

bool UnrealURL::HasOption(const std::string& name) const
{
	for (const std::string& option : Options)
	{
		if ((option.size() >= name.size() + 1 && option[name.size()] == '=') || option.size() == name.size())
		{
			std::string key = option.substr(0, name.size());
			for (char& c : key) c = std::tolower(c);
			if (key == name)
				return true;
		}
	}
	return false;
}

std::string UnrealURL::GetOption(std::string name) const
{
	for (char& c : name) c = std::tolower(c);

	for (const std::string& option : Options)
	{
		if (option.size() >= name.size() + 1 && option[name.size()] == '=')
		{
			std::string key = option.substr(0, name.size());
			for (char& c : key) c = std::tolower(c);
			if (key == name)
				return option.substr(name.size() + 1);
		}
	}
	return {};
}

std::string UnrealURL::GetAddressURL() const
{
	return Host + ":" + std::to_string(Port);
}

std::string UnrealURL::GetOptions() const
{
	std::string result;
	for (const std::string& option : Options)
	{
		result += "?";
		result += option;
	}
	return result;
}

std::string UnrealURL::GetPortal() const
{
	return Portal;
}

std::string UnrealURL::ToString() const
{
	std::string result;

	if (Protocol != "unreal")
	{
		result += Protocol;
		result += ":";
		if (!Host.empty())
			result += "//";
	}

	if (!Host.empty() || Port != 7777)
	{
		result += Host;
		result += ":";
		result += std::to_string(Port);
		result += "/";
	}

	result += Map;
	result += GetOptions();
	result += GetPortal();

	return result;
}

bool UnrealURL::Empty() const
{
	return Map.empty() && Portal.empty() && Options.empty();
}

void UnrealURL::Clear()
{
	Map.clear();
	Portal.clear();
	Options.clear();
}

