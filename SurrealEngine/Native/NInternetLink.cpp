
#include "Precomp.h"
#include "NInternetLink.h"
#include "VM/NativeFunc.h"
#include "Packages/IpDrv/UInternetLink.h"
#include "Utils/Logger.h"
#include <cstdint>

namespace
{
	// GameSpy's "secure"/"validate" challenge-response, aka gsseckey/gsmsalg - the algorithm every
	// GameSpy-SDK-based master server (and every client that wants a real server list back) has to
	// implement identically. Ported from Luigi Auriemma's gsmsalg 0.3.3 (GPLv2), the documented,
	// widely-cited reference implementation for this exact protocol - see e.g.
	// https://github.com/devzspy/GameSpy-Openspy-Core/blob/master/common/gsmsalg.cpp
	// enctype 0 (plain, no post-processing step) is what older games like UT99 use.
	static char GsValFunc(int reg)
	{
		if (reg < 26) return (char)(reg + 'A');
		if (reg < 52) return (char)(reg + 'G');
		if (reg < 62) return (char)(reg - 4);
		if (reg == 62) return '+';
		if (reg == 63) return '/';
		return 0;
	}

	static std::string GsSecKey(const std::string& src, const std::string& key)
	{
		if (src.empty() || src.size() > 65 || key.empty())
			return {};

		uint8_t enctmp[256];
		for (int i = 0; i < 256; i++)
			enctmp[i] = (uint8_t)i;

		uint8_t a = 0;
		for (int i = 0; i < 256; i++)
		{
			a = (uint8_t)(a + enctmp[i] + (uint8_t)key[i % key.size()]);
			uint8_t x = enctmp[a];
			enctmp[a] = enctmp[i];
			enctmp[i] = x;
		}

		uint8_t tmp[66] = {};
		uint8_t b = 0;
		a = 0;
		size_t size = 0;
		for (; size < src.size(); size++)
		{
			a = (uint8_t)(a + (uint8_t)src[size] + 1);
			uint8_t x = enctmp[a];
			b = (uint8_t)(b + x);
			uint8_t y = enctmp[b];
			enctmp[b] = x;
			enctmp[a] = y;
			tmp[size] = (uint8_t)((uint8_t)src[size] ^ enctmp[(uint8_t)(x + y)]);
		}
		for (; size % 3; size++)
			tmp[size] = 0;

		std::string result;
		result.reserve((size * 4) / 3 + 1);
		for (size_t i = 0; i < size; i += 3)
		{
			uint8_t x = tmp[i], y = tmp[i + 1], z = tmp[i + 2];
			result += GsValFunc(x >> 2);
			result += GsValFunc(((x & 3) << 4) | (y >> 4));
			result += GsValFunc(((y & 15) << 2) | (z >> 6));
			result += GsValFunc(z & 63);
		}
		return result;
	}

	// Per-game GameSpy SDK secret key ("gamekey"/"cipher"), sourced from 333networks' own master
	// server config (data/SupportedGames.json in their Masterserver-Qt5 repo) - they need the exact
	// same key to run their own compatible master server implementation. This engine only ever
	// plays "ut" (Unreal Tournament), so that's the only one implemented here.
	static const char* GameKeyFor(const std::string& gameName)
	{
		if (gameName == "ut")
			return "Z5Nfb0";
		return nullptr;
	}
}

void NInternetLink::RegisterFunctions()
{
	RegisterVMNativeFunc_1("InternetLink", "GetLastError", &NInternetLink::GetLastError, 0);
	RegisterVMNativeFunc_1("InternetLink", "GetLocalIP", &NInternetLink::GetLocalIP, 0);
	RegisterVMNativeFunc_2("InternetLink", "IpAddrToString", &NInternetLink::IpAddrToString, 0);
	RegisterVMNativeFunc_1("InternetLink", "IsDataPending", &NInternetLink::IsDataPending, 0);
	RegisterVMNativeFunc_6("InternetLink", "ParseURL", &NInternetLink::ParseURL, 0);
	RegisterVMNativeFunc_1("InternetLink", "Resolve", &NInternetLink::Resolve, 0);
	RegisterVMNativeFunc_3("InternetLink", "StringToIpAddr", &NInternetLink::StringToIpAddr, 0);
	RegisterVMNativeFunc_3("InternetLink", "Validate", &NInternetLink::Validate, 0);
}

void NInternetLink::GetLastError(UObject* Self, int& ReturnValue)
{
	ReturnValue = Self->Cast<UInternetLink>(Self)->GetLastError();
}

void NInternetLink::GetLocalIP(UObject* Self, IpAddr& Arg)
{
	Arg = Self->Cast<UInternetLink>(Self)->GetLocalIP();
}

void NInternetLink::IsDataPending(UObject* Self, BitfieldBool& ReturnValue)
{
	ReturnValue = Self->Cast<UInternetLink>(Self)->IsDataPending();
}

void NInternetLink::Resolve(UObject* Self, const std::string& Domain)
{
	Self->Cast<UInternetLink>(Self)->Resolve(Domain);
}

void NInternetLink::IpAddrToString(UObject* Self, const IpAddr& Arg, std::string& ReturnValue)
{
	ReturnValue = Self->Cast<UInternetLink>(Self)->IpAddrToString(Arg);
}

void NInternetLink::StringToIpAddr(UObject* Self, const std::string& Str, IpAddr& Addr, BitfieldBool& ReturnValue)
{
	ReturnValue = Self->Cast<UInternetLink>(Self)->StringToIpAddr(Str, Addr);
}

void NInternetLink::ParseURL(UObject* Self, const std::string& URL, std::string& Addr, int& Port, std::string& LevelName, std::string& EntryName, BitfieldBool& ReturnValue)
{
	LogUnimplemented("InternetLink.ParseURL");
	ReturnValue = false;
}

void NInternetLink::Validate(UObject* Self, const std::string& ValidationString, const std::string& GameName, std::string& ReturnValue)
{
	const char* gameKey = GameKeyFor(GameName);
	if (!gameKey)
	{
		LogUnimplemented("InternetLink.Validate for GameName '" + GameName + "'");
		ReturnValue = "";
		return;
	}

	ReturnValue = GsSecKey(ValidationString, gameKey);
}
