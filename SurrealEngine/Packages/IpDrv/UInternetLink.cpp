
#include "Precomp.h"
#include "UInternetLink.h"
#include "VM/ScriptCall.h"
#include "VM/Frame.h"
#include "Package/PackageManager.h"
#include "Packages/Core/UFunction.h"
#include "Engine.h"
#include <cstdlib>

#ifdef WIN32
#include <WinSock2.h>
typedef unsigned long in_addr_t;
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
static int closesocket(int fd) { return close(fd); }
#endif

UInternetLink::~UInternetLink()
{
	if (Thread.joinable())
		Thread.join();
}

void UInternetLink::Tick(float elapsed)
{
	UInternetInfo::Tick(elapsed);

	std::unique_lock<std::mutex> lock(Mutex);
	IpAddr resolvedAddr = ResolvedAddr;
	int resolveStatus = ResolveStatus;
	if (resolveStatus > 1)
		ResolveStatus = 0;
	lock.unlock();

	if (ResolveStatus == 2)
	{
		UFunction* func = FindEventFunction(this, "Resolved");
		if (func)
		{
			UStructProperty prop({}, nullptr, ObjectFlags::NoFlags);
			prop.Struct = UObject::Cast<UStructProperty>(func->Properties[0])->Struct;
			CallEvent(this, EventName::Resolved, { ExpressionValue::Variable(&resolvedAddr, &prop) });
		}
	}
	else if (ResolveStatus == 3)
	{
		CallEvent(this, EventName::ResolveFailed);
	}
}

int UInternetLink::GetLastError()
{
	std::unique_lock<std::mutex> lock(Mutex);
	return LastError;
}

IpAddr UInternetLink::GetLocalIP()
{
	return LocalIP;
}

bool UInternetLink::IsDataPending()
{
	return DataPending() != 0;
}

void UInternetLink::Resolve(const std::string& Domain)
{
	// Diagnostic: set SE_DEBUG_NET=1 to trace DNS resolution requests/results. Note Port is
	// unconditionally set to 7777 (the default UT game port) here regardless of what the caller
	// actually wants to connect to afterward - fine if the calling script always overwrites Port
	// itself before using the resolved address, wrong (and worth fixing) if it doesn't and this
	// silently sends every resolved connection attempt at the wrong port.
	static const bool debugNet = std::getenv("SE_DEBUG_NET") != nullptr;

	std::unique_lock<std::mutex> lock(Mutex);
	if (ResolveStatus != 1)
	{
		ResolveStatus = 1;

		if (Thread.joinable())
			Thread.detach();

		std::string _address = Domain;
		auto threadMain = [this, _address, debugNet]()
			{
				if (debugNet)
					fprintf(stderr, "[Net] Resolving \"%s\"...\n", _address.c_str());

				in_addr_t ipv4_address = inet_addr(_address.c_str());
				if (ipv4_address == INADDR_NONE)
				{
					hostent* host = gethostbyname(_address.c_str());
					if (host)
					{
						ipv4_address = *((in_addr_t*)host->h_addr_list[0]);
					}
				}

				if (debugNet)
				{
					if (ipv4_address != INADDR_NONE)
					{
						uint8_t* b = (uint8_t*)&ipv4_address;
						fprintf(stderr, "[Net] Resolved \"%s\" -> %u.%u.%u.%u (port defaults to 7777 unless the caller overrides it)\n",
							_address.c_str(), b[0], b[1], b[2], b[3]);
					}
					else
					{
						fprintf(stderr, "[Net] Failed to resolve \"%s\"\n", _address.c_str());
					}
				}

				std::unique_lock<std::mutex> lock2(Mutex);
				ResolveStatus = (ipv4_address != INADDR_NONE) ? 2 : 3;
				ResolvedAddr.Addr = ipv4_address;
				ResolvedAddr.Port = htons(7777);
			};

		Thread = std::thread(threadMain);
	}
}

std::string UInternetLink::IpAddrToString(const IpAddr& Arg)
{
	uint32_t addr_long = (uint32_t)ntohl(Arg.Addr);
	return
		std::to_string((addr_long & 0xff000000) >> 24) + "." +
		std::to_string((addr_long & 0x00ff0000) >> 16) + "." +
		std::to_string((addr_long & 0x0000ff00) >> 8) + "." +
		std::to_string(addr_long & 0x000000ff) + ":" +
		std::to_string(ntohs(Arg.Port));
}

bool UInternetLink::StringToIpAddr(const std::string& Str, IpAddr& Addr)
{
	size_t portStart = Str.find(':');
	if (portStart == std::string::npos)
		portStart = Str.size();
	in_addr_t ipv4_address = inet_addr(Str.substr(0, portStart).c_str());
	Addr.Addr = ipv4_address;
	if (portStart == std::string::npos)
		Addr.Port = htons(7777);
	else
		Addr.Port = htons(std::atoi(Str.substr(portStart + 1).c_str()));
	return ipv4_address != INADDR_NONE && Addr.Port != 0 && Addr.Port != 0xffff;
}
