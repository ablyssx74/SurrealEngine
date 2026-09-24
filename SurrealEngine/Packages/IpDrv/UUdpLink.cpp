
#include "Precomp.h"
#include "UUdpLink.h"
#include "VM/ScriptCall.h"
#include "VM/Frame.h"
#include "Package/PackageManager.h"
#include "Engine.h"
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <cerrno>

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

namespace
{
	// Diagnostic: set SE_DEBUG_NET=1 to trace UdpLink send/receive activity.
	static bool DebugNet()
	{
		static const bool debugNet = std::getenv("SE_DEBUG_NET") != nullptr;
		return debugNet;
	}

	static std::string AddrToString(const IpAddr& addr)
	{
		uint32_t a = ntohl((uint32_t)addr.Addr);
		char buf[32];
		snprintf(buf, sizeof(buf), "%u.%u.%u.%u:%u", (a >> 24) & 0xff, (a >> 16) & 0xff, (a >> 8) & 0xff, a & 0xff, ntohs(addr.Port));
		return buf;
	}
}

UUdpLink::UUdpLink(NameString name, UClass* base, ObjectFlags flags) : UInternetLink(name, base, flags)
{
	handle = socket(AF_INET, SOCK_DGRAM, 0);
	if (handle != invalid_socket_value)
	{
#ifdef WIN32
		u_long nonblocking = 1;
		ioctlsocket(handle, FIONBIO, &nonblocking);
#else
		int nonblocking = 1;
		ioctl(handle, FIONBIO, &nonblocking);
#endif
	}
}

UUdpLink::~UUdpLink()
{
	if (handle != invalid_socket_value)
		closesocket(handle);
}

void UUdpLink::Tick(float elapsed)
{
	UInternetLink::Tick(elapsed);

	if (handle == invalid_socket_value)
		return;

	// Drain every pending datagram this tick, queueing each one (with its sender address) for
	// ReadText()/ReadBinary() to poll. UdpLink's original Received* events take a leading IpAddr
	// parameter unlike TcpLink's (connectionless, so the source address matters per-message) -
	// since that exact signature can't be verified against the loaded class metadata from this
	// layer and calling a script event with the wrong argument shape risks a VM-level mismatch,
	// this deliberately sticks to the polling API (which is what server-browser style UnrealScript
	// typically uses anyway) rather than guessing at the event dispatch.
	for (;;)
	{
		char buffer[4096];
		sockaddr_in from;
		memset(&from, 0, sizeof(sockaddr_in));
#ifdef WIN32
		int fromLen = sizeof(sockaddr_in);
#else
		socklen_t fromLen = sizeof(sockaddr_in);
#endif
		int received = recvfrom(handle, buffer, sizeof(buffer), 0, (sockaddr*)&from, &fromLen);
		if (received <= 0)
			break;

		PendingDatagram datagram;
		datagram.From.Addr = from.sin_addr.s_addr;
		datagram.From.Port = from.sin_port;
		datagram.Data.assign(buffer, received);
		ReceiveQueue.push_back(std::move(datagram));
	}

	DataPending() = ReceiveQueue.empty() ? 0 : 1;
}

int UUdpLink::BindPort(int Port, bool bUseNextAvailable)
{
	// See the matching bug/fix note in UTcpLink::BindPort() - bUseNextAvailable was never actually
	// used, so a single EADDRINUSE (e.g. multiple links wanting the same starting port at once)
	// just gave up instead of trying successive ports. Also restores sin_family = AF_INET, which
	// was missing here entirely - bind() on an AF_INET socket with an unset (zeroed) family can
	// fail outright on some platforms, silently, before bUseNextAvailable would even matter.
	const int maxAttempts = (bUseNextAvailable && Port != 0) ? 20 : 1;
	for (int attempt = 0; attempt < maxAttempts; attempt++)
	{
		sockaddr_in addr;
		memset(&addr, 0, sizeof(sockaddr_in));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = INADDR_ANY;
		addr.sin_port = htons(Port + attempt);

		int result = bind(handle, (const sockaddr*)&addr, sizeof(sockaddr_in));
		if (result == -1)
		{
			if (DebugNet())
				fprintf(stderr, "[Net] UdpLink.BindPort(%d) failed (errno=%d), %s\n", Port + attempt, errno,
					attempt + 1 < maxAttempts ? "trying next port" : "giving up");
			continue;
		}

#ifdef WIN32
		int size = sizeof(sockaddr_in);
#else
		socklen_t size = sizeof(sockaddr_in);
#endif
		result = getsockname(handle, (sockaddr*)&addr, &size);
		if (result == -1)
			return 0;

		LocalIP.Addr = addr.sin_addr.s_addr;
		LocalIP.Port = addr.sin_port;

		if (DebugNet())
			fprintf(stderr, "[Net] UdpLink.BindPort: bound to port %d\n", ntohs(addr.sin_port));

		return ntohs(addr.sin_port);
	}

	return 0;
}

int UUdpLink::ReadBinary(IpAddr& Addr, int Count, uint8_t& B)
{
	if (Count <= 0 || ReceiveQueue.empty())
		return 0;

	PendingDatagram& datagram = ReceiveQueue.front();
	Addr = datagram.From;
	int n = std::min<int>(Count, (int)datagram.Data.size());
	memcpy(&B, datagram.Data.data(), n);
	ReceiveQueue.pop_front();
	DataPending() = ReceiveQueue.empty() ? 0 : 1;
	return n;
}

bool UUdpLink::SendBinary(const IpAddr& Addr, int Count, uint8_t B)
{
	if (Count <= 0)
		return false;

	sockaddr_in addr;
	memset(&addr, 0, sizeof(sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = Addr.Addr;
	addr.sin_port = Addr.Port;

	int result = sendto(handle, (const char*)&B, Count, 0, (const sockaddr*)&addr, sizeof(sockaddr_in));
	return result != -1;
}

int UUdpLink::ReadText(IpAddr& Addr, std::string& Str)
{
	if (ReceiveQueue.empty())
		return 0;

	PendingDatagram datagram = std::move(ReceiveQueue.front());
	ReceiveQueue.pop_front();
	Addr = datagram.From;
	Str = std::move(datagram.Data);
	DataPending() = ReceiveQueue.empty() ? 0 : 1;
	return (int)Str.size();
}

bool UUdpLink::SendText(const IpAddr& Addr, const std::string& Str)
{
	if (Str.size() > 0x7ffffff0)
		return false;

	sockaddr_in addr;
	memset(&addr, 0, sizeof(sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = Addr.Addr;
	addr.sin_port = Addr.Port;

	std::string msg = Str;
	if (LinkMode() == MODE_Line)
		msg += "\r\n";

	int result = sendto(handle, msg.c_str(), (int)msg.size(), 0, (const sockaddr*)&addr, sizeof(sockaddr_in));
	return result != -1;
}
