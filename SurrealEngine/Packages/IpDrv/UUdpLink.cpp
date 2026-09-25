
#include "Precomp.h"
#include "UUdpLink.h"
#include "VM/ScriptCall.h"
#include "VM/Frame.h"
#include "Package/PackageManager.h"
#include "Packages/Core/UClass.h"
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

	// For an IpAddr that genuinely came from the OS (e.g. recvfrom()'s source address) - Port is
	// real network byte order here, so this needs the ntohs() conversion to display correctly.
	static std::string AddrToString(const IpAddr& addr)
	{
		uint32_t a = ntohl((uint32_t)addr.Addr);
		char buf[32];
		snprintf(buf, sizeof(buf), "%u.%u.%u.%u:%u", (a >> 24) & 0xff, (a >> 16) & 0xff, (a >> 8) & 0xff, a & 0xff, ntohs(addr.Port));
		return buf;
	}

	// For an IpAddr script constructed itself (e.g. SendText/SendBinary's destination) - confirmed
	// via SE_DEBUG_NET (see the matching fix in UTcpLink::Open()) that script always hands these
	// functions a plain, unswapped host-order port number, not a pre-swapped network-byte-order
	// value - so this must NOT apply ntohs(), unlike AddrToString() above.
	static std::string ScriptAddrToString(const IpAddr& addr)
	{
		uint32_t a = ntohl((uint32_t)addr.Addr);
		char buf[32];
		snprintf(buf, sizeof(buf), "%u.%u.%u.%u:%u", (a >> 24) & 0xff, (a >> 16) & 0xff, (a >> 8) & 0xff, a & 0xff, (unsigned)addr.Port);
		return buf;
	}

	static std::string EscapeForLog(const std::string& s)
	{
		std::string result;
		result.reserve(s.size());
		for (unsigned char c : s)
		{
			if (c == '\\') result += "\\\\";
			else if (c == '"') result += "\\\"";
			else if (c == '\r') result += "\\r";
			else if (c == '\n') result += "\\n";
			else if (c < 0x20 || c >= 0x7f)
			{
				char buf[8];
				snprintf(buf, sizeof(buf), "\\x%02x", c);
				result += buf;
			}
			else result += (char)c;
		}
		return result;
	}

	static std::string ObjLabel(UObject* obj)
	{
		if (!obj)
			return "?";
		std::string className = obj->Class ? obj->Class->Name.ToString() : "?";
		return className + "'" + obj->Name.ToString() + "'";
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
		if (DebugNet())
			fprintf(stderr, "[Net] %s UdpLink received %d bytes from %s: \"%s\"\n", ObjLabel(this).c_str(), received, AddrToString(datagram.From).c_str(), EscapeForLog(datagram.Data).c_str());
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
				fprintf(stderr, "[Net] %s UdpLink.BindPort(%d) failed (errno=%d), %s\n", ObjLabel(this).c_str(), Port + attempt, errno,
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
			fprintf(stderr, "[Net] %s UdpLink.BindPort: bound to port %d\n", ObjLabel(this).c_str(), ntohs(addr.sin_port));

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
	// Bug: same missing byte-order conversion as UTcpLink::Open() - Addr.Port is script's plain
	// host-order port number, not pre-swapped network byte order, so every packet here was
	// silently sent to a byte-swapped destination port instead of the real one. This is exactly
	// why UBrowserServerPing's per-server status queries were going nowhere: they ping each
	// discovered server's real game port (e.g. 7778) via this function.
	addr.sin_port = htons((uint16_t)Addr.Port);

	int result = sendto(handle, (const char*)&B, Count, 0, (const sockaddr*)&addr, sizeof(sockaddr_in));
	if (DebugNet())
		fprintf(stderr, "[Net] %s UdpLink.SendBinary(%d bytes) to %s -> %d\n", ObjLabel(this).c_str(), Count, ScriptAddrToString(Addr).c_str(), result);
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
	// Bug: same missing byte-order conversion as SendBinary()/UTcpLink::Open() above.
	addr.sin_port = htons((uint16_t)Addr.Port);

	std::string msg = Str;
	if (LinkMode() == MODE_Line)
		msg += "\r\n";

	int result = sendto(handle, msg.c_str(), (int)msg.size(), 0, (const sockaddr*)&addr, sizeof(sockaddr_in));
	if (DebugNet())
		fprintf(stderr, "[Net] %s UdpLink.SendText(%d bytes) to %s -> %d: \"%s\"\n", ObjLabel(this).c_str(), (int)msg.size(), ScriptAddrToString(Addr).c_str(), result, EscapeForLog(msg).c_str());
	return result != -1;
}
