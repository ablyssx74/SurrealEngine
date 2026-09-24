
#include "Precomp.h"
#include "UTcpLink.h"
#include "VM/ScriptCall.h"
#include "VM/Frame.h"
#include "Package/PackageManager.h"
#include "Packages/Core/UClass.h"
#include "Engine.h"
#include <algorithm>
#include <cstring>
#include <cstdlib>

#ifdef WIN32
#include <WinSock2.h>
typedef unsigned long in_addr_t;
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <cerrno>
static int closesocket(int fd) { return close(fd); }
#endif

namespace
{
	// ELinkState as declared by IpDrv.TcpLink's original UnrealScript class. This engine has no
	// generic way to look up an UnrealScript enum's ordinal values by name at this layer, so
	// these are hardcoded to the well-established, long-documented values used throughout the
	// UT99/UE1 modding community (unchanged for 25+ years). If some script-side code branches on
	// LinkState in a way that misbehaves, this mapping is the first thing to double check.
	enum ELinkState : uint8_t
	{
		STATE_Initialized = 0,
		STATE_ResolvingHost = 1,
		STATE_Connecting = 2,
		STATE_Listening = 3,
		STATE_Connected = 4,
	};

	static void SetNonBlocking(socket_t handle)
	{
#ifdef WIN32
		u_long nonblocking = 1;
		ioctlsocket(handle, FIONBIO, &nonblocking);
#else
		int nonblocking = 1;
		ioctl(handle, FIONBIO, &nonblocking);
#endif
	}

	static bool WouldBlock()
	{
#ifdef WIN32
		return WSAGetLastError() == WSAEWOULDBLOCK;
#else
		return errno == EWOULDBLOCK || errno == EAGAIN;
#endif
	}

	static bool ConnectInProgress()
	{
#ifdef WIN32
		return WSAGetLastError() == WSAEWOULDBLOCK;
#else
		return errno == EINPROGRESS || errno == EWOULDBLOCK;
#endif
	}

	// Diagnostic: set SE_DEBUG_NET=1 to trace TcpLink connect/send/receive activity.
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

	// Diagnostic: identifies which script class/instance a trace line belongs to - needed to tell
	// apart e.g. concurrent UBrowserGSpyLink instances (one per configured master server) or a
	// server-heartbeat UdpServerUplink connection from an actual browser query, which otherwise
	// look identical in the log.
	static std::string ObjLabel(UObject* obj)
	{
		if (!obj)
			return "?";
		std::string className = obj->Class ? obj->Class->Name.ToString() : "?";
		return className + "'" + obj->Name.ToString() + "'";
	}
}

UTcpLink::UTcpLink(NameString name, UClass* base, ObjectFlags flags) : UInternetLink(name, base, flags)
{
	handle = socket(AF_INET, SOCK_STREAM, 0);
	if (handle != invalid_socket_value)
		SetNonBlocking(handle);
}

UTcpLink::~UTcpLink()
{
	if (handle != invalid_socket_value)
		closesocket(handle);
}

void UTcpLink::Tick(float elapsed)
{
	UInternetLink::Tick(elapsed);

	if (handle == invalid_socket_value)
		return;

	if (LinkState() == STATE_Connecting)
	{
		fd_set writefds, exceptfds;
		FD_ZERO(&writefds);
		FD_ZERO(&exceptfds);
		FD_SET(handle, &writefds);
		FD_SET(handle, &exceptfds);
		timeval tv = { 0, 0 };
		int result = select((int)handle + 1, nullptr, &writefds, &exceptfds, &tv);
		if (result > 0)
		{
			int error = 0;
#ifdef WIN32
			int errlen = sizeof(error);
#else
			socklen_t errlen = sizeof(error);
#endif
			getsockopt(handle, SOL_SOCKET, SO_ERROR, (char*)&error, &errlen);
			if (error != 0 || FD_ISSET(handle, &exceptfds))
			{
				if (DebugNet())
					fprintf(stderr, "[Net] %s TcpLink connect to %s failed (SO_ERROR=%d)\n", ObjLabel(this).c_str(), AddrToString(RemoteAddr()).c_str(), error);
				LinkState() = STATE_Initialized;
				CallEvent(this, EventName::Closed);
			}
			else
			{
				if (DebugNet())
					fprintf(stderr, "[Net] %s TcpLink connected to %s\n", ObjLabel(this).c_str(), AddrToString(RemoteAddr()).c_str());
				LinkState() = STATE_Connected;
				CallEvent(this, EventName::Opened);
			}
		}
	}
	else if (LinkState() == STATE_Connected)
	{
		char buffer[4096];
		int received = recv(handle, buffer, sizeof(buffer), 0);
		if (received > 0)
		{
			if (DebugNet())
				fprintf(stderr, "[Net] %s TcpLink received %d bytes from %s\n", ObjLabel(this).c_str(), received, AddrToString(RemoteAddr()).c_str());
			ReceiveBuffer.append(buffer, received);
			DataPending() = 1;
			DispatchReceived();
		}
		else if (received == 0)
		{
			if (DebugNet())
				fprintf(stderr, "[Net] %s TcpLink connection to %s closed by remote\n", ObjLabel(this).c_str(), AddrToString(RemoteAddr()).c_str());
			Close();
			CallEvent(this, EventName::Closed);
		}
		else if (!WouldBlock())
		{
			if (DebugNet())
				fprintf(stderr, "[Net] %s TcpLink recv() error on connection to %s, closing\n", ObjLabel(this).c_str(), AddrToString(RemoteAddr()).c_str());
			Close();
			CallEvent(this, EventName::Closed);
		}
	}
}

void UTcpLink::DispatchReceived()
{
	// Only auto-fire Received* events in event mode - in manual mode, the data stays in
	// ReceiveBuffer for ReadText()/ReadBinary() to poll instead.
	if (ReceiveMode() != RMODE_Event)
	{
		if (DebugNet())
			fprintf(stderr, "[Net] %s TcpLink data buffered (ReceiveMode=Manual, LinkMode=%d, %d bytes waiting for ReadText/ReadBinary poll)\n", ObjLabel(this).c_str(), (int)LinkMode(), (int)ReceiveBuffer.size());
		return;
	}

	if (LinkMode() == MODE_Line)
	{
		size_t pos;
		while ((pos = ReceiveBuffer.find('\n')) != std::string::npos)
		{
			std::string line = ReceiveBuffer.substr(0, pos);
			if (!line.empty() && line.back() == '\r')
				line.pop_back();
			ReceiveBuffer.erase(0, pos + 1);
			if (DebugNet())
				fprintf(stderr, "[Net] %s TcpLink firing ReceivedLine: \"%s\"\n", ObjLabel(this).c_str(), line.c_str());
			CallEvent(this, EventName::ReceivedLine, { ExpressionValue::StringValue(line) });
		}
		DataPending() = ReceiveBuffer.empty() ? 0 : 1;
	}
	else if (LinkMode() == MODE_Text)
	{
		if (!ReceiveBuffer.empty())
		{
			std::string text = std::move(ReceiveBuffer);
			ReceiveBuffer.clear();
			DataPending() = 0;
			if (DebugNet())
				fprintf(stderr, "[Net] %s TcpLink firing ReceivedText: %d bytes\n", ObjLabel(this).c_str(), (int)text.size());
			CallEvent(this, EventName::ReceivedText, { ExpressionValue::StringValue(text) });
		}
	}
	// MODE_Binary isn't auto-dispatched as a ReceivedBinary event yet - ReadBinary() can still
	// be polled manually regardless of ReceiveMode. (Diagnostic above now reports LinkMode so a
	// debug log makes it possible to tell whether this gap is actually being hit.)
}

int UTcpLink::BindPort(int Port, bool bUseNextAvailable)
{
	if (handle == invalid_socket_value)
		return 0;

	// Bug: bUseNextAvailable was accepted but never actually used - a single failed bind() (e.g.
	// EADDRINUSE because an earlier link on the same port is still open) just gave up. Real UT99
	// script code relies on this to hand out a different local port to each simultaneously-open
	// link that wants the same starting port (e.g. one UBrowserGSpyLink per configured master
	// server, all requesting the same port) - confirmed via SE-Log-LastRun.txt showing the first
	// GSpyLink bind succeeding and every subsequent one failing with "Error binding local port,
	// aborting." at the exact same port. Port 0 means "OS picks any free port", which practically
	// never fails, so retrying only makes sense for an explicit nonzero port.
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
				fprintf(stderr, "[Net] %s TcpLink.BindPort(%d) failed (errno=%d), %s\n", ObjLabel(this).c_str(), Port + attempt, errno,
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

		if (DebugNet())
			fprintf(stderr, "[Net] %s TcpLink.BindPort: bound to port %d\n", ObjLabel(this).c_str(), ntohs(addr.sin_port));

		return ntohs(addr.sin_port);
	}

	return 0;
}

bool UTcpLink::Listen()
{
	// Server-side listening (hosting) isn't implemented yet - this link is client-connect only.
	return false;
}

bool UTcpLink::Open(const IpAddr& Addr)
{
	if (DebugNet())
		fprintf(stderr, "[Net] %s TcpLink.Open(%s) called (handle %s, LinkState=%d, raw Addr.Port=%d)\n",
			ObjLabel(this).c_str(), AddrToString(Addr).c_str(), handle != invalid_socket_value ? "valid" : "INVALID", (int)LinkState(), (int)Addr.Port);

	if (handle == invalid_socket_value || LinkState() != STATE_Initialized)
	{
		if (DebugNet())
			fprintf(stderr, "[Net] %s TcpLink.Open() rejected (bad handle or not in Initialized state)\n", ObjLabel(this).c_str());
		return false;
	}

	sockaddr_in addr;
	memset(&addr, 0, sizeof(sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = Addr.Addr;
	addr.sin_port = Addr.Port;

	int result = connect(handle, (const sockaddr*)&addr, sizeof(sockaddr_in));
	if (result == -1 && !ConnectInProgress())
	{
		if (DebugNet())
#ifdef WIN32
			fprintf(stderr, "[Net] %s TcpLink connect() to %s failed immediately (WSAError=%d)\n", ObjLabel(this).c_str(), AddrToString(Addr).c_str(), WSAGetLastError());
#else
			fprintf(stderr, "[Net] %s TcpLink connect() to %s failed immediately (errno=%d %s)\n", ObjLabel(this).c_str(), AddrToString(Addr).c_str(), errno, strerror(errno));
#endif
		return false;
	}

	RemoteAddr() = Addr;
	if (result == -1)
	{
		if (DebugNet())
			fprintf(stderr, "[Net] %s TcpLink connect() to %s in progress (non-blocking)\n", ObjLabel(this).c_str(), AddrToString(Addr).c_str());
		LinkState() = STATE_Connecting;
	}
	else
	{
		if (DebugNet())
			fprintf(stderr, "[Net] %s TcpLink connected to %s immediately\n", ObjLabel(this).c_str(), AddrToString(Addr).c_str());
		LinkState() = STATE_Connected;
		CallEvent(this, EventName::Opened);
	}
	return true;
}

bool UTcpLink::Close()
{
	if (handle != invalid_socket_value)
	{
		closesocket(handle);
		handle = socket(AF_INET, SOCK_STREAM, 0);
		if (handle != invalid_socket_value)
			SetNonBlocking(handle);
	}
	LinkState() = STATE_Initialized;
	ReceiveBuffer.clear();
	DataPending() = 0;
	return true;
}

bool UTcpLink::IsConnected()
{
	return LinkState() == STATE_Connected;
}

int UTcpLink::ReadBinary(int Count, uint8_t& B)
{
	if (Count <= 0 || ReceiveBuffer.empty())
		return 0;

	int n = std::min<int>(Count, (int)ReceiveBuffer.size());
	memcpy(&B, ReceiveBuffer.data(), n);
	ReceiveBuffer.erase(0, n);
	DataPending() = ReceiveBuffer.empty() ? 0 : 1;
	return n;
}

int UTcpLink::SendBinary(int Count, uint8_t B)
{
	if (LinkState() != STATE_Connected || Count <= 0)
		return 0;

	int result = send(handle, (const char*)&B, Count, 0);
	return result == -1 ? 0 : result;
}

int UTcpLink::ReadText(std::string& Str)
{
	if (ReceiveBuffer.empty())
		return 0;

	Str = std::move(ReceiveBuffer);
	int count = (int)Str.size();
	ReceiveBuffer.clear();
	DataPending() = 0;
	return count;
}

int UTcpLink::SendText(const std::string& Str)
{
	if (LinkState() != STATE_Connected)
	{
		if (DebugNet())
			fprintf(stderr, "[Net] %s TcpLink.SendText() called while not connected (LinkState=%d), ignored\n", ObjLabel(this).c_str(), (int)LinkState());
		return 0;
	}

	std::string msg = Str;
	if (LinkMode() == MODE_Line)
		msg += "\r\n";

	int result = send(handle, msg.c_str(), (int)msg.size(), 0);
	if (DebugNet())
		fprintf(stderr, "[Net] %s TcpLink.SendText(%d bytes) -> %d\n", ObjLabel(this).c_str(), (int)msg.size(), result);
	return result == -1 ? 0 : result;
}
