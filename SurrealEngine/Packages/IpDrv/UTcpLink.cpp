
#include "Precomp.h"
#include "UTcpLink.h"
#include "VM/ScriptCall.h"
#include "VM/Frame.h"
#include "Package/PackageManager.h"
#include "Engine.h"
#include <algorithm>
#include <cstring>

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
				LinkState() = STATE_Initialized;
				CallEvent(this, EventName::Closed);
			}
			else
			{
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
			ReceiveBuffer.append(buffer, received);
			DataPending() = 1;
			DispatchReceived();
		}
		else if (received == 0)
		{
			Close();
			CallEvent(this, EventName::Closed);
		}
		else if (!WouldBlock())
		{
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
		return;

	if (LinkMode() == MODE_Line)
	{
		size_t pos;
		while ((pos = ReceiveBuffer.find('\n')) != std::string::npos)
		{
			std::string line = ReceiveBuffer.substr(0, pos);
			if (!line.empty() && line.back() == '\r')
				line.pop_back();
			ReceiveBuffer.erase(0, pos + 1);
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
			CallEvent(this, EventName::ReceivedText, { ExpressionValue::StringValue(text) });
		}
	}
	// MODE_Binary isn't auto-dispatched as a ReceivedBinary event yet - ReadBinary() can still
	// be polled manually regardless of ReceiveMode.
}

int UTcpLink::BindPort(int Port, bool bUseNextAvailable)
{
	if (handle == invalid_socket_value)
		return 0;

	sockaddr_in addr;
	memset(&addr, 0, sizeof(sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(Port);

	int result = bind(handle, (const sockaddr*)&addr, sizeof(sockaddr_in));
	if (result == -1)
		return 0;

#ifdef WIN32
	int size = sizeof(sockaddr_in);
#else
	socklen_t size = sizeof(sockaddr_in);
#endif
	result = getsockname(handle, (sockaddr*)&addr, &size);
	if (result == -1)
		return 0;

	return ntohs(addr.sin_port);
}

bool UTcpLink::Listen()
{
	// Server-side listening (hosting) isn't implemented yet - this link is client-connect only.
	return false;
}

bool UTcpLink::Open(const IpAddr& Addr)
{
	if (handle == invalid_socket_value || LinkState() != STATE_Initialized)
		return false;

	sockaddr_in addr;
	memset(&addr, 0, sizeof(sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = Addr.Addr;
	addr.sin_port = Addr.Port;

	int result = connect(handle, (const sockaddr*)&addr, sizeof(sockaddr_in));
	if (result == -1 && !ConnectInProgress())
		return false;

	RemoteAddr() = Addr;
	if (result == -1)
	{
		LinkState() = STATE_Connecting;
	}
	else
	{
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
		return 0;

	std::string msg = Str;
	if (LinkMode() == MODE_Line)
		msg += "\r\n";

	int result = send(handle, msg.c_str(), (int)msg.size(), 0);
	return result == -1 ? 0 : result;
}
