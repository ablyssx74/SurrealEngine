
#include "Precomp.h"
#include "RemoteConnection.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>

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
#include <cerrno>
static int closesocket(remote_socket_t fd) { return close(fd); }
#endif

namespace
{
	// Diagnostic: set SE_DEBUG_NET=1 to trace this connection attempt, same flag the rest of the
	// networking code (UTcpLink/UUdpLink) already uses.
	static bool DebugNet()
	{
		static const bool debugNet = std::getenv("SE_DEBUG_NET") != nullptr;
		return debugNet;
	}
}

RemoteConnection::~RemoteConnection()
{
	Disconnect();
}

bool RemoteConnection::Connect(const std::string& host, int port)
{
	Disconnect();

	handle = socket(AF_INET, SOCK_DGRAM, 0);
	if (handle == remote_invalid_socket_value)
	{
		if (DebugNet())
			fprintf(stderr, "[Net] RemoteConnection: socket() failed\n");
		return false;
	}

#ifdef WIN32
	u_long nonblocking = 1;
	ioctlsocket(handle, FIONBIO, &nonblocking);
#else
	int nonblocking = 1;
	ioctl(handle, FIONBIO, &nonblocking);
#endif

	in_addr_t addr = inet_addr(host.c_str());
	if (addr == INADDR_NONE)
	{
		hostent* he = gethostbyname(host.c_str());
		if (!he)
		{
			if (DebugNet())
				fprintf(stderr, "[Net] RemoteConnection: could not resolve host \"%s\"\n", host.c_str());
			Disconnect();
			return false;
		}
		addr = *((in_addr_t*)he->h_addr_list[0]);
	}

	sockaddr_in dest;
	memset(&dest, 0, sizeof(sockaddr_in));
	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = addr;
	dest.sin_port = htons((uint16_t)port);

	// connect() on a UDP socket does not perform any handshake with the remote host - it just
	// fixes the destination address so send()/recv() can be used instead of sendto()/recvfrom(),
	// and means the OS will surface an ICMP port-unreachable (e.g. "nothing is listening there")
	// as a later send()/recv() error instead of it being silently swallowed.
	if (::connect(handle, (const sockaddr*)&dest, sizeof(sockaddr_in)) == -1)
	{
		if (DebugNet())
			fprintf(stderr, "[Net] RemoteConnection: connect() to %s:%d failed\n", host.c_str(), port);
		Disconnect();
		return false;
	}

	remoteHost = host;
	remotePort = port;

	if (DebugNet())
		fprintf(stderr, "[Net] RemoteConnection: socket ready, target %s:%d\n", host.c_str(), port);

	// Placeholder probe, NOT a real UT99 protocol packet - this engine has no implementation of
	// UE1's actual netcode yet (packet header framing, channels/bunches, the control-channel
	// handshake are all unimplemented - see Docs/Status.md and RemoteConnection.h). Sending
	// something, even something wrong, makes a join attempt observable (via this log and in a
	// packet capture) instead of it silently doing nothing, which is what happened before this
	// existed. The next step is deriving the actual packet format from a genuine capture and
	// replacing this with a real handshake.
	uint8_t probe[4] = { 0, 0, 0, 0 };
	int sent = send(handle, (const char*)probe, sizeof(probe), 0);
	if (DebugNet())
		fprintf(stderr, "[Net] RemoteConnection: sent %d-byte placeholder probe (NOT the real UT99 protocol) -> %d\n", (int)sizeof(probe), sent);

	return true;
}

void RemoteConnection::Disconnect()
{
	if (handle != remote_invalid_socket_value)
	{
		closesocket(handle);
		handle = remote_invalid_socket_value;
	}
	remoteHost.clear();
	remotePort = 0;
}

void RemoteConnection::Tick(float elapsed)
{
	if (handle == remote_invalid_socket_value)
		return;

	for (;;)
	{
		char buffer[4096];
		int received = recv(handle, buffer, sizeof(buffer), 0);
		if (received > 0)
		{
			if (DebugNet())
			{
				std::string hex;
				char hexbuf[4];
				int shown = received < 64 ? received : 64;
				for (int i = 0; i < shown; i++)
				{
					snprintf(hexbuf, sizeof(hexbuf), "%02x ", (uint8_t)buffer[i]);
					hex += hexbuf;
				}
				fprintf(stderr, "[Net] RemoteConnection: received %d bytes from %s:%d: %s%s\n",
					received, remoteHost.c_str(), remotePort, hex.c_str(), received > shown ? "..." : "");
			}
			continue;
		}

#ifdef WIN32
		int err = WSAGetLastError();
		bool wouldBlock = (err == WSAEWOULDBLOCK);
#else
		bool wouldBlock = (errno == EWOULDBLOCK || errno == EAGAIN);
#endif
		if (!wouldBlock && DebugNet())
		{
			// Most likely an ICMP port-unreachable coming back, i.e. "nothing is listening on
			// that port" - useful signal even without a real protocol implementation.
#ifdef WIN32
			fprintf(stderr, "[Net] RemoteConnection: recv() error (WSAError=%d) from %s:%d\n", err, remoteHost.c_str(), remotePort);
#else
			fprintf(stderr, "[Net] RemoteConnection: recv() error (errno=%d %s) from %s:%d\n", errno, strerror(errno), remoteHost.c_str(), remotePort);
#endif
		}
		break;
	}
}
