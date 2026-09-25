
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

	// First real handshake attempt. This is NOT a general encoder yet - UE1's packet/bunch bit
	// format was reverse-engineered from a genuine Wireshark capture of a real UT99-for-Linux
	// client joining a real UT99-for-Linux server (see the session notes), and most of it now
	// checks out, but a few bits of the bunch header are still uncertain (see below). Rather than
	// risk sending something subtly wrong that a real server just silently drops (as it already
	// did with the old 4-byte placeholder probe), this sends the literal bytes of a real client's
	// first-ever packet from that capture: PacketId=0, no ack yet, one reliable control-channel
	// bunch containing "HELLO REV=101 MINVER=432 VER=469\0" - the exact string a real 469-build
	// client sends to open a connection. Those captured bytes are known-correct (a real server
	// accepted them and replied with a real CHALLENGE), and they happen to be bit-identical to
	// what our own PacketId/HasAck encoding would produce for a first packet anyway (both are 0),
	// so replaying them verbatim is a valid way to test whether *our* transport (socket open,
	// connect(), send()) can elicit a real response - independent of whether our own from-scratch
	// bit-packer (needed later for messages we can't just replay, like a login with a real player
	// name) is exactly right yet.
	//
	// Remaining uncertainty in the reverse-engineered bunch header (doesn't affect this replay,
	// but matters once we build packets from scratch): after a 3-bit flags field (bOpen/bClose/
	// bReliable, believed 0/0/1 here), a 10-bit ChIndex (0), and a 10-bit ChSequence (1 for the
	// first reliable bunch), there are two more fields - a channel-type and a content-length -
	// that decode as Unreal's classic "compact index" variable-length integers, but their exact
	// bit boundary is uncertain by about 1 bit.
	static const uint8_t helloPacket[41] = {
		0x00, 0x80, 0x05, 0x20, 0x80, 0x40, 0x44, 0x08, 0x52, 0x11, 0x13, 0xd3, 0x13, 0x88, 0x54,
		0x91, 0x55, 0x4f, 0x0c, 0x4c, 0x0c, 0x48, 0x53, 0x92, 0x93, 0x55, 0x91, 0x54, 0x0f, 0xcd,
		0x8c, 0x0c, 0x88, 0x55, 0x91, 0x54, 0x0f, 0x8d, 0x4d, 0x0e, 0x40
	};
	int sent = send(handle, (const char*)helloPacket, sizeof(helloPacket), 0);
	if (DebugNet())
		fprintf(stderr, "[Net] RemoteConnection: sent %d-byte HELLO packet (replayed from a real capture) -> %d\n", (int)sizeof(helloPacket), sent);

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

			// Second step of the handshake test: once *anything* comes back after our HELLO, reply
			// with a real captured client's second packet (PacketId=1, acking the server's
			// PacketId=0 - both true here too, since this is also our second packet acking the
			// server's first reply) containing "NETSPEED 20000" and a LOGIN control message. This
			// is, again, verbatim replayed bytes, not something built from our own bit-packer (see
			// RemoteConnection.h) - notably its "RESPONSE=" value is whatever the real client
			// computed from *that* session's CHALLENGE, which won't match this server's freshly
			// generated CHALLENGE. Sending it anyway is a cheap way to find out whether this
			// server validates RESPONSE at all before we've reverse-engineered how to compute it
			// correctly - either a WELCOME (or some other clearly-different reaction) or continued
			// silence is useful new information either way.
			if (!sentLoginReply)
			{
				sentLoginReply = true;
				static const uint8_t loginPacket[169] = {
					0x01, 0x40, 0x00, 0x80, 0x00, 0x08, 0x10, 0x80, 0x7a, 0x70, 0x2a, 0xa2, 0x9a, 0x82,
					0x2a, 0x2a, 0x22, 0x02, 0x91, 0x81, 0x81, 0x81, 0x81, 0x01, 0x70, 0x12, 0x60, 0x7a,
					0x3a, 0x4a, 0x72, 0x02, 0x91, 0x2a, 0x9a, 0x82, 0x7a, 0x72, 0x9a, 0x2a, 0xea, 0x69,
					0x89, 0xc1, 0xa9, 0x89, 0xc9, 0xc1, 0x91, 0xb1, 0x01, 0xa9, 0x92, 0x62, 0xea, 0x49,
					0x72, 0x23, 0x2b, 0xc3, 0x73, 0xa9, 0x73, 0x93, 0xfb, 0x61, 0x0a, 0x72, 0xfa, 0x71,
					0x0a, 0x6b, 0x2b, 0xeb, 0xa1, 0x92, 0x9a, 0x81, 0xf9, 0x19, 0x62, 0x0b, 0x9b, 0x9b,
					0xeb, 0x99, 0x5a, 0x2b, 0x63, 0x2b, 0xa3, 0x0b, 0x63, 0x1b, 0x42, 0x0b, 0x93, 0x9b,
					0x73, 0xb9, 0x0a, 0x93, 0x13, 0x7a, 0x9b, 0x9b, 0xfb, 0xa1, 0x2b, 0x0b, 0x6b, 0xeb,
					0x89, 0xf9, 0x99, 0x5b, 0x4b, 0x73, 0xeb, 0xf9, 0x31, 0x0a, 0x1b, 0x2b, 0xeb, 0xf9,
					0xb1, 0x7a, 0x4b, 0x1b, 0x2b, 0xeb, 0xf9, 0x79, 0xb2, 0x2b, 0x93, 0x93, 0x4b, 0x23,
					0x2b, 0x1b, 0x62, 0x0b, 0x9b, 0x9b, 0xeb, 0xf9, 0x19, 0x42, 0x2b, 0x1b, 0x5b, 0x9b,
					0xab, 0x6b, 0xeb, 0x71, 0x7a, 0x1b, 0x42, 0x2b, 0x1b, 0x5b, 0x9b, 0xab, 0x6b, 0x03,
					0x08
				};
				int sent = send(handle, (const char*)loginPacket, sizeof(loginPacket), 0);
				if (DebugNet())
					fprintf(stderr, "[Net] RemoteConnection: sent %d-byte NETSPEED+LOGIN reply (replayed from a real capture, stale RESPONSE value) -> %d\n", (int)sizeof(loginPacket), sent);
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
