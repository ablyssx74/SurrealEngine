#pragma once

#include <string>

#ifdef WIN32
typedef unsigned long long remote_socket_t; // matches SOCKET's underlying type (UINT_PTR) without pulling in WinSock2.h here
#define remote_invalid_socket_value ((remote_socket_t)-1)
#else
typedef int remote_socket_t;
#define remote_invalid_socket_value -1
#endif

// WIP scaffolding for real multiplayer client-join support (SurrealEngine currently has no
// implementation of UT99's actual netcode - see Docs/Status.md). This is NOT a general
// implementation of that protocol yet: it opens a raw UDP socket toward the server and sends
// a real captured "HELLO" handshake packet (see RemoteConnection.cpp), so a join attempt is
// observable (SE_DEBUG_NET logging, capturable in a packet sniffer) and can actually reach a
// real server's handshake logic instead of just being silently dropped. Building arbitrary
// outgoing packets (e.g. a login with the local player's real name) still needs a proper
// bit-packer once the reverse-engineered packet/bunch format is fully nailed down.
class RemoteConnection
{
public:
	RemoteConnection() = default;
	~RemoteConnection();

	RemoteConnection(const RemoteConnection&) = delete;
	RemoteConnection& operator=(const RemoteConnection&) = delete;

	// Resolves host, opens a UDP socket, and sends the initial probe. Returns false only for a
	// local failure (socket creation, DNS resolution) - a server not existing or not responding
	// can't be detected this way (UDP has no connection handshake at the OS level), only via
	// whatever Tick() observes afterward.
	bool Connect(const std::string& host, int port);
	void Disconnect();
	bool IsConnected() const { return handle != remote_invalid_socket_value; }

	// Polls for incoming data and logs whatever arrives (or whatever error the OS reports, e.g.
	// an ICMP port-unreachable surfacing as a receive error) via SE_DEBUG_NET.
	void Tick(float elapsed);

private:
	remote_socket_t handle = remote_invalid_socket_value;
	std::string remoteHost;
	int remotePort = 0;
};
