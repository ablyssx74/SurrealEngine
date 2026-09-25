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
// implementation of that protocol yet, but it's no longer just replaying captured bytes either:
// it opens a raw UDP socket, sends a captured "HELLO" packet (the one case - a brand new channel
// opening - the reverse-engineered bit format doesn't fully cover yet), then parses the server's
// real CHALLENGE response and replies with a NETSPEED+LOGIN packet built from scratch by a small
// bit-packer, using a RESPONSE value actually computed from the server's challenge (see
// RemoteConnection.cpp for the packet/bunch format and the ChallengeResponse formula, both
// reverse-engineered and confirmed against a live UT99 server this session). Still missing: a
// real player name/class instead of the placeholder "TR30"/SkeletalChars.WarBoss, package
// validation and map sync, and everything from actor replication onward.
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
	bool sentLoginReply = false;
	bool sentJoin = false;
	int nextOutgoingPacketId = 2; // 0 was HELLO, 1 was NETSPEED+LOGIN
	int nextChSequence = 3; // 1 was HELLO's bunch, 2 was NETSPEED+LOGIN's
};
