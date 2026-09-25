#pragma once

#include <string>
#include <vector>
#include <map>
#include <cstdint>

#ifdef WIN32
typedef unsigned long long remote_socket_t; // matches SOCKET's underlying type (UINT_PTR) without pulling in WinSock2.h here
#define remote_invalid_socket_value ((remote_socket_t)-1)
#else
typedef int remote_socket_t;
#define remote_invalid_socket_value -1
#endif

// A package the server says is required, parsed from a "USES GUID=... PKG=... FLAGS=... SIZE=...
// FNAME=..." control message. guidHex is kept in the exact 32-character form the server sent it
// in - that's also the filename real UT99 clients cache a downloaded copy under (<GUID>.uxx), so
// there's no reason to reformat it.
struct RemoteRequiredPackage
{
	std::string guidHex;
	std::string packageName;
	std::string fileName;
	uint32_t fileSize = 0;
};

// An in-progress file-channel download: bytes accumulate here as bunches arrive on chIndex, until
// either fileSize bytes have been received or the channel's closing bunch arrives.
struct RemoteFileDownload
{
	RemoteRequiredPackage package;
	std::vector<uint8_t> data;
};

// WIP scaffolding for real multiplayer client-join support (SurrealEngine currently has no
// implementation of UT99's actual netcode - see Docs/Status.md). This is NOT a general
// implementation of that protocol yet: it opens a raw UDP socket and drives the login handshake
// (HELLO -> CHALLENGE -> NETSPEED+LOGIN -> package list -> WELCOME -> JOIN) using a real,
// from-scratch implementation of UE1's bit-packed wire format (see RemoteConnection.cpp for the
// packet/bunch structure and the ChallengeResponse formula - both reverse-engineered from genuine
// packet captures and confirmed against a live UT99 server, then cross-checked against real
// 1997-1999 Epic Games UT99 source files for the exact field layout). Received packets are parsed
// structurally (every ack and bunch entry, not just the control channel). Control-channel
// (ChType=Control) content is interpreted, including the post-LOGIN package list: any required
// package this engine doesn't already have a local file for is downloaded over a real UE1 file
// channel (see BuildFileChannelRequest/the file-channel handling in Tick()) and saved to the
// cache folder the same way a real client would (<CacheFolder>/<GUID>.uxx) - though nothing
// downstream (PackageManager) knows how to load from that cache yet, so a downloaded package
// isn't usable for anything beyond having the right bytes on disk. Actor channel bunches - real
// gameplay state replication, which starts flowing immediately after JOIN - are recognized but
// not decoded. Still missing: a real player name/class instead of the placeholder
// "TR30"/SkeletalChars.WarBoss, teaching PackageManager to resolve packages from the download
// cache, and actor property replication.
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
	int nextChannelIndex = 1; // 0 is the control channel; file channels are opened above it
	std::map<int, int> nextChSequenceByChannel; // per channel - ChSequence is scoped to its channel, not global
	std::vector<RemoteRequiredPackage> pendingDownloads; // known missing, not yet requested
	std::map<int, RemoteFileDownload> activeDownloads; // chIndex -> download in progress on that channel

	int AllocateChSequence(int chIndex);
	void HandlePackageListMessage(const std::string& text);
	void StartNextDownload();
	void FinishDownload(int chIndex, bool success);
};
