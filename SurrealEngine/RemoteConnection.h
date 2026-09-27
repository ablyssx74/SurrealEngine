#pragma once

#include <string>
#include <vector>
#include <map>
#include <set>
#include <cstdint>

class Package;
class UObject;
class UActor;
class UClass;
class UPlayerPawn;
class UProperty;
class BitReader; // defined in RemoteConnection.cpp - shared between the packet parser and the actor/property decoder below

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

// One package the server's "USES" messages announced, tracked in the exact order those messages
// arrived during login. That order is what defines this connection's flat, package-spanning
// object-index space (reimplements UPackageMap::List/Compute/ObjectToIndex/IndexToObject from real
// UT99 source - UnCoreNet.cpp: a wire-level "object index" is just a running sum of each known
// package's own export-table size, and resolving one walks this same list subtracting each
// package's count until it lands in the right one). Real UT99 blocks completing the join until
// every package in this list is locally available (downloading whichever aren't) before it ever
// builds this mapping - this reimplementation does the same: see ResolvePackageMap().
struct RemotePackageMapEntry
{
	std::string guidHex;
	std::string packageName;
	uint32_t remoteGeneration = 0; // the "GEN=" value - which of the server's own package generations the wire's object indices were built against
	Package* package = nullptr; // resolved by ResolvePackageMap() once loadable locally
	int objectBase = 0; // this package's first flat object index, set by ResolvePackageMap()
	int objectCount = 0; // this package's export count as of remoteGeneration (see Package::GetExportCountForGeneration), set by ResolvePackageMap()
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
// isn't usable for anything beyond having the right bytes on disk (this means a join whose
// required packages aren't all already present locally can't complete the steps below yet -
// ResolvePackageMap() fails cleanly and map/actor decoding is skipped for that connection).
//
// Once every required package is confirmed present locally, WELCOME's LEVEL= triggers a real,
// network-client-mode level load (Engine::LoadMap(..., isNetworkClient=true) - loads the same
// .unr every client and the server itself loaded, skips server-only GameInfo/InitGame, and
// destroys every non-bStatic/non-bNoDelete actor the level file placed, mirroring real UT99's
// UGameEngine::LoadMap client path). Actor-channel bunches are then decoded for real: a fresh
// channel's bOpen bunch resolves an object reference (DecodeObjectRef, reimplementing real UT99's
// UPackageMapLevel::SerializeObject) to either an already-loaded static/bNoDelete actor or a class
// to dynamically spawn; either way, ClassNetCache (see ClassNetCache.h) maps the bunch's per-
// property RepIndex stream to real UProperty/UFunction fields, and property values are decoded per
// UProperty::ValueType (DecodePropertyValue) and written directly into the actor's live property
// storage. RPC function calls are parsed (to stay bit-aligned) but not invoked yet. Still missing:
// a real player name/class instead of the placeholder "TR30"/SkeletalChars.WarBoss, teaching
// PackageManager to resolve packages from the download cache, Name/array/map property replication,
// and sending replication back to the server (this is receive-only).
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

	// A short, human-readable line describing what this connection is currently doing
	// ("Connecting to host:port...", "Downloading X.utx: 42% (1.2/4.9 MB)", "Loading map X...") -
	// empty once there's nothing worth telling the player about (not connected, or fully joined).
	// Drawn on screen every frame by RenderSubsystem::PostRender(), independent of the SE_DEBUG_NET
	// stderr logging (which stays as detailed wire-level tracing for development, not for players).
	const std::string& GetStatusLine() const { return statusLine; }

private:
	std::string statusLine;

	remote_socket_t handle = remote_invalid_socket_value;
	std::string remoteHost;
	int remotePort = 0;
	bool sentLoginReply = false;
	bool sentJoin = false;
	bool loadedNetworkMap = false; // true once WELCOME's LEVEL= has triggered a client-mode LoadMap
	std::string pendingNetworkMapLevel; // set by TryLoadNetworkMap while it keeps failing, so Tick() can retry (e.g. once missing packages actually finish becoming loadable)
	float networkMapRetryCooldown = 0.0f; // seconds until Tick() retries TryLoadNetworkMap again - without this it re-tries (and re-logs the same failure) every single frame while a package download is still in flight, which can take a while
	bool possessedOwnPawn = false; // true once a locally-owned PlayerPawn has been possessed (see step 8's heuristic in the plan)
	int nextOutgoingPacketId = 2; // 0 was HELLO, 1 was NETSPEED+LOGIN
	int nextChannelIndex = 1; // 0 is the control channel; AllocateFileChannelIndex() searches upward from here
	std::set<int> knownChannelIndices; // every channel index seen in use on this connection so far, ours or the server's own (see AllocateFileChannelIndex)
	std::map<int, int> nextChSequenceByChannel; // per channel - ChSequence is scoped to its channel, not global
	std::vector<RemoteRequiredPackage> pendingDownloads; // known missing, not yet requested
	std::map<int, RemoteFileDownload> activeDownloads; // chIndex -> download in progress on that channel
	std::vector<RemotePackageMapEntry> packageMapList; // every USES package, in arrival order
	std::map<int, UActor*> activeActorChannels; // chIndex -> actor, for channels currently open
	std::map<UActor*, int> actorChannelsByActor; // reverse lookup - which channel a dynamic actor is on

	int AllocateChSequence(int chIndex);

	// Picks a channel index for a file-channel request we're about to open, skipping any index
	// already known to be in use - by us (an existing download) or by the server (any channel
	// index it's opened on this connection, tracked in knownChannelIndices regardless of channel
	// type - see Tick()). Without this, a purely-incrementing counter could pick an index the
	// server had already claimed for one of its own actor channels (confirmed against a real
	// server: the server opens actor channels starting at low indices immediately after JOIN, so a
	// naive counter collides with it almost immediately), silently stalling that download at 0%
	// forever since the request lands on a channel the server considers already taken.
	int AllocateFileChannelIndex();
	void HandlePackageListMessage(const std::string& text);
	void StartNextDownload();
	void FinishDownload(int chIndex, bool success);

	// PackageMap equivalent (see RemotePackageMapEntry's comment). Returns false if any known
	// package isn't loadable locally yet - callers should skip whatever depended on it and retry
	// later (e.g. on the next WELCOME-triggered attempt, or the next actor bunch).
	bool ResolvePackageMap();
	int PackageMapMaxObjectIndex() const;
	UObject* PackageMapIndexToObject(int flatIndex) const;

	void TryLoadNetworkMap(const std::string& levelName);
	// packetData/packetSize is the full received packet a bunch's content offset is relative to
	// (matches how ReadBunchStrings/ReadBunchRawBytes already address bunch content in the .cpp).
	void HandleActorBunch(const uint8_t* packetData, int packetSize, int chIndex, bool bOpen, bool bClose, int contentBitOffset, int contentBits);
	void PossessIfOwnPawn(UActor* actor);

	// Reimplements UPackageMapLevel::SerializeObject's read path (real UT99 source, UnNetDrv.cpp):
	// one bit selects between a live actor-channel reference (bounded ReadInt(MAX_CHANNELS), 0=None)
	// and a static package-object reference (bounded ReadInt(PackageMapMaxObjectIndex()), resolved
	// via PackageMapIndexToObject). Used for both the actor-channel bOpen bunch's class/actor
	// reference and every UObjectProperty field.
	UObject* DecodeObjectRef(BitReader& br);

	// Reimplements the per-ValueType NetSerializeItem formats confirmed against real UT99 source
	// (UnProp.cpp) for the types this covers (byte/int/float/bool/object/vector/rotator/plane/
	// generic struct - see RemoteConnection.cpp), writing the decoded value into elementPtr (as
	// returned by UProperty::GetElement on the actor's property storage). Returns false for a type
	// this doesn't handle yet (name/array/map - see the class doc comment's Deferred items), which
	// means whatever bits it already consumed can't be trusted either - callers must stop decoding
	// the rest of that bunch, not just skip this one field.
	bool DecodePropertyValue(BitReader& br, UProperty* prop, void* elementPtr);
};
