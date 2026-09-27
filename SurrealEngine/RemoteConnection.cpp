
#include "Precomp.h"
#include "RemoteConnection.h"
#include "Engine.h"
#include "ClassNetCache.h"
#include "Package/PackageManager.h"
#include "Package/Package.h"
#include "Packages/Core/UObject.h"
#include "Packages/Core/UClass.h"
#include "Packages/Core/UEnum.h"
#include "Packages/Core/Properties/UProperty.h"
#include "Packages/Core/Properties/UByteProperty.h"
#include "Packages/Core/Properties/UIntProperty.h"
#include "Packages/Core/Properties/UFloatProperty.h"
#include "Packages/Core/Properties/UBoolProperty.h"
#include "Packages/Core/Properties/UObjectProperty.h"
#include "Packages/Core/Properties/UStructProperty.h"
#include "Packages/Core/UFunction.h"
#include "Packages/Engine/Actors/UActor.h"
#include "Packages/Engine/Actors/Pawn/UPlayerPawn.h"
#include "Packages/Engine/Actors/Info/ULevelInfo.h"
#include "Packages/Engine/Resources/Level/ULevel.h"
#include "Math/rotator.h"
#include "Utils/File.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cmath>
#include <algorithm>
#include <vector>
#include <string>

// BitReader is used both by the packet/bunch parser below (anonymous namespace) and by
// RemoteConnection's actor/property decoder (RemoteConnection.h declares it as an incomplete type,
// so it must live at file scope here rather than inside the anonymous namespace, or the two
// declarations would refer to unrelated types).
//
// LSB-first bit reader matching UE1's wire format - see the BitWriter comment below for how this
// was derived. ArIsError-style overflow tracking (the `error` flag) mirrors real UT99's
// FBitReader::SerializeBits/SerializeInt (Core/Src/UnBits.cpp in real UT99 source): a read that
// would run past the declared bit length sets `error` and returns 0 instead of reading garbage.
// This is what lets actor-channel property decoding detect "no more replicated fields in this
// bunch" the same way the real engine does - confirmed from source this session that the writer
// never sends an explicit terminator; the reader just runs out of bits mid-ReadInt.
class BitReader
{
public:
	BitReader(const uint8_t* data, int sizeBytes) : data(data), sizeBits(sizeBytes * 8) {}

	// Same as above, but caps the logical bit length below what sizeBytes*8 would allow - for
	// carving an exact-bit-length span (e.g. one bunch's content) out of a larger buffer, matching
	// how a real FInBunch is an exact bit count, not byte-rounded.
	BitReader(const uint8_t* data, int sizeBytes, int exactSizeBits) : data(data), sizeBits(std::min(sizeBytes * 8, exactSizeBits)) {}

	int RemainingBits() const { return sizeBits - bitPos; }
	int GetBitPos() const { return bitPos; }
	bool IsError() const { return error; }

	int ReadBit()
	{
		if (bitPos >= sizeBits)
		{
			error = true;
			return 0;
		}
		int bit = (data[bitPos / 8] >> (bitPos % 8)) & 1;
		bitPos++;
		return bit;
	}

	uint32_t ReadBits(int count)
	{
		uint32_t value = 0;
		for (int i = 0; i < count; i++)
			value |= (uint32_t)ReadBit() << i;
		return value;
	}

	// The reader side of BitWriter::WriteInt below - see its comment for the algorithm. Tracks the
	// exact same running total the writer did, so it independently knows when to stop. Sets `error`
	// (without returning early - matches real FBitReader::SerializeInt, which keeps looping so Pos
	// ends up in the same place a full decode would have left it) if the value can't be completed
	// within the remaining bits.
	uint32_t ReadInt(uint32_t valueMax)
	{
		uint32_t value = 0;
		for (uint32_t mask = 1; value + mask < valueMax && mask != 0; mask <<= 1)
		{
			if (ReadBit())
				value |= mask;
		}
		return value;
	}

	uint32_t ReadCompactIndex()
	{
		uint32_t b0 = ReadBits(8);
		uint32_t value = b0 & 0x3F;
		int shift = 6;
		bool cont = ((b0 >> 6) & 1) != 0;
		for (int guard = 0; cont && guard < 4; guard++)
		{
			uint32_t bN = ReadBits(8);
			value |= (bN & 0x7F) << shift;
			shift += 7;
			cont = ((bN >> 7) & 1) != 0;
		}
		return value;
	}

	std::string ReadString()
	{
		uint32_t len = ReadCompactIndex();
		std::string s;
		s.reserve(len);
		for (uint32_t i = 0; i < len; i++)
		{
			uint8_t c = (uint8_t)ReadBits(8);
			if (c != 0)
				s.push_back((char)c);
		}
		return s;
	}

private:
	const uint8_t* data;
	int sizeBits;
	int bitPos = 0;
	bool error = false;
};

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

	// Formats a byte count as e.g. "4.9 MB" for the on-screen download-progress status line.
	std::string FormatMegabytes(size_t bytes)
	{
		char buf[32];
		snprintf(buf, sizeof(buf), "%.1f MB", bytes / (1024.0 * 1024.0));
		return buf;
	}

	// LSB-first bit writer/reader matching UE1's wire format, reverse-engineered this session from
	// genuine Wireshark captures of a real UT99-for-Linux client talking to a real UT99-for-Linux
	// server, cross-checked against a set of real 1997-1999 Epic Games UT99 engine source files
	// (UnConn.cpp/UnChan.cpp/UnBunch.cpp) obtained separately, and validated by re-encoding
	// captured packets from scratch and getting exact byte-for-byte matches (including the bOpen=1
	// "new channel" case, previously unsolved and replayed verbatim from a capture - now built
	// fresh like everything else). Written fresh here; never copied from Epic's source text.
	class BitWriter
	{
	public:
		void WriteBit(int bit)
		{
			if (bitPos % 8 == 0)
				bytes.push_back(0);
			if (bit)
				bytes.back() |= (uint8_t)(1 << (bitPos % 8));
			bitPos++;
		}

		void WriteBits(uint32_t value, int count)
		{
			for (int i = 0; i < count; i++)
				WriteBit((value >> i) & 1);
		}

		// UE1's universal bounded-integer primitive (FBitWriter::SerializeInt/WriteInt in the real
		// engine, confirmed against real 1997-1999 UT99 source this session). Encodes a value in
		// [0,valueMax) as a truncated binary code: one bit per doubling of a mask, stopping as soon
		// as the accumulated value-so-far plus the next mask can no longer reach valueMax - meaning
		// it's self-terminating (the reader tracks the same running total and stops the same way)
		// and, for values near the top of a non-power-of-two range, uses fewer bits than a fixed
		// ceil(log2(valueMax)) width would. Only *looks* fixed-width for a power-of-two valueMax
		// (every case this session validated empirically before this source turned up, e.g.
		// MAX_PACKETID=16384) - it genuinely isn't for others (e.g. MAX_CHANNELS=1023).
		void WriteInt(uint32_t value, uint32_t valueMax)
		{
			uint32_t newValue = 0;
			for (uint32_t mask = 1; newValue + mask < valueMax && mask != 0; mask <<= 1)
			{
				bool bit = (value & mask) != 0;
				WriteBit(bit ? 1 : 0);
				if (bit)
					newValue += mask;
			}
		}

		// Epic's classic "compact index" variable-length integer, as used throughout Unreal's
		// serialization: byte 0 holds 6 magnitude bits then a continue bit then a sign bit (all
		// LSB-first); each following byte holds 7 more magnitude bits then a continue bit. We only
		// ever write positive lengths here, so the sign bit is always 0.
		void WriteCompactIndex(uint32_t value)
		{
			uint32_t v = value;
			uint32_t low6 = v & 0x3F;
			v >>= 6;
			bool cont = v != 0;
			WriteBits(low6 | (cont ? 0x40u : 0u), 8);
			while (cont)
			{
				uint32_t low7 = v & 0x7F;
				v >>= 7;
				cont = v != 0;
				WriteBits(low7 | (cont ? 0x80u : 0u), 8);
			}
		}

		// FString wire format: a compact-index length (character count including the null
		// terminator), the raw ANSI bytes, then the null terminator.
		void WriteString(const std::string& s)
		{
			WriteCompactIndex((uint32_t)s.size() + 1);
			for (unsigned char c : s)
				WriteBits(c, 8);
			WriteBits(0, 8);
		}

		// Appends another writer's bits verbatim - used to splice a bunch's already-serialized
		// content (built separately so its bit length is known before the bunch header, which
		// needs that length, is written) into the outer packet stream.
		void AppendBits(const BitWriter& other)
		{
			for (int i = 0; i < other.bitPos; i++)
				WriteBit((other.bytes[i / 8] >> (i % 8)) & 1);
		}

		int GetBitCount() const { return bitPos; }

		// Writes the packet trailer bit and pads to a byte boundary, then returns the bytes.
		std::vector<uint8_t> Finish()
		{
			WriteBit(1);
			while (bitPos % 8 != 0)
				WriteBit(0);
			return bytes;
		}

	private:
		std::vector<uint8_t> bytes;
		int bitPos = 0;
	};

	// UE1 channel types (EChannelType in the real engine). Only Control is used by anything this
	// code builds; Actor/File are recognized when parsing so logging can say what a channel is.
	enum EChannelType
	{
		CHTYPE_None = 0,
		CHTYPE_Control = 1,
		CHTYPE_Actor = 2,
		CHTYPE_File = 3,
	};

	// The "Max" bounds for UE1's WriteInt/ReadInt bounded-integer primitive (see BitWriter::WriteInt
	// above), confirmed this session against real 1997-1999 UT99 engine source (UnNet.h/UnConn.h
	// for the constants, UnBits.cpp for the algorithm - it's a self-terminating truncated binary
	// code, not a fixed bit width, though it happens to produce a fixed width whenever Max is an
	// exact power of two, which is how every one of these was first found empirically before the
	// source was available):
	//   MAX_PACKETID   = 16384  (PacketId, AckPacketId)
	//   MAX_CHANNELS   =  1023  (ChIndex) - NOT a power of two, so this one genuinely does vary in
	//   width for values near the top of the range, unlike the others below.
	//   MAX_CHSEQUENCE =  1024  (ChSequence)
	//   CHTYPE_MAX     =     8  (ChType)
	//   MaxPacket*8    =  4096  (BunchDataBits, a bit count not a byte count) - MaxPacket itself
	//   (512 bytes) matches the largest packets ever observed in any real capture (~505-510 bytes
	//   of payload, consistent with a 512-byte cap minus header/trailer overhead).
	constexpr uint32_t MAX_PACKETID = 16384;
	constexpr uint32_t MAX_CHANNELS = 1023;
	constexpr uint32_t MAX_CHSEQUENCE = 1024;
	constexpr uint32_t CHTYPE_MAX = 8;
	constexpr uint32_t MAX_BUNCH_DATA_BITS = 512 * 8;

	// The most bits WriteInt(valueMax) could ever produce (i.e. what a fixed-width encoding would
	// use). Used only as a guard when parsing - real data always has at least this many bits left
	// for a genuine field of this kind, so seeing fewer means what's left is the packet's trailer
	// bit and padding, not a real field, and parsing should stop rather than try to interpret it.
	int MaxBitsForRange(uint32_t valueMax)
	{
		int bits = 0;
		for (uint32_t mask = 1; mask < valueMax && mask != 0; mask <<= 1)
			bits++;
		return bits;
	}

	// UT99's connection-level challenge/response transform (UGameEngine::ChallengeResponse in the
	// real engine). Cracked this session by finding a real (CHALLENGE, RESPONSE) pair in a genuine
	// capture and testing hypotheses against it; the exact formula was then independently
	// confirmed against a historical Unreal Engine 1 source tree. Written fresh here (not copied)
	// purely for UT99 wire-protocol interoperability: without computing the same value a real
	// client would, a real server rejects the login with "FAILURE CHALLENGE".
	int32_t ChallengeResponse(int32_t challenge)
	{
		uint32_t c = (uint32_t)challenge;
		uint32_t result = (c * 237u) ^ 0x93fe92Ceu ^ (uint32_t)(challenge >> 16) ^ (c << 16);
		return (int32_t)result;
	}

	// Writes one packet-level "entry": a bunch. Every packet is PacketId followed by a sequence of
	// self-describing entries - each starts with an IsAck bit; IsAck=1 means a plain
	// acknowledgement (just an AckPacketId), IsAck=0 means a full bunch as written here. Confirmed
	// against real UT99 source: bControl (=bOpen||bClose) gates whether bOpen/bClose follow;
	// bReliable gates whether ChSequence follows; (bReliable||bOpen) gates whether ChType follows.
	void WriteBunch(BitWriter& packet, bool bOpen, bool bClose, bool bReliable, int chIndex, int chType, int chSequence, const BitWriter& content)
	{
		packet.WriteBit(0); // IsAck = 0: this entry is a bunch, not an ack
		bool bControl = bOpen || bClose;
		packet.WriteBit(bControl ? 1 : 0);
		if (bControl)
		{
			packet.WriteBit(bOpen ? 1 : 0);
			packet.WriteBit(bClose ? 1 : 0);
		}
		packet.WriteBit(bReliable ? 1 : 0);
		packet.WriteInt((uint32_t)chIndex, MAX_CHANNELS);
		if (bReliable)
			packet.WriteInt((uint32_t)chSequence, MAX_CHSEQUENCE);
		if (bReliable || bOpen)
			packet.WriteInt((uint32_t)chType, CHTYPE_MAX);
		packet.WriteInt((uint32_t)content.GetBitCount(), MAX_BUNCH_DATA_BITS);
		packet.AppendBits(content);
	}

	// Writes a plain-ack entry: IsAck=1 followed by the PacketId being acknowledged. A single
	// packet can carry any number of these (and any number of bunches) - real servers do exactly
	// that, e.g. acking eight outstanding packets at once in a single reply.
	void WriteAckEntry(BitWriter& packet, int ackPacketId)
	{
		packet.WriteBit(1);
		packet.WriteInt((uint32_t)ackPacketId, MAX_PACKETID);
	}

	// A reliable, already-open (bOpen=bClose=0) control-channel (ChIndex=0, ChType=Control) bunch
	// carrying plain text content - the shape of every message this client sends after HELLO.
	void WriteControlBunch(BitWriter& packet, int chSequence, const BitWriter& content)
	{
		WriteBunch(packet, /*bOpen=*/false, /*bClose=*/false, /*bReliable=*/true, /*chIndex=*/0, CHTYPE_Control, chSequence, content);
	}

	// An ack-only packet: PacketId followed by nothing but one ack entry. What a real client sends
	// when it has nothing new to say but needs the server to know it's still there and which
	// packet just arrived.
	std::vector<uint8_t> BuildAckPacket(int packetId, int ackPacketId)
	{
		BitWriter packet;
		packet.WriteInt((uint32_t)packetId, MAX_PACKETID);
		WriteAckEntry(packet, ackPacketId);
		return packet.Finish();
	}

	// The very first packet a client ever sends: PacketId=0, no ack yet, a single reliable bunch
	// that *opens* the control channel (bOpen=1, ChSequence=1) containing the HELLO handshake
	// message. Building this from scratch (rather than replaying captured bytes, as earlier this
	// session) was verified by re-encoding a real captured HELLO packet and getting an exact
	// byte-for-byte match.
	std::vector<uint8_t> BuildHelloPacket()
	{
		BitWriter content;
		content.WriteString("HELLO REV=101 MINVER=432 VER=469");

		BitWriter packet;
		packet.WriteInt(0, MAX_PACKETID);
		WriteBunch(packet, /*bOpen=*/true, /*bClose=*/false, /*bReliable=*/true, /*chIndex=*/0, CHTYPE_Control, /*chSequence=*/1, content);
		return packet.Finish();
	}

	// Builds our reply to the server's CHALLENGE: a NETSPEED message and a LOGIN message (with a
	// correctly-computed RESPONSE) in one reliable control-channel bunch, exactly mirroring what a
	// real client sends at this point in the handshake.
	std::vector<uint8_t> BuildLoginPacket(int packetId, int ackPacketId, int chSequence, int32_t response)
	{
		BitWriter content;
		content.WriteString("NETSPEED 20000");
		content.WriteString("LOGIN RESPONSE=" + std::to_string(response) +
			" URL=Index.unr?LAN?Name=TR30?Class=SkeletalChars.WarBoss?team=1?skin=?Face=?Voice=?OverrideClass=?Checksum=NoChecksum");

		BitWriter packet;
		packet.WriteInt((uint32_t)packetId, MAX_PACKETID);
		WriteAckEntry(packet, ackPacketId);
		WriteControlBunch(packet, chSequence, content);
		return packet.Finish();
	}

	// Builds our reply once the server's WELCOME arrives: a "JOIN" message in a reliable
	// control-channel bunch, exactly mirroring what a real client sends to enter the game.
	std::vector<uint8_t> BuildJoinPacket(int packetId, int ackPacketId, int chSequence)
	{
		BitWriter content;
		content.WriteString("JOIN");

		BitWriter packet;
		packet.WriteInt((uint32_t)packetId, MAX_PACKETID);
		WriteAckEntry(packet, ackPacketId);
		WriteControlBunch(packet, chSequence, content);
		return packet.Finish();
	}

	// A single decoded bunch entry from a received packet. contentBitOffset/contentBits describe
	// the bunch's payload as a span of bits within the original packet buffer (not copied out),
	// since only control-channel (ChType==Control) content is ever interpreted as text right now -
	// actor/file channel content (real gameplay state replication) is a separately-scoped piece of
	// work that doesn't exist yet.
	struct ParsedBunch
	{
		bool bOpen = false, bClose = false, bReliable = false;
		int chIndex = 0;
		int chType = CHTYPE_None;
		int chSequence = 0;
		int contentBitOffset = 0;
		int contentBits = 0;
	};

	struct ParsedPacket
	{
		bool valid = false;
		int packetId = -1;
		std::vector<int> acks;
		std::vector<ParsedBunch> bunches;
	};

	// Decodes a received packet's PacketId and its full sequence of self-describing entries
	// (interleaved acks and bunches, in whatever order and quantity the sender chose - real
	// servers send anywhere from zero to a dozen+ of each in a single packet). Stops cleanly at
	// the packet's trailer bit: the last "entry" the loop reads is always that lone trailer bit
	// misread as a bogus IsAck=1 with too few bits left for a real AckPacketId to follow, which is
	// how the loop knows to stop (the trailer only pads to the next byte boundary, at most 7 bits,
	// always less than the 14 a real ack needs, so this never misfires on real data - confirmed
	// against 265+ real captured packets spanning the full handshake through a live post-JOIN
	// actor-replication burst, all of which decode with zero overflow/truncation anomalies).
	ParsedPacket ParsePacket(const uint8_t* data, int size)
	{
		ParsedPacket result;
		BitReader br(data, size);
		if (br.RemainingBits() < MaxBitsForRange(MAX_PACKETID))
			return result;
		result.packetId = (int)br.ReadInt(MAX_PACKETID);
		result.valid = true;

		while (br.RemainingBits() >= 1)
		{
			int isAck = br.ReadBit();
			if (isAck)
			{
				if (br.RemainingBits() < MaxBitsForRange(MAX_PACKETID))
					break; // the packet's trailer bit, not a real ack entry
				result.acks.push_back((int)br.ReadInt(MAX_PACKETID));
			}
			else
			{
				if (br.RemainingBits() < 2)
					break;
				bool bControl = br.ReadBit() != 0;
				bool bOpen = false, bClose = false;
				if (bControl)
				{
					if (br.RemainingBits() < 2)
						break;
					bOpen = br.ReadBit() != 0;
					bClose = br.ReadBit() != 0;
				}
				if (br.RemainingBits() < 1)
					break;
				bool bReliable = br.ReadBit() != 0;
				if (br.RemainingBits() < MaxBitsForRange(MAX_CHANNELS))
					break;
				int chIndex = (int)br.ReadInt(MAX_CHANNELS);
				int chSequence = 0;
				if (bReliable)
				{
					if (br.RemainingBits() < MaxBitsForRange(MAX_CHSEQUENCE))
						break;
					chSequence = (int)br.ReadInt(MAX_CHSEQUENCE);
				}
				int chType = CHTYPE_None;
				if (bReliable || bOpen)
				{
					if (br.RemainingBits() < MaxBitsForRange(CHTYPE_MAX))
						break;
					chType = (int)br.ReadInt(CHTYPE_MAX);
				}
				if (br.RemainingBits() < MaxBitsForRange(MAX_BUNCH_DATA_BITS))
					break;
				int contentBits = (int)br.ReadInt(MAX_BUNCH_DATA_BITS);
				if (contentBits < 0 || contentBits > br.RemainingBits())
					break;

				ParsedBunch pb;
				pb.bOpen = bOpen; pb.bClose = bClose; pb.bReliable = bReliable;
				pb.chIndex = chIndex; pb.chType = chType; pb.chSequence = chSequence;
				pb.contentBitOffset = br.GetBitPos();
				pb.contentBits = contentBits;
				result.bunches.push_back(pb);

				for (int i = 0; i < contentBits; i++)
					br.ReadBit();
			}
		}
		return result;
	}

	// Reads every FString out of a bunch's content span. Safe to call on any bunch (bounded by the
	// bunch's own declared bit length, so it can't run past its content into whatever follows),
	// but only meaningful for control-channel bunches - the control channel is nothing but a
	// reliable ordered stream of these (confirmed this session: multiple Logf()-style messages sit
	// back-to-back in one bunch's payload with zero framing between them).
	std::vector<std::string> ReadBunchStrings(const uint8_t* data, int size, const ParsedBunch& bunch)
	{
		std::vector<std::string> result;
		int byteOff = bunch.contentBitOffset / 8;
		int subBit = bunch.contentBitOffset % 8;
		if (byteOff >= size)
			return result;

		BitReader br(data + byteOff, size - byteOff);
		if (subBit)
			br.ReadBits(subBit);

		int remaining = bunch.contentBits;
		while (remaining > 8) // a valid string needs at least a length byte plus a null terminator
		{
			int before = br.RemainingBits();
			std::string s = br.ReadString();
			int consumed = before - br.RemainingBits();
			if (consumed <= 0 || consumed > remaining)
				break;
			remaining -= consumed;
			result.push_back(std::move(s));
		}
		return result;
	}

	// Reads a bunch's raw content bytes verbatim - what a file-channel bunch's payload is (a plain
	// Serialize() of file data, unlike the control channel's FStrings). File content is always a
	// whole number of bytes on the wire (real UT99 sends it via FArchive::Serialize, a raw byte
	// copy), so contentBits/8 is exact.
	std::vector<uint8_t> ReadBunchRawBytes(const uint8_t* data, int size, const ParsedBunch& bunch)
	{
		std::vector<uint8_t> result;
		int byteOff = bunch.contentBitOffset / 8;
		int subBit = bunch.contentBitOffset % 8;
		if (byteOff >= size)
			return result;

		BitReader br(data + byteOff, size - byteOff);
		if (subBit)
			br.ReadBits(subBit);

		int numBytes = bunch.contentBits / 8;
		result.reserve(numBytes);
		for (int i = 0; i < numBytes; i++)
			result.push_back((uint8_t)br.ReadBits(8));
		return result;
	}

	// Builds our request to download a required package: a bunch that *opens* a new file channel
	// (bOpen=1, ChType=File), whose content is nothing but the package's 16-byte GUID - exactly
	// what a real client sends (UFileChannel::ReceivedBunch in the real engine: "Bunch << Guid").
	// guidHex is the 32-character hex string as the server's "USES GUID=..." message wrote it;
	// parsing it back into the 4 big-endian 32-bit words it represents and writing each with
	// WriteInt's LSB-first bit order reproduces the exact same raw bytes a real FGuid's in-memory
	// layout (four little-endian DWORDs) would serialize to.
	std::vector<uint8_t> BuildFileChannelRequest(int packetId, int chIndex, int chSequence, const std::string& guidHex)
	{
		BitWriter content;
		for (int i = 0; i < 4; i++)
		{
			uint32_t word = (uint32_t)strtoul(guidHex.substr(i * 8, 8).c_str(), nullptr, 16);
			content.WriteBits(word, 32);
		}

		BitWriter packet;
		packet.WriteInt((uint32_t)packetId, MAX_PACKETID);
		WriteBunch(packet, /*bOpen=*/true, /*bClose=*/false, /*bReliable=*/true, chIndex, CHTYPE_File, chSequence, content);
		return packet.Finish();
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
	statusLine = "Connecting to " + host + ":" + std::to_string(port) + "...";

	if (DebugNet())
		fprintf(stderr, "[Net] RemoteConnection: socket ready, target %s:%d\n", host.c_str(), port);

	std::vector<uint8_t> helloPacket = BuildHelloPacket();
	int sent = send(handle, (const char*)helloPacket.data(), (int)helloPacket.size(), 0);
	if (DebugNet())
		fprintf(stderr, "[Net] RemoteConnection: sent %d-byte HELLO packet -> %d\n", (int)helloPacket.size(), sent);

	// HELLO consumed the control channel's ChSequence 1; the CHALLENGE handler below hardcodes
	// NETSPEED+LOGIN as ChSequence 2, so channel 0's next free sequence is 3.
	nextChSequenceByChannel[0] = 3;

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
	statusLine.clear();
}

// Every channel has its own ChSequence numbering, starting at 1 when it's opened (confirmed this
// session against real UT99 source and live captures - the control channel's HELLO bunch is
// ChSequence 1, and the first bunch on any freshly-opened actor channel in a capture is always 1
// too, regardless of what other channels are already open). A single flat counter shared across
// all channels (which is what this connection used before file channels existed, since only the
// control channel was ever in play) would be wrong here.
int RemoteConnection::AllocateChSequence(int chIndex)
{
	int& next = nextChSequenceByChannel[chIndex];
	if (next == 0)
		next = 1;
	return next++;
}

int RemoteConnection::AllocateFileChannelIndex()
{
	while (knownChannelIndices.count(nextChannelIndex))
		nextChannelIndex++;
	int result = nextChannelIndex++;
	knownChannelIndices.insert(result);
	return result;
}

// Parses a "USES GUID=<hex> PKG=<name> FLAGS=<n> SIZE=<n> [GEN=<n>] [REALGEN=<n>] FNAME=<file>"
// message (one per required package, sent after LOGIN succeeds - format cracked earlier this
// session from a real capture). Anything this engine doesn't already have a same-named local file
// for is queued for download over a real UE1 file channel. No-op for any other control message.
void RemoteConnection::HandlePackageListMessage(const std::string& text)
{
	if (text.rfind("USES ", 0) != 0)
		return;

	auto extract = [&](const std::string& key) -> std::string
	{
		size_t pos = text.find(key);
		if (pos == std::string::npos)
			return {};
		pos += key.size();
		size_t end = text.find(' ', pos);
		return text.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
	};

	std::string guidHex = extract("GUID=");
	std::string pkgName = extract("PKG=");
	std::string sizeStr = extract("SIZE=");
	std::string genStr = extract("GEN=");
	std::string fileName = extract("FNAME=");
	if (guidHex.size() != 32 || pkgName.empty() || fileName.empty())
	{
		if (DebugNet())
			fprintf(stderr, "[Net] RemoteConnection: couldn't parse package requirement out of \"%s\" - ignoring\n", text.c_str());
		return;
	}

	// Every USES package - present locally or not - defines a slot in this connection's flat
	// object-index space (see RemotePackageMapEntry's comment), in the exact order these messages
	// arrive. This has to be tracked regardless of local presence: skipping an already-present
	// package here would shift the index of every package that comes after it.
	RemotePackageMapEntry mapEntry;
	mapEntry.guidHex = guidHex;
	mapEntry.packageName = pkgName;
	mapEntry.remoteGeneration = (uint32_t)strtoul(genStr.c_str(), nullptr, 10);
	packageMapList.push_back(mapEntry);

	if (engine && engine->packages && engine->packages->HasPackageFile(pkgName))
	{
		if (DebugNet())
			fprintf(stderr, "[Net] RemoteConnection: package \"%s\" already present locally - not downloading\n", pkgName.c_str());
		return;
	}

	RemoteRequiredPackage pkg;
	pkg.guidHex = guidHex;
	pkg.packageName = pkgName;
	pkg.fileName = fileName;
	pkg.fileSize = (uint32_t)strtoul(sizeStr.c_str(), nullptr, 10);

	if (DebugNet())
		fprintf(stderr, "[Net] RemoteConnection: package \"%s\" (GUID=%s, %u bytes) missing locally - queued for download\n",
			pkg.packageName.c_str(), pkg.guidHex.c_str(), pkg.fileSize);

	pendingDownloads.push_back(std::move(pkg));
	StartNextDownload();
}

// Downloads one package at a time (real clients appear to pace these too, going by the capture
// this session's protocol work was built from - a fresh channel per package, not several at
// once), so this only actually starts a request when nothing else is already in flight.
void RemoteConnection::StartNextDownload()
{
	if (!activeDownloads.empty() || pendingDownloads.empty())
		return;

	RemoteRequiredPackage pkg = pendingDownloads.front();
	pendingDownloads.erase(pendingDownloads.begin());

	int chIndex = AllocateFileChannelIndex();
	int chSequence = AllocateChSequence(chIndex);

	std::vector<uint8_t> requestPacket = BuildFileChannelRequest(nextOutgoingPacketId++, chIndex, chSequence, pkg.guidHex);
	int sent = send(handle, (const char*)requestPacket.data(), (int)requestPacket.size(), 0);
	if (DebugNet())
		fprintf(stderr, "[Net] RemoteConnection: requesting download of \"%s\" (GUID=%s) on channel %d -> %d\n",
			pkg.packageName.c_str(), pkg.guidHex.c_str(), chIndex, sent);
	statusLine = "Downloading " + pkg.packageName + ": 0% (0.0/" + FormatMegabytes(pkg.fileSize) + ")";

	RemoteFileDownload download;
	download.package = std::move(pkg);
	activeDownloads[chIndex] = std::move(download);
}

// Called once a file channel's transfer is done (its closing bunch arrived) or has stalled out.
// A real client validates the transferred size against the size the package list announced and
// saves the result as <CacheFolder>/<GUID>.uxx (UFileChannel::Destroy in the real engine) - matched
// here, though nothing downstream (PackageManager) knows how to load a package back out of that
// cache yet, so this only gets the bytes onto disk in the right place for that to build on later.
void RemoteConnection::FinishDownload(int chIndex, bool success)
{
	auto it = activeDownloads.find(chIndex);
	if (it == activeDownloads.end())
		return;

	RemoteFileDownload download = std::move(it->second);
	activeDownloads.erase(it);

	bool sizeMatches = download.data.size() == download.package.fileSize;
	if (success && sizeMatches && engine && engine->packages)
	{
		std::filesystem::path cacheFolder = engine->packages->GetCacheFolderPath();
		Directory::create(cacheFolder.string());
		std::filesystem::path dest = cacheFolder / (download.package.guidHex + ".uxx");
		File::write_all_bytes(dest.string(), download.data.data(), download.data.size());
		if (DebugNet())
			fprintf(stderr, "[Net] RemoteConnection: downloaded \"%s\" (%zu bytes) -> %s\n",
				download.package.packageName.c_str(), download.data.size(), dest.string().c_str());
		// If there's another package queued, StartNextDownload() below immediately overwrites
		// this with its own "Downloading ...: 0%" line - this is only what's left on screen once
		// every queued package is done.
		statusLine = "Downloaded " + download.package.packageName + ". Waiting for the server...";
	}
	else if (DebugNet())
	{
		fprintf(stderr, "[Net] RemoteConnection: download of \"%s\" failed or was incomplete (%zu/%u bytes received)\n",
			download.package.packageName.c_str(), download.data.size(), download.package.fileSize);
	}

	StartNextDownload();
}

// Reimplements UPackageMap::Compute() (real UT99 source, UnCoreNet.cpp): resolves every package in
// packageMapList to a loaded Package* and assigns it a flat objectBase, which is the running sum of
// every earlier package's own export-table size. Returns false the moment any package in the list
// isn't locally loadable - real UT99 never builds this mapping until every USES package has been
// downloaded, so this doesn't try to cope with a partially-resolved list either (an unresolvable
// package mid-list would make every later package's index wrong anyway).
bool RemoteConnection::ResolvePackageMap()
{
	if (!engine || !engine->packages)
		return false;

	int base = 0;
	for (RemotePackageMapEntry& entry : packageMapList)
	{
		if (!entry.package)
		{
			if (!engine->packages->HasPackageFile(entry.packageName))
				return false;
			entry.package = engine->packages->GetPackage(entry.packageName);
			if (!entry.package)
				return false;
		}
		entry.objectBase = base;
		base += entry.package->GetExportCount();
	}
	return true;
}

int RemoteConnection::PackageMapMaxObjectIndex() const
{
	if (packageMapList.empty() || !packageMapList.back().package)
		return 0;
	return packageMapList.back().objectBase + packageMapList.back().package->GetExportCount();
}

// Reimplements UPackageMap::IndexToObject (UnCoreNet.cpp): walk the package list in order,
// subtracting each package's export count, until flatIndex lands inside one - then resolve it
// through that package's own export table. Assumes ResolvePackageMap() already succeeded; returns
// nullptr for an out-of-range index or an unresolved package.
UObject* RemoteConnection::PackageMapIndexToObject(int flatIndex) const
{
	if (flatIndex < 0)
		return nullptr;

	for (const RemotePackageMapEntry& entry : packageMapList)
	{
		if (!entry.package)
			return nullptr;
		int count = entry.package->GetExportCount();
		if (flatIndex < count)
			return entry.package->GetUObject(flatIndex + 1); // Package::GetUObject uses a 1-based export convention
		flatIndex -= count;
	}
	return nullptr;
}

// Reimplements UPackageMapLevel::SerializeObject's read path (UnNetDrv.cpp): one bit selects
// between a live actor-channel reference and a static package-object reference (see
// RemoteConnection.h's DecodeObjectRef comment).
UObject* RemoteConnection::DecodeObjectRef(BitReader& br)
{
	constexpr uint32_t MAX_CHANNELS_LOCAL = 1023; // matches MAX_CHANNELS below - kept in sync there

	if (br.ReadBit())
	{
		// Dynamic actor reference (or None): a channel index on this connection, not a package
		// object index - real UT99 resolves this to whichever actor currently owns that channel.
		uint32_t chIndex = br.ReadInt(MAX_CHANNELS_LOCAL);
		if (br.IsError() || chIndex == 0)
			return nullptr;
		auto it = activeActorChannels.find((int)chIndex);
		return it != activeActorChannels.end() ? static_cast<UObject*>(it->second) : nullptr;
	}
	else
	{
		// Static object reference: a flat index into the connection's known packages.
		uint32_t index = br.ReadInt((uint32_t)PackageMapMaxObjectIndex());
		if (br.IsError())
			return nullptr;
		return PackageMapIndexToObject((int)index);
	}
}

// Reimplements the per-ValueType NetSerializeItem formats confirmed against real UT99 source
// (Core/Src/UnProp.cpp) - see RemoteConnection.h's comment on this function for what "false" means.
bool RemoteConnection::DecodePropertyValue(BitReader& br, UProperty* prop, void* elementPtr)
{
	switch (prop->ValueType)
	{
	case ExpressionValueType::ValueByte:
	{
		UByteProperty* byteProp = UObject::TryCast<UByteProperty>(prop);
		int bits = (byteProp && byteProp->EnumType) ? std::max(1, (int)std::ceil(std::log2((double)std::max<size_t>(2, byteProp->EnumType->ElementNames.size())))) : 8;
		*(uint8_t*)elementPtr = (uint8_t)br.ReadBits(bits);
		return true;
	}
	case ExpressionValueType::ValueInt:
		*(int32_t*)elementPtr = (int32_t)br.ReadBits(32);
		return true;
	case ExpressionValueType::ValueFloat:
	{
		uint32_t bits = br.ReadBits(32);
		*(float*)elementPtr = *reinterpret_cast<float*>(&bits);
		return true;
	}
	case ExpressionValueType::ValueBool:
	{
		UBoolProperty* boolProp = UObject::TryCast<UBoolProperty>(prop);
		boolProp->SetBool(elementPtr, br.ReadBit() != 0);
		return true;
	}
	case ExpressionValueType::ValueObject:
		*(UObject**)elementPtr = DecodeObjectRef(br);
		return true;
	case ExpressionValueType::ValueVector:
	{
		// Compressed varying-width vector (UStructProperty::NetSerializeItem's "Vector" case):
		// a 4-bit magnitude-class selector, then each axis biased into that many bits.
		uint32_t bits = br.ReadInt(16);
		int bias = 1 << (bits + 1);
		uint32_t maxVal = 1u << (bits + 2);
		uint32_t dx = br.ReadInt(maxVal), dy = br.ReadInt(maxVal), dz = br.ReadInt(maxVal);
		*(vec3*)elementPtr = vec3((float)((int)dx - bias), (float)((int)dy - bias), (float)((int)dz - bias));
		return true;
	}
	case ExpressionValueType::ValueRotator:
	{
		// Per-axis "is nonzero" bit gates whether a byte (the axis's high 8 bits) follows.
		Rotator r(0, 0, 0);
		if (br.ReadBit()) r.Pitch = ((int)br.ReadBits(8)) << 8;
		if (br.ReadBit()) r.Yaw = ((int)br.ReadBits(8)) << 8;
		if (br.ReadBit()) r.Roll = ((int)br.ReadBits(8)) << 8;
		*(Rotator*)elementPtr = r;
		return true;
	}
	case ExpressionValueType::ValueStruct:
	{
		UStructProperty* structProp = UObject::TryCast<UStructProperty>(prop);
		if (structProp && structProp->Struct && structProp->Struct->Name == "Plane")
		{
			// 4x raw 16-bit values (X,Y,Z,W), uncompressed.
			float* p = (float*)elementPtr;
			for (int i = 0; i < 4; i++)
				p[i] = (float)(int16_t)br.ReadBits(16);
			return true;
		}
		// Name/array/map and any other struct type aren't handled yet (see the class doc comment's
		// Deferred items) - the caller must stop decoding the rest of this bunch.
		return false;
	}
	default:
		return false;
	}
}

// Once every USES package is confirmed present locally, loads the map WELCOME named as a real
// network client (reimplements UGameEngine::LoadMap's Pending-level path - real UT99 source,
// UnGame.cpp - via Engine::LoadMap's isNetworkClient flag: same .unr every client and the server
// itself loaded, no local GameInfo/InitGame, non-static/non-bNoDelete actors torn down since
// they're not the server's live copies). No-ops if a map was already loaded for this connection, or
// if any required package still isn't resolvable (see ResolvePackageMap) - the latter is a known,
// explicitly out-of-scope gap (downloaded packages aren't loadable by PackageManager yet).
void RemoteConnection::TryLoadNetworkMap(const std::string& levelName)
{
	if (loadedNetworkMap || levelName.empty() || !engine || !engine->packages)
		return;

	if (!ResolvePackageMap())
	{
		// Not fatal - e.g. a package that's still mid-download (see FinishDownload) or, right now,
		// one PackageManager can't yet resolve out of the download cache at all (a known, explicitly
		// out-of-scope gap - see the class doc comment). Remember the level name so Tick() keeps
		// retrying instead of getting stuck after one failed attempt, in case that ever changes.
		pendingNetworkMapLevel = levelName;
		// Don't clobber a "Downloading X: N%" line already on screen with this less useful one -
		// only show it while nothing more specific is happening (e.g. once every download so far
		// has finished but the map still can't load - a known, out-of-scope gap, see the class doc
		// comment - or before any download has started at all).
		if (statusLine.empty() || statusLine.rfind("Downloaded ", 0) == 0)
			statusLine = "Waiting for required packages before loading \"" + levelName + "\"...";
		if (DebugNet())
			fprintf(stderr, "[Net] RemoteConnection: not every required package is available locally yet - can't load \"%s\" as a network client\n", levelName.c_str());
		return;
	}

	UnrealURL url;
	url.Map = levelName;
	if (url.Map.find('.') == std::string::npos)
		url.Map += "." + engine->packages->GetMapExtension();

	statusLine = "Loading map \"" + url.Map + "\"...";
	try
	{
		engine->LoadMap(url, {}, /*isNetworkClient=*/true);
		loadedNetworkMap = true;
		pendingNetworkMapLevel.clear();
		statusLine.clear();
		if (DebugNet())
			fprintf(stderr, "[Net] RemoteConnection: loaded \"%s\" as a network client\n", url.Map.c_str());
	}
	catch (const std::exception& e)
	{
		pendingNetworkMapLevel.clear(); // a real load failure (bad map, script error, ...) - retrying won't help
		statusLine = "Failed to load \"" + url.Map + "\": " + e.what();
		if (DebugNet())
			fprintf(stderr, "[Net] RemoteConnection: failed to load \"%s\" as a network client: %s\n", url.Map.c_str(), e.what());
	}
}

// Treats the first dynamically-spawned PlayerPawn received after JOIN as our own and possesses it -
// see RemoteConnection.h's class doc comment for why this is a heuristic rather than the exact real
// mechanism (UNetConnection::HandleClientPlayer in real UT99 source flips this from Actor->
// bNetOwner, whose own trigger wasn't fully pinned down from source this session).
void RemoteConnection::PossessIfOwnPawn(UActor* actor)
{
	if (possessedOwnPawn || !engine)
		return;

	UPlayerPawn* pawn = UObject::TryCast<UPlayerPawn>(actor);
	if (!pawn)
		return;

	possessedOwnPawn = true;
	engine->PossessNetworkActor(pawn);
	if (DebugNet())
		fprintf(stderr, "[Net] RemoteConnection: possessing \"%s\" as our own pawn\n", pawn->Name.ToString().c_str());
}

// Decodes one actor-channel bunch (reimplements UActorChannel::ReceivedBunch - real UT99 source,
// UnChan.cpp): a fresh channel's bunch must be bOpen and resolves an object reference to either an
// already-loaded actor or a class to dynamically spawn (see DecodeObjectRef); either way, every
// bunch on an established channel then carries zero or more RepIndex-tagged property values (see
// ClassNetCache.h) or RPC calls, back to back, until the bunch's content bits run out.
void RemoteConnection::HandleActorBunch(const uint8_t* packetData, int packetSize, int chIndex, bool bOpen, bool bClose, int contentBitOffset, int contentBits)
{
	// Without a loaded network map there's no valid PackageMap (ResolvePackageMap only ever
	// partially resolves packageMapList when it fails - see TryLoadNetworkMap) and no level for
	// these actors to attach to anyway. Bailing out here matters, not just as a nicety: with an
	// unresolved PackageMap, PackageMapMaxObjectIndex() falls back to 0, which makes
	// DecodeObjectRef's ReadInt(0) consume zero bits and always resolve to flat index 0 - silently
	// wrong output (always the same bogus actor) plus a desynced bit position for the rest of the
	// bunch, rather than a clean failure. Confirmed against a real server: every actor channel
	// misresolved to the same actor until this guard was added.
	if (!loadedNetworkMap)
		return;

	int byteOff = contentBitOffset / 8;
	int subBit = contentBitOffset % 8;
	if (byteOff >= packetSize)
		return;

	BitReader br(packetData + byteOff, packetSize - byteOff, subBit + contentBits);
	if (subBit)
		br.ReadBits(subBit);

	UActor* actor = nullptr;
	auto existing = activeActorChannels.find(chIndex);
	if (existing != activeActorChannels.end())
	{
		actor = existing->second;
	}
	else
	{
		if (!bOpen)
			return; // a channel we haven't seen before must be introduced by its bOpen bunch

		UObject* obj = DecodeObjectRef(br);
		if (br.IsError())
			return;

		actor = UObject::TryCast<UActor>(obj);
		if (!actor)
		{
			UClass* spawnClass = UObject::TryCast<UClass>(obj);
			if (!spawnClass)
			{
				if (DebugNet())
					fprintf(stderr, "[Net] RemoteConnection: actor channel %d bOpen resolved to neither an actor nor a class - ignoring\n", chIndex);
				return;
			}

			// Dynamic spawn: a raw, uncompressed FVector follows (3x 32-bit floats via a plain
			// Ar << X << Y << Z in real UT99 source - NOT the compressed vector encoding that only
			// applies inside the property stream below).
			uint32_t bx = br.ReadBits(32), by = br.ReadBits(32), bz = br.ReadBits(32);
			if (br.IsError())
				return;
			vec3 location(*reinterpret_cast<float*>(&bx), *reinterpret_cast<float*>(&by), *reinterpret_cast<float*>(&bz));

			if (!engine || !engine->LevelInfo)
				return;
			actor = engine->LevelInfo->Spawn(spawnClass, std::nullopt, std::nullopt, location, Rotator(0, 0, 0));
			if (!actor)
			{
				if (DebugNet())
					fprintf(stderr, "[Net] RemoteConnection: failed to spawn \"%s\" for actor channel %d\n", spawnClass->Name.ToString().c_str(), chIndex);
				return;
			}
			if (DebugNet())
				fprintf(stderr, "[Net] RemoteConnection: actor channel %d spawned \"%s\"\n", chIndex, spawnClass->Name.ToString().c_str());
		}
		else if (DebugNet())
		{
			fprintf(stderr, "[Net] RemoteConnection: actor channel %d references existing actor \"%s\"\n", chIndex, actor->Name.ToString().c_str());
		}

		activeActorChannels[chIndex] = actor;
		actorChannelsByActor[actor] = chIndex;
		PossessIfOwnPawn(actor);
	}

	if (!actor || !actor->Class)
		return;

	ClassNetCache* classCache = ClassNetCache::Get(actor->Class);
	if (!classCache)
		return;

	uint32_t repIndex = br.ReadInt((uint32_t)classCache->GetMaxIndex());
	UField* field = br.IsError() ? nullptr : classCache->GetFromIndex((int)repIndex);
	while (field)
	{
		UProperty* prop = UObject::TryCast<UProperty>(field);
		if (prop)
		{
			int element = 0;
			if (prop->ArrayDimension != 1)
				element = (int)br.ReadBits(8);

			void* elementPtr = prop->GetElement(actor->GetProperty(prop), element);
			if (!DecodePropertyValue(br, prop, elementPtr))
			{
				if (DebugNet())
					fprintf(stderr, "[Net] RemoteConnection: actor channel %d: unsupported property type for \"%s\" - abandoning rest of this bunch\n", chIndex, prop->Name.ToString().c_str());
				break;
			}
		}
		else
		{
			// RPC call: parse (and discard) parameters to stay bit-aligned - actually invoking
			// UnrealScript functions from network RPCs is deferred (see the class doc comment).
			UFunction* function = UObject::TryCast<UFunction>(field);
			if (!function)
				break;

			bool paramError = false;
			for (UProperty* param : function->Properties)
			{
				if (!AnyFlags(param->PropFlags, PropertyFlags::Parm) || AnyFlags(param->PropFlags, PropertyFlags::ReturnParm))
					continue;

				bool isBool = param->ValueType == ExpressionValueType::ValueBool;
				bool present = isBool || br.ReadBit() != 0;
				if (br.IsError())
				{
					paramError = true;
					break;
				}
				if (present)
				{
					uint8_t scratch[16] = {};
					if (!DecodePropertyValue(br, param, scratch))
					{
						paramError = true;
						break;
					}
				}
			}
			if (paramError)
			{
				if (DebugNet())
					fprintf(stderr, "[Net] RemoteConnection: actor channel %d: couldn't parse parameters for RPC \"%s\" - abandoning rest of this bunch\n", chIndex, function->Name.ToString().c_str());
				break;
			}
		}

		if (br.IsError())
			break;
		repIndex = br.ReadInt((uint32_t)classCache->GetMaxIndex());
		field = br.IsError() ? nullptr : classCache->GetFromIndex((int)repIndex);
	}

	if (bClose)
	{
		activeActorChannels.erase(chIndex);
		actorChannelsByActor.erase(actor);
	}
}

void RemoteConnection::Tick(float elapsed)
{
	if (handle == remote_invalid_socket_value)
		return;

	if (!loadedNetworkMap && !pendingNetworkMapLevel.empty())
	{
		networkMapRetryCooldown -= elapsed;
		if (networkMapRetryCooldown <= 0.0f)
		{
			TryLoadNetworkMap(pendingNetworkMapLevel); // retry - see the comment where this was set
			networkMapRetryCooldown = 2.0f; // still failing while a package downloads is normal, not worth retrying (or re-logging) every single frame
		}
	}

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

			ParsedPacket packet = ParsePacket((const uint8_t*)buffer, received);
			if (!packet.valid)
			{
				if (DebugNet())
					fprintf(stderr, "[Net] RemoteConnection: received data too short to contain a PacketId - ignoring\n");
				continue;
			}
			if (DebugNet() && (packet.acks.size() > 1 || packet.bunches.size() > 1))
				fprintf(stderr, "[Net] RemoteConnection: packet %d carries %d ack(s) and %d bunch(es)\n",
					packet.packetId, (int)packet.acks.size(), (int)packet.bunches.size());

			// Every packet needs to be acked, and - as found earlier this session - individually,
			// not just "ack the latest and let it imply everything before that arrived": acking
			// only the newest PacketId after draining a batch of received packets left a real
			// server re-sending the exact same reliable bunch content over and over, meaning
			// AckPacketId is a per-packet acknowledgement, not a cumulative one.
			bool acked = false;

			for (const ParsedBunch& bunch : packet.bunches)
			{
				// Record every channel index the server ever opens, regardless of type or whether
				// we otherwise do anything with this bunch - AllocateFileChannelIndex() needs this
				// to avoid picking an index the server already claimed for something else (e.g. one
				// of its own actor channels).
				knownChannelIndices.insert(bunch.chIndex);

				if (bunch.chType == CHTYPE_File)
				{
					auto downloadIt = activeDownloads.find(bunch.chIndex);
					if (downloadIt != activeDownloads.end())
					{
						std::vector<uint8_t> chunk = ReadBunchRawBytes((const uint8_t*)buffer, received, bunch);
						downloadIt->second.data.insert(downloadIt->second.data.end(), chunk.begin(), chunk.end());
						uint32_t fileSize = downloadIt->second.package.fileSize;
						if (fileSize > 0)
						{
							int percent = (int)(100.0 * downloadIt->second.data.size() / fileSize);
							statusLine = "Downloading " + downloadIt->second.package.packageName + ": " + std::to_string(percent) +
								"% (" + FormatMegabytes(downloadIt->second.data.size()) + "/" + FormatMegabytes(fileSize) + ")";
						}
						if (bunch.bClose || downloadIt->second.data.size() >= fileSize)
							FinishDownload(bunch.chIndex, true); // may overwrite statusLine again - see FinishDownload
					}
					continue;
				}

				if (bunch.chType == CHTYPE_Actor)
				{
					HandleActorBunch((const uint8_t*)buffer, received, bunch.chIndex, bunch.bOpen, bunch.bClose, bunch.contentBitOffset, bunch.contentBits);
					continue;
				}

				if (bunch.chIndex != 0 || bunch.chType != CHTYPE_Control)
					continue; // only the control, file and actor channels are understood right now

				std::vector<std::string> messages = ReadBunchStrings((const uint8_t*)buffer, received, bunch);
				for (const std::string& text : messages)
				{
					if (DebugNet())
						fprintf(stderr, "[Net] RemoteConnection: control message: \"%s\"\n", text.c_str());

					HandlePackageListMessage(text);

					// Second step of the handshake: once the server's CHALLENGE arrives, reply with
					// a real NETSPEED+LOGIN message, using a RESPONSE value actually computed from
					// the server's challenge (see ChallengeResponse above) instead of a stale
					// replayed one - which a real server correctly rejects with "FAILURE CHALLENGE".
					if (!sentLoginReply && text.rfind("CHALLENGE ", 0) == 0)
					{
						size_t pos = text.find("CHALLENGE=", strlen("CHALLENGE "));
						if (pos != std::string::npos)
						{
							pos += strlen("CHALLENGE=");
							int32_t challenge = (int32_t)strtol(text.c_str() + pos, nullptr, 10);
							int32_t response = ChallengeResponse(challenge);
							sentLoginReply = true;
							statusLine = "Logging in...";
							if (DebugNet())
								fprintf(stderr, "[Net] RemoteConnection: parsed CHALLENGE=%d from server packet %d, computed RESPONSE=%d\n", challenge, packet.packetId, response);

							// Our packet 0 was the HELLO, so this is packet 1; the control
							// channel's first reliable bunch was HELLO (ChSequence=1), so this is
							// ChSequence=2.
							std::vector<uint8_t> loginPacket = BuildLoginPacket(1, packet.packetId, 2, response);
							int sent = send(handle, (const char*)loginPacket.data(), (int)loginPacket.size(), 0);
							if (DebugNet())
								fprintf(stderr, "[Net] RemoteConnection: sent %d-byte NETSPEED+LOGIN reply -> %d\n", (int)loginPacket.size(), sent);
							acked = true; // the login packet above already acks this server packet
						}
					}
					// Third step: once the server's WELCOME arrives (after LOGIN, it sends the
					// required-package list, then WELCOME), tell it we're entering the game. A real
					// client's JOIN is what makes the server start spawning actors and replicating
					// real gameplay state; once every required package is confirmed present
					// locally, WELCOME's LEVEL= now also triggers a real network-client-mode level
					// load (see TryLoadNetworkMap) so there's an actual level for those actor-channel
					// bunches to populate.
					else if (sentLoginReply && !sentJoin && text.rfind("WELCOME ", 0) == 0)
					{
						sentJoin = true;
						std::vector<uint8_t> joinPacket = BuildJoinPacket(nextOutgoingPacketId++, packet.packetId, AllocateChSequence(0));
						int sent = send(handle, (const char*)joinPacket.data(), (int)joinPacket.size(), 0);
						if (DebugNet())
							fprintf(stderr, "[Net] RemoteConnection: parsed \"%s\", sent %d-byte JOIN reply -> %d\n", text.c_str(), (int)joinPacket.size(), sent);
						acked = true; // the JOIN packet above already acks this server packet

						size_t levelPos = text.find("LEVEL=");
						if (levelPos != std::string::npos)
						{
							levelPos += strlen("LEVEL=");
							size_t levelEnd = text.find(' ', levelPos);
							std::string levelName = text.substr(levelPos, levelEnd == std::string::npos ? std::string::npos : levelEnd - levelPos);
							TryLoadNetworkMap(levelName);
						}
					}
				}
			}

			if (!acked)
			{
				std::vector<uint8_t> ackPacket = BuildAckPacket(nextOutgoingPacketId++, packet.packetId);
				int sent = send(handle, (const char*)ackPacket.data(), (int)ackPacket.size(), 0);
				if (DebugNet())
					fprintf(stderr, "[Net] RemoteConnection: sent %d-byte ack of server packet %d -> %d\n", (int)ackPacket.size(), packet.packetId, sent);
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
