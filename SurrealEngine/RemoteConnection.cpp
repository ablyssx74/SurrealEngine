
#include "Precomp.h"
#include <chrono>
#include "VM/Frame.h"
#include "VM/ExpressionValue.h"
#include "VM/ExpressionEvaluator.h"
#include "VM/Bytecode.h"
#include "Packages/Engine/UViewport.h"
#include "Packages/Engine/Actors/Info/UZoneInfo.h"
#include "Packages/Engine/Actors/Inventory/UWeapon.h"
#include <set>
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
		int GetBit(int i) const { return (bytes[i / 8] >> (i % 8)) & 1; }

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

void RemoteConnection::ResetSession()
{
	sentLoginReply = false;
	sentJoin = false;
	loadedNetworkMap = false;
	pendingNetworkMapLevel.clear();
	networkMapRetryCooldown = 0.0f;
	possessedOwnPawn = false;
	nextOutgoingPacketId = 2; // 0 is HELLO, 1 is NETSPEED+LOGIN
	nextChannelIndex = 1;
	knownChannelIndices.clear();
	nextChSequenceByChannel.clear();
	pendingDownloads.clear();
	activeDownloads.clear();
	packageMapList.clear();
	activeActorChannels.clear();
	actorChannelsByActor.clear();
	pendingReliable.clear();
	levelChangeRequested = false;
	gaveUp = false;
	helloAttempts = 0;
}

void RemoteConnection::RequestLevelChange(const std::string& url)
{
	if (handle == remote_invalid_socket_value)
		return;
	if (DebugNet())
		fprintf(stderr, "[Net] RemoteConnection: server requested a level change (%s) - reconnecting\n", url.c_str());
	levelChangeRequested = true;
}

bool RemoteConnection::Connect(const std::string& host, int port)
{
	Disconnect();
	ResetSession();

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

	lastHelloAt = netClock;
	lastPacketAt = netClock;
	helloAttempts = 1;

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

	std::vector<uint8_t> requestPacket = BuildFileChannelRequest(AllocatePacketId(), chIndex, chSequence, pkg.guidHex);
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
		// Saved under the package's own name (e.g. "EpicCustomModels.u"), with its real extension
		// from the server's FNAME=, not a GUID-named ".uxx" regardless of actual type - a real
		// UT99 client caches by GUID instead (letting distinct generations of a same-named package
		// coexist), but this engine already identifies every other package purely by name
		// everywhere else, so matching that - and registering the result below - is what actually
		// makes a downloaded package resolvable at all, this session and after a restart (see
		// RegisterDownloadedPackage/ScanPaths's cache-folder scan) instead of just sitting there as
		// bytes on disk nothing ever looks at again.
		std::filesystem::path cacheFolder = engine->packages->GetCacheFolderPath();
		Directory::create(cacheFolder.string());
		std::string extension = std::filesystem::path(download.package.fileName).extension().string();
		std::filesystem::path dest = cacheFolder / (download.package.packageName + extension);
		File::write_all_bytes(dest.string(), download.data.data(), download.data.size());
		engine->packages->RegisterDownloadedPackage(download.package.packageName, dest.string());
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
	int nameBase = 0;
	for (RemotePackageMapEntry& entry : packageMapList)
	{
		if (!entry.package)
		{
			if (!engine->packages->HasPackageFile(entry.packageName))
				return false;
			entry.package = engine->packages->GetPackage(entry.packageName);
			if (!entry.package)
				return false;

			// Diagnostic: this engine only ever matched a USES package to a local file by name -
			// never by the GUID the server actually announced for it. A same-named but genuinely
			// different file (e.g. this connection's local install predates or postdates whatever
			// patch level the server runs) has its own, unrelated export table: no amount of
			// generation-clipping arithmetic can align two files that didn't share that history,
			// since "generation N" only means the same thing for files descended from the same
			// lineage. Warn loudly here so a GUID mismatch isn't mistaken for an indexing bug.
			if (DebugNet())
			{
				const uint8_t* localGuid = entry.package->GetGuid();
				char localGuidHex[33];
				for (int i = 0; i < 16; i++)
					snprintf(localGuidHex + i * 2, 3, "%02X", localGuid[i]);
				if (entry.guidHex != localGuidHex)
					fprintf(stderr, "[Net] RemoteConnection: WARNING - local \"%s\" has GUID %s but the server announced GUID %s for it - "
						"this is NOT the same file the server is using, so its object indices cannot possibly line up\n",
						entry.packageName.c_str(), localGuidHex, entry.guidHex.c_str());
			}
		}
		entry.nameBase = nameBase;
		entry.nameCount = entry.package->GetNameCountForGeneration((int)entry.remoteGeneration);
		nameBase += entry.nameCount;
		entry.objectBase = base;
		entry.objectCount = entry.package->GetExportCountForGeneration((int)entry.remoteGeneration);
		if (DebugNet())
			fprintf(stderr, "[Net] RemoteConnection: package map: %-16s remoteGen=%d fullExports=%d -> base=%d count=%d\n",
				entry.packageName.c_str(), (int)entry.remoteGeneration, entry.package->GetExportCount(), base, entry.objectCount);
		base += entry.objectCount;
	}
	return true;
}

int RemoteConnection::PackageMapMaxObjectIndex() const
{
	if (packageMapList.empty() || !packageMapList.back().package)
		return 0;
	return packageMapList.back().objectBase + packageMapList.back().objectCount;
}

int RemoteConnection::PackageMapMaxNameIndex() const
{
	if (packageMapList.empty() || !packageMapList.back().package)
		return 0;
	return packageMapList.back().nameBase + packageMapList.back().nameCount;
}

// The name-table twin of PackageMapIndexToObject: a flat name index is a running sum of each
// package's name count, resolved through that package's own name table.
bool RemoteConnection::PackageMapIndexToName(int flatIndex, std::string& outName) const
{
	if (flatIndex < 0)
		return false;

	for (const RemotePackageMapEntry& entry : packageMapList)
	{
		if (!entry.package)
			return false;
		if (flatIndex < entry.nameCount)
		{
			outName = entry.package->GetName(flatIndex).ToString();
			return true;
		}
		flatIndex -= entry.nameCount;
	}
	return false;
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
		if (flatIndex < entry.objectCount)
			return entry.package->GetUObject(flatIndex + 1); // Package::GetUObject uses a 1-based export convention
		flatIndex -= entry.objectCount;
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
		lastRefWasDynamic = true;
		lastDynamicRefChannel = (int)chIndex;
		if (br.IsError() || chIndex == 0)
			return nullptr;
		auto it = activeActorChannels.find((int)chIndex);
		return it != activeActorChannels.end() ? static_cast<UObject*>(it->second) : nullptr;
	}
	else
	{
		// Static object reference: a flat index into the connection's known packages.
		lastRefWasDynamic = false;
		uint32_t maxIndex = (uint32_t)PackageMapMaxObjectIndex();
		uint32_t index = br.ReadInt(maxIndex);
		if (br.IsError())
			return nullptr;
		UObject* obj = PackageMapIndexToObject((int)index);
		lastStaticRefIndex = (int)index;

		if (DebugNet())
		{
			// Diagnostic: which package/local-offset this flat index actually landed in, and what
			// it resolved to - narrows down whether a resolution failure is this connection's
			// object-index math disagreeing with the server's (index lands in a plausible package
			// but at the wrong local offset, or beyond MaxObjectIndex entirely) versus something
			// else (e.g. bit-alignment drifting upstream of this read).
			int remaining = (int)index;
			std::string where = "out of range";
			for (const RemotePackageMapEntry& entry : packageMapList)
			{
				if (!entry.package)
				{
					where = "package \"" + entry.packageName + "\" not resolved";
					break;
				}
				if (remaining < entry.objectCount)
				{
					where = "package \"" + entry.packageName + "\" local index " + std::to_string(remaining) +
						"/" + std::to_string(entry.objectCount) + " (GEN=" + std::to_string(entry.remoteGeneration) + ")";
					break;
				}
				remaining -= entry.objectCount;
			}
			fprintf(stderr, "[Net] RemoteConnection: static object ref index=%u/%u -> %s -> %s\n",
				index, maxIndex, where.c_str(),
				obj ? (obj->Class ? (obj->Class->Name.ToString() + "'" + obj->Name.ToString() + "'").c_str() : "(no class)") : "(null)");
		}

		return obj;
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
	{
		UObject* obj = DecodeObjectRef(br);

		// Only store an object the property can actually hold. Anything else (e.g. a texture in an
		// Actor-typed Owner) would later be treated as an actor by script/engine code and read
		// garbage - that crashed ULevel::TickActor recursing through Owner().
		UObjectProperty* objProp = UObject::TryCast<UObjectProperty>(prop);
		if (obj && objProp && objProp->ObjectClass)
		{
			bool assignable = false;
			for (UStruct* s = obj->Class; s && !assignable; s = s->BaseStruct)
				assignable = (s == objProp->ObjectClass);
			if (!assignable)
			{
				if (DebugNet())
					fprintf(stderr, "[Net] RemoteConnection: rejected %s '%s' for property \"%s\" (needs %s) | trail: %s\n",
						obj->Class ? obj->Class->Name.ToString().c_str() : "?", obj->Name.ToString().c_str(),
						prop->Name.ToString().c_str(), objProp->ObjectClass->Name.ToString().c_str(), decodeTrail.c_str());
				obj = nullptr;
			}
		}

		*(UObject**)elementPtr = obj;
		return true;
	}
	case ExpressionValueType::ValueColor:
	{
		// A Color (R,G,B,A bytes) goes over the wire as each member's byte in declaration order.
		Color col;
		col.R = (uint8_t)br.ReadBits(8);
		col.G = (uint8_t)br.ReadBits(8);
		col.B = (uint8_t)br.ReadBits(8);
		col.A = (uint8_t)br.ReadBits(8);
		*(Color*)elementPtr = col;
		return !br.IsError();
	}
	case ExpressionValueType::ValueString:
		// UStrProperty::NetSerializeItem is a plain FString: compact length, then that many bytes
		// including the null terminator (BitReader::ReadString already strips it).
		*(std::string*)elementPtr = br.ReadString();
		return !br.IsError();
	case ExpressionValueType::ValueName:
	{
		// A Name on the wire is a flat index into the concatenated name tables of the package list (the
		// name-table twin of a static object ref), bounded by the total name count. Verified against a
		// captured ClientAdjustPosition: the 15 bits read 4680, exactly "PlayerWalking" in Engine's table,
		// and the remaining parameters then ended exactly on the bunch's last bit. (An earlier version
		// read a "hardcoded name" flag bit first; on v469 there is no such bit.)
		uint32_t nameIndex = br.ReadInt((uint32_t)PackageMapMaxNameIndex());
		std::string decoded;
		if (br.IsError() || !PackageMapIndexToName((int)nameIndex, decoded))
			return false;
		if (DebugNet())
			fprintf(stderr, "[Net] RemoteConnection: Name \"%s\" = \"%s\" (flat name index %u/%d)\n", prop->Name.ToString().c_str(), decoded.c_str(), nameIndex, PackageMapMaxNameIndex());
		*(NameString*)elementPtr = NameString(decoded);
		return true;
	}
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
		// Per-axis "is nonzero" bit gates whether the axis value follows. Up to v436 that's one byte
		// (the axis's high 8 bits); v469 sends more precision: 14 bits, i.e. the axis shifted right by 2.
		// The 469 width was found by replaying captured actor bunches offline: it's the only width that
		// makes the great majority of real bunches end exactly on their last bit (see BUNCHEND logging).
		const bool wideRotator = engine && engine->LaunchInfo.ue1Version >= 469;
		const int axisBits = wideRotator ? 14 : 8;
		const int axisShift = wideRotator ? 2 : 8;
		Rotator r(0, 0, 0);
		if (br.ReadBit()) r.Pitch = ((int)br.ReadBits(axisBits)) << axisShift;
		if (br.ReadBit()) r.Yaw = ((int)br.ReadBits(axisBits)) << axisShift;
		if (br.ReadBit()) r.Roll = ((int)br.ReadBits(axisBits)) << axisShift;
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
		if (structProp && structProp->Struct)
		{
			// A struct made only of byte members (Color, and the like) goes over the wire as each
			// member's NetSerializeItem in order - one byte apiece, which is also exactly the struct's
			// raw memory, so both ways of describing it agree. Other generic structs aren't handled.
			bool allBytes = !structProp->Struct->Properties.empty();
			for (UProperty* member : structProp->Struct->Properties)
				allBytes = allBytes && member->ArrayDimension == 1 && UObject::TryCast<UByteProperty>(member) && !UObject::TryCast<UByteProperty>(member)->EnumType;
			if (allBytes)
			{
				for (UProperty* member : structProp->Struct->Properties)
					*(static_cast<uint8_t*>(elementPtr) + member->DataOffset.DataOffset) = (uint8_t)br.ReadBits(8);
				return !br.IsError();
			}
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

		// The package map was resolved before the level was loaded, and GetPackage() gave the level's entry a
		// separate copy of the map file. Static references to level actors (LevelInfo, zones, movers,
		// pickups, ...) must resolve into the level that is actually running - Engine::LevelPackage -
		// or everything the server replicates to them lands on objects the level never uses.
		if (engine->LevelPackage)
		{
			for (RemotePackageMapEntry& entry : packageMapList)
			{
				if (entry.package && entry.package != engine->LevelPackage && entry.packageName == engine->LevelPackage->GetPackageName().ToString())
				{
					if (DebugNet())
						fprintf(stderr, "[Net] RemoteConnection: pointing the package map's \"%s\" entry at the running level package\n", entry.packageName.c_str());
					entry.package = engine->LevelPackage;
				}
			}
		}

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

int RemoteConnection::AllocatePacketId()
{
	int id = nextOutgoingPacketId;
	nextOutgoingPacketId = (nextOutgoingPacketId + 1) % MAX_PACKETID;
	return id;
}

// Decodes one RPC parameter into a script value. Each type is decoded by DecodePropertyValue into a
// correctly typed temporary, then wrapped in an ExpressionValue.
bool RemoteConnection::DecodeParamValue(BitReader& br, UProperty* param, ExpressionValue& out)
{
	switch (param->ValueType)
	{
	case ExpressionValueType::ValueByte: { uint8_t v = 0; if (!DecodePropertyValue(br, param, &v)) return false; out = ExpressionValue::ByteValue(v); return true; }
	case ExpressionValueType::ValueInt: { int32_t v = 0; if (!DecodePropertyValue(br, param, &v)) return false; out = ExpressionValue::IntValue(v); return true; }
	case ExpressionValueType::ValueFloat: { float v = 0; if (!DecodePropertyValue(br, param, &v)) return false; out = ExpressionValue::FloatValue(v); return true; }
	case ExpressionValueType::ValueBool:
	{
		uint32_t storage = 0; // a bool property's value lives in a mask bit of a 32-bit word
		UBoolProperty* boolProp = UObject::TryCast<UBoolProperty>(param);
		if (!boolProp || !DecodePropertyValue(br, param, &storage))
			return false;
		out = ExpressionValue::BoolValue(boolProp->GetBool(&storage));
		return true;
	}
	case ExpressionValueType::ValueObject: { UObject* v = nullptr; if (!DecodePropertyValue(br, param, &v)) return false; out = ExpressionValue::ObjectValue(v); return true; }
	case ExpressionValueType::ValueVector: { vec3 v(0.0f, 0.0f, 0.0f); if (!DecodePropertyValue(br, param, &v)) return false; out = ExpressionValue::VectorValue(v); return true; }
	case ExpressionValueType::ValueRotator: { Rotator v(0, 0, 0); if (!DecodePropertyValue(br, param, &v)) return false; out = ExpressionValue::RotatorValue(v); return true; }
	case ExpressionValueType::ValueString: { std::string v; if (!DecodePropertyValue(br, param, &v)) return false; out = ExpressionValue::StringValue(v); return true; }
	case ExpressionValueType::ValueName: { NameString v; if (!DecodePropertyValue(br, param, &v)) return false; out = ExpressionValue::NameValue(v); return true; }
	case ExpressionValueType::ValueColor: { Color v = {}; if (!DecodePropertyValue(br, param, &v)) return false; out = ExpressionValue::ColorValue(v); return true; }
	default: return false;
	}
}

// Client->server RPC (see the declaration). The wire form mirrors what HandleActorBunch decodes:
// the function's RepIndex (ReadInt bounded by the class's MaxIndex), then each parameter in order - a
// bool is just its bit, anything else is a "present" bit (set when the value isn't zero) followed by
// the value itself when present.
bool RemoteConnection::TrySendRPC(UObject* instance, UFunction* function, const Array<ExpressionValue>& args)
{
	if (!loadedNetworkMap || handle == remote_invalid_socket_value || !function || !AllFlags(function->FuncFlags, FunctionFlags::Net))
		return false;

	UActor* actor = UObject::TryCast<UActor>(instance);
	if (!actor || !actor->Class)
		return false;

	auto channelIt = actorChannelsByActor.find(actor);
	if (channelIt == actorChannelsByActor.end())
		return false; // not an actor the server replicates to us

	const std::string functionName = function->Name.ToString();
	if (actor->Role() >= ROLE_Authority)
		return false;
	if (functionName.compare(0, 10, "ServerMove") == 0 && args.size() > 0 && args[0].GetType() == ExpressionValueType::ValueFloat)
		lastMoveTimeStamp = args[0].ToFloat();

	// Is this function replicated from here to the server? The class script's replication block gives
	// each net function a condition - "reliable if( Role<ROLE_Authority ) NextWeapon, ServerMove" - and the
	// function remembers where in the declaring class's bytecode that condition lives (ReplicationOffset).
	// Evaluating it in the actor's context is exactly how the real engine decides, and it is what makes
	// exec functions such as NextWeapon (which the server, not the client, must run) go over the wire.
	bool replicatesToServer = false;
	bool evaluated = false;
	try
	{
		UClass* declaringClass = UObject::TryCast<UClass>(function->Outer());
		if (declaringClass && declaringClass->Code)
		{
			int statementIndex = declaringClass->Code->FindStatementIndex(function->ReplicationOffset);
			if (statementIndex >= 0 && statementIndex < (int)declaringClass->Code->Statements.size())
			{
				ExpressionEvalResult result = ExpressionEvaluator::Eval(declaringClass->Code->Statements[statementIndex], actor, actor, nullptr);
				if (result.Value.GetType() != ExpressionValueType::Nothing)
				{
					replicatesToServer = result.Value.ToBool();
					evaluated = true;
				}
			}
		}
	}
	catch (const std::exception&)
	{
	}
	if (!evaluated)
		replicatesToServer = functionName.compare(0, 6, "Server") == 0; // fallback: the naming convention for client->server functions
	if (!replicatesToServer)
		return false;

	ClassNetCache* classCache = ClassNetCache::Get(actor->Class);
	int netIndex = classCache ? classCache->GetFieldNetIndex(function) : -1;
	if (netIndex < 0)
		return false;

	const bool wideRotator = engine && engine->LaunchInfo.ue1Version >= 469;

	auto encodeObject = [&](BitWriter& bw, UObject* obj) -> bool
	{
		if (!obj)
		{
			bw.WriteBit(1); // a dynamic ref to channel 0 is None
			bw.WriteInt(0, MAX_CHANNELS);
			return true;
		}
		if (UActor* objActor = UObject::TryCast<UActor>(obj))
		{
			auto it = actorChannelsByActor.find(objActor);
			if (it != actorChannelsByActor.end())
			{
				bw.WriteBit(1);
				bw.WriteInt((uint32_t)it->second, MAX_CHANNELS);
				return true;
			}
		}
		for (const RemotePackageMapEntry& entry : packageMapList)
		{
			if (entry.package && entry.package == obj->package && (int)obj->exportIndex < entry.objectCount)
			{
				bw.WriteBit(0);
				bw.WriteInt((uint32_t)(entry.objectBase + (int)obj->exportIndex), (uint32_t)PackageMapMaxObjectIndex());
				return true;
			}
		}
		return false;
	};

	auto isZero = [](UProperty* prop, const ExpressionValue& v) -> bool
	{
		switch (prop->ValueType)
		{
		case ExpressionValueType::ValueByte: return v.ToByte() == 0;
		case ExpressionValueType::ValueInt: return v.ToInt() == 0;
		case ExpressionValueType::ValueFloat: return v.ToFloat() == 0.0f;
		case ExpressionValueType::ValueObject: return v.ToObject() == nullptr;
		case ExpressionValueType::ValueVector: { const vec3& x = v.ToVector(); return x.x == 0.0f && x.y == 0.0f && x.z == 0.0f; }
		case ExpressionValueType::ValueRotator: { const Rotator& r = v.ToRotator(); return r.Pitch == 0 && r.Yaw == 0 && r.Roll == 0; }
		case ExpressionValueType::ValueString: return v.ToString().empty();
		case ExpressionValueType::ValueColor: { const Color& k = v.ToColor(); return k.R == 0 && k.G == 0 && k.B == 0 && k.A == 0; }
		default: return false;
		}
	};

	auto encodeValue = [&](BitWriter& bw, UProperty* prop, const ExpressionValue& v) -> bool
	{
		switch (prop->ValueType)
		{
		case ExpressionValueType::ValueByte:
		{
			UByteProperty* byteProp = UObject::TryCast<UByteProperty>(prop);
			int bits = (byteProp && byteProp->EnumType) ? std::max(1, (int)std::ceil(std::log2((double)std::max<size_t>(2, byteProp->EnumType->ElementNames.size())))) : 8;
			bw.WriteBits(v.ToByte(), bits);
			return true;
		}
		case ExpressionValueType::ValueInt: bw.WriteBits((uint32_t)v.ToInt(), 32); return true;
		case ExpressionValueType::ValueFloat: { float f = v.ToFloat(); uint32_t bits; memcpy(&bits, &f, 4); bw.WriteBits(bits, 32); return true; }
		case ExpressionValueType::ValueObject: return encodeObject(bw, v.ToObject());
		case ExpressionValueType::ValueVector:
		{
			// The mirror of the decoder: a magnitude class (the smallest "bits" whose bias exceeds the
			// largest component), then each component biased into bits+2 bits.
			const vec3& vec = v.ToVector();
			int x = (int)std::lround(vec.x), y = (int)std::lround(vec.y), z = (int)std::lround(vec.z);
			int largest = std::max(std::max(std::abs(x), std::abs(y)), std::abs(z));
			int bits = 0;
			while (bits < 15 && (1 << (bits + 1)) <= largest)
				bits++;
			int bias = 1 << (bits + 1);
			int maxVal = 1 << (bits + 2);
			auto biased = [&](int comp) { return (uint32_t)std::min(std::max(comp + bias, 0), maxVal - 1); };
			bw.WriteInt((uint32_t)bits, 16);
			bw.WriteInt(biased(x), (uint32_t)maxVal);
			bw.WriteInt(biased(y), (uint32_t)maxVal);
			bw.WriteInt(biased(z), (uint32_t)maxVal);
			return true;
		}
		case ExpressionValueType::ValueRotator:
		{
			const Rotator& r = v.ToRotator();
			const int axisBits = wideRotator ? 14 : 8;
			const int axisShift = wideRotator ? 2 : 8;
			const uint32_t mask = (1u << axisBits) - 1;
			for (int axis : { r.Pitch, r.Yaw, r.Roll })
			{
				uint32_t value = ((uint32_t)axis >> axisShift) & mask;
				bw.WriteBit(value != 0 ? 1 : 0);
				if (value != 0)
					bw.WriteBits(value, axisBits);
			}
			return true;
		}
		case ExpressionValueType::ValueString: bw.WriteString(v.ToString()); return true;
		case ExpressionValueType::ValueColor: { const Color& k = v.ToColor(); bw.WriteBits(k.R, 8); bw.WriteBits(k.G, 8); bw.WriteBits(k.B, 8); bw.WriteBits(k.A, 8); return true; }
		default: return false;
		}
	};

	BitWriter content;
	content.WriteInt((uint32_t)netIndex, (uint32_t)classCache->GetMaxIndex());

	size_t argIndex = 0;
	for (UProperty* param : function->Properties)
	{
		if (!AnyFlags(param->PropFlags, PropertyFlags::Parm) || AnyFlags(param->PropFlags, PropertyFlags::ReturnParm))
			continue;

		const ExpressionValue* value = argIndex < args.size() ? &args[argIndex] : nullptr;
		argIndex++;
		const bool hasValue = value && value->GetType() != ExpressionValueType::Nothing;

		if (param->ValueType == ExpressionValueType::ValueBool)
		{
			content.WriteBit(hasValue && value->ToBool() ? 1 : 0);
			continue;
		}

		const bool present = hasValue && !isZero(param, *value);
		content.WriteBit(present ? 1 : 0);
		if (present && !encodeValue(content, param, *value))
		{
			if (DebugNet())
				fprintf(stderr, "[Net] RemoteConnection: can't encode parameter \"%s\" of %s - RPC not sent\n", param->Name.ToString().c_str(), functionName.c_str());
			return true; // swallow the call: running a Server* function locally on a client actor would be wrong too
		}
	}

	if (DebugNet())
	{
		static int moveArgLogs = 0;
		std::string desc;
		for (size_t i = 0; i < args.size(); i++)
		{
			if (args[i].GetType() == ExpressionValueType::ValueVector)
			{
				const vec3& vv = args[i].ToVector();
				char b[80]; snprintf(b, sizeof(b), " v%d=(%.0f,%.0f,%.0f)", (int)i, vv.x, vv.y, vv.z); desc += b;
			}
			else if (args[i].GetType() == ExpressionValueType::ValueFloat)
			{
				char b[40]; snprintf(b, sizeof(b), " f%d=%.2f", (int)i, args[i].ToFloat()); desc += b;
			}
			else if (args[i].GetType() == ExpressionValueType::ValueBool)
			{
				desc += args[i].ToBool() ? " b" + std::to_string(i) + "=1" : "";
			}
		}
		if (moveArgLogs < 6 || (moveArgLogs < 2000 && (desc.find(" b") != std::string::npos || desc.find("v1=(0,0,0)") == std::string::npos)))
		{
			moveArgLogs++;
			fprintf(stderr, "[Net] RemoteConnection: %s args:%s\n", functionName.c_str(), desc.c_str());
		}
	}

	if (DebugNet() && functionName.compare(0, 10, "ServerMove") == 0)
	{
		// While a fire button is down, show every argument of the move with its type, to see where the fire flags travel.
		UPlayerPawn* movingPawn = UObject::TryCast<UPlayerPawn>(actor);
		static int fireMoveLogs = 0;
		if (movingPawn && (movingPawn->bFire() || movingPawn->bAltFire()) && fireMoveLogs < 60)
		{
			fireMoveLogs++;
			std::string all;
			size_t i = 0;
			for (UProperty* param : function->Properties)
			{
				if (!AnyFlags(param->PropFlags, PropertyFlags::Parm) || AnyFlags(param->PropFlags, PropertyFlags::ReturnParm))
					continue;
				all += " " + param->Name.ToString() + "=";
				if (i < args.size())
				{
					switch (args[i].GetType())
					{
					case ExpressionValueType::ValueBool: all += args[i].ToBool() ? "T" : "F"; break;
					case ExpressionValueType::ValueByte: all += std::to_string((int)args[i].ToByte()); break;
					case ExpressionValueType::ValueInt: all += std::to_string(args[i].ToInt()); break;
					case ExpressionValueType::ValueFloat: all += std::to_string(args[i].ToFloat()); break;
					case ExpressionValueType::Nothing: all += "-"; break;
					default: all += "?"; break;
					}
				}
				i++;
			}
			fprintf(stderr, "[Net] FIREMOVE bFire=%d bAltFire=%d |%s\n", (int)movingPawn->bFire(), (int)movingPawn->bAltFire(), all.c_str());
		}
	}

	const int chIndex = channelIt->second;
	const bool reliable = AnyFlags(function->FuncFlags, FunctionFlags::NetReliable);
	const int chSequence = reliable ? AllocateChSequence(chIndex) : 0;
	const int packetId = AllocatePacketId();

	BitWriter packet;
	packet.WriteInt((uint32_t)packetId, MAX_PACKETID);
	WriteBunch(packet, /*bOpen=*/false, /*bClose=*/false, reliable, chIndex, CHTYPE_Actor, chSequence, content);
	std::vector<uint8_t> bytes = packet.Finish();
	int sent = send(handle, (const char*)bytes.data(), (int)bytes.size(), 0);

	static std::map<std::string, int> sentRpcCounts;
	int& sentThisFunction = sentRpcCounts[functionName];
	sentThisFunction++;
	if (DebugNet() && (sentThisFunction <= 4 || sentThisFunction % 200 == 0))
		fprintf(stderr, "[Net] RemoteConnection: sent RPC %s on channel %d (%d content bits, %s) -> %d\n", functionName.c_str(), chIndex, content.GetBitCount(), reliable ? "reliable" : "unreliable", sent);

	if (reliable)
	{
		PendingReliable pending;
		pending.packetId = packetId;
		pending.chIndex = chIndex;
		pending.chSequence = chSequence;
		pending.contentBits = content.GetBitCount();
		for (int i = 0; i < pending.contentBits; i += 8)
		{
			uint8_t b = 0;
			for (int j = 0; j < 8 && i + j < pending.contentBits; j++)
				b |= (uint8_t)(content.GetBit(i + j) << j);
			pending.content.push_back(b);
		}
		pending.sentAt = netClock;
		pendingReliable.push_back(std::move(pending));
	}
	return true;
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

		std::string leadBits;
		if (DebugNet())
		{
			BitReader peek(packetData + byteOff, packetSize - byteOff, subBit + contentBits);
			if (subBit)
				peek.ReadBits(subBit);
			for (int i = 0; i < 48 && peek.RemainingBits() > 0; i++)
				leadBits += peek.ReadBit() ? '1' : '0';
		}

		UObject* obj = DecodeObjectRef(br);
		if (br.IsError())
			return;

		if (DebugNet())
			fprintf(stderr, "[Net] RemoteConnection: bOpen ch=%d bits=%d lead=%s -> %s\n", chIndex, contentBits, leadBits.c_str(),
				obj ? ((obj->Class ? obj->Class->Name.ToString() : std::string("?")) + "'" + obj->Name.ToString() + "'").c_str() : "(null)");

		actor = UObject::TryCast<UActor>(obj);
		if (!actor)
		{
			UClass* spawnClass = UObject::TryCast<UClass>(obj);
			if (!spawnClass)
			{
				if (DebugNet())
					fprintf(stderr, "[Net] RemoteConnection: actor channel %d bOpen resolved to neither an actor nor a class - ignoring (%s, bClose=%d, contentBits=%d)\n", chIndex,
						lastRefWasDynamic ? ("dynamic ref to channel " + std::to_string(lastDynamicRefChannel) + (obj ? "" : ", no actor open there")).c_str() : ("static ref, flat index " + std::to_string(lastStaticRefIndex)).c_str(),
						(int)bClose, contentBits);
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
			if (actor && actor->RemoteRole() != ROLE_None)
				std::swap(actor->Role(), actor->RemoteRole()); // the real engine's bRemoteOwned spawn: on this client the actor is the server's proxy
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

	decodeTrail = actor->Class->Name.ToString() + ":";
	// SE_NET_CAPTURE (with SE_DEBUG_NET) dumps every class's replicated field table and every actor bunch's raw bits so the
	// decoder can be replayed offline against format variants.
	if (DebugNet() && getenv("SE_NET_CAPTURE"))
	{
		auto vtName = [](UProperty* pr) -> std::string
		{
			switch (pr->ValueType)
			{
			case ExpressionValueType::ValueByte: return "Byte";
			case ExpressionValueType::ValueInt: return "Int";
			case ExpressionValueType::ValueBool: return "Bool";
			case ExpressionValueType::ValueFloat: return "Float";
			case ExpressionValueType::ValueObject: return "Object";
			case ExpressionValueType::ValueVector: return "Vector";
			case ExpressionValueType::ValueRotator: return "Rotator";
			case ExpressionValueType::ValueString: return "String";
			case ExpressionValueType::ValueName: return "Name";
			case ExpressionValueType::ValueColor: return "Color";
			case ExpressionValueType::ValueStruct:
			{
				UStructProperty* sp = UObject::TryCast<UStructProperty>(pr);
				return std::string("Struct:") + ((sp && sp->Struct) ? sp->Struct->Name.ToString() : "?");
			}
			case ExpressionValueType::ValueCoords: return "Coords";
			case ExpressionValueType::ValueQuat: return "Quat";
			case ExpressionValueType::ValueArray: return "Array";
			default: return "Nothing";
			}
		};
		auto enumN = [](UProperty* pr) -> int
		{
			UByteProperty* bp = UObject::TryCast<UByteProperty>(pr);
			return (bp && bp->EnumType) ? (int)bp->EnumType->ElementNames.size() : 0;
		};
		static std::set<UClass*> capturedClasses;
		if (capturedClasses.insert(actor->Class).second)
		{
			fprintf(stderr, "CAPCLASS %s %d\n", actor->Class->Name.ToString().c_str(), classCache->GetMaxIndex());
			for (int i = 0; i < classCache->GetMaxIndex(); i++)
			{
				UField* f = classCache->GetFromIndex(i);
				if (!f) { fprintf(stderr, "CAPFIELD %d X - - 0 0\n", i); continue; }
				if (UProperty* pr = UObject::TryCast<UProperty>(f))
					fprintf(stderr, "CAPFIELD %d P %s %s %d %d\n", i, pr->Name.ToString().c_str(), vtName(pr).c_str(), enumN(pr), (int)pr->ArrayDimension);
				else if (UFunction* fn = UObject::TryCast<UFunction>(f))
				{
					fprintf(stderr, "CAPFIELD %d F %s - 0 0\n", i, fn->Name.ToString().c_str());
					int j = 0;
					for (UProperty* pp : fn->Properties)
					{
						if (!AnyFlags(pp->PropFlags, PropertyFlags::Parm) || AnyFlags(pp->PropFlags, PropertyFlags::ReturnParm))
							continue;
						fprintf(stderr, "CAPPARAM %d %d %s %s %d %d\n", i, j++, pp->Name.ToString().c_str(), vtName(pp).c_str(), enumN(pp), (int)pp->ArrayDimension);
					}
				}
			}
			fprintf(stderr, "CAPEND %s\n", actor->Class->Name.ToString().c_str());
		}
		BitReader cap(packetData + byteOff, packetSize - byteOff, subBit + contentBits);
		if (subBit)
			cap.ReadBits(subBit);
		std::string capBits;
		for (int i = 0; i < contentBits; i++)
			capBits += cap.ReadBit() ? '1' : '0';
		fprintf(stderr, "CAPBUNCH %d %s %d %d %d %s\n", chIndex, actor->Class->Name.ToString().c_str(), (int)bOpen, br.GetBitPos() - subBit, contentBits, capBits.c_str());
	}

	int remainBeforeRep = br.RemainingBits(); // end-of-bunch alignment check: a correctly decoded bunch leaves 0 bits when the final index read fails
	std::string lastFieldName;
	uint32_t repIndex = br.ReadInt((uint32_t)classCache->GetMaxIndex());
	UField* field = br.IsError() ? nullptr : classCache->GetFromIndex((int)repIndex);
	while (field)
	{
		lastFieldName = field->Name.ToString() + "(" + field->Class->Name.ToString() + ")";
		UProperty* prop = UObject::TryCast<UProperty>(field);
		if (prop)
		{
			int element = 0;
			if (prop->ArrayDimension != 1)
				element = (int)br.ReadBits(8);
			if (DebugNet())
				decodeTrail += " " + prop->Name.ToString() + "(" + prop->Class->Name.ToString() + ",rep" + std::to_string(repIndex) + ")@" + std::to_string(br.GetBitPos());

			void* elementPtr = prop->GetElement(actor->GetProperty(prop), element);
			if (DebugNet() && (prop->Name == "TimeDilation" || prop->Name == "Pauser"))
				fprintf(stderr, "[Net] LEVELPROP incoming %s for %s on channel %d\n", prop->Name.ToString().c_str(), actor->Class->Name.ToString().c_str(), chIndex);
			if (DebugNet() && prop->Name == "PlayerViewOffset")
				fprintf(stderr, "[Net] PVO update incoming for %s %s on channel %d\n", actor->Class->Name.ToString().c_str(), actor->Name.ToString().c_str(), chIndex);
			if (DebugNet() && prop->Name == "TimeDilation")
			{
				bool ok = DecodePropertyValue(br, prop, elementPtr);
				fprintf(stderr, "[Net] LEVELPROP TimeDilation decoded = %.4f (ok=%d) actor=%s %p engine->LevelInfo=%s %p same=%d\n", *(float*)elementPtr, (int)ok,
					actor->Name.ToString().c_str(), (void*)actor, engine->LevelInfo ? engine->LevelInfo->Name.ToString().c_str() : "-", (void*)engine->LevelInfo, (int)((UObject*)actor == (UObject*)engine->LevelInfo));
				if (!ok) break;
			}
			else if (!DecodePropertyValue(br, prop, elementPtr))
			{
				if (DebugNet())
					fprintf(stderr, "[Net] RemoteConnection: actor channel %d: unsupported property type for \"%s\" - abandoning rest of this bunch\n", chIndex, prop->Name.ToString().c_str());
				break;
			}
		}
		else
		{
			// RPC call from the server: decode the parameters, then run the function on the actor.
			UFunction* function = UObject::TryCast<UFunction>(field);
			if (!function)
				break;

			Array<ExpressionValue> callArgs;
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
				ExpressionValue value;
				if (present)
				{
					if (!DecodeParamValue(br, param, value))
					{
						paramError = true;
						break;
					}
				}
				else
				{
					value = ExpressionValue::DefaultValue(param);
				}
				callArgs.push_back(std::move(value));
			}
			if (paramError)
			{
				if (DebugNet())
					fprintf(stderr, "[Net] RemoteConnection: actor channel %d: couldn't parse parameters for RPC \"%s\" - abandoning rest of this bunch\n", chIndex, function->Name.ToString().c_str());
				break;
			}

			if (AnyFlags(function->FuncFlags, FunctionFlags::Net))
			{
				if (DebugNet())
					fprintf(stderr, "[Net] RemoteConnection: RPC %s on channel %d (%s)\n", function->Name.ToString().c_str(), chIndex, actor->Class->Name.ToString().c_str());
				try
				{
					Frame::Call(function, actor, std::move(callArgs));
				}
				catch (const std::exception& e)
				{
					if (DebugNet())
						fprintf(stderr, "[Net] RemoteConnection: RPC %s failed: %s\n", function->Name.ToString().c_str(), e.what());
				}
			}
		}

		if (br.IsError())
			break;
		remainBeforeRep = br.RemainingBits();
		repIndex = br.ReadInt((uint32_t)classCache->GetMaxIndex());
		field = br.IsError() ? nullptr : classCache->GetFromIndex((int)repIndex);
	}
	if (DebugNet())
	{
		fprintf(stderr, "[Net] BUNCHEND class=%s end=%s remain=%d last=%s\n", actor->Class->Name.ToString().c_str(),
			field ? "BROKE" : "natural", remainBeforeRep, lastFieldName.c_str());
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

	netClock += elapsed;

	if (levelChangeRequested)
	{
		const std::string host = remoteHost;
		const int port = remotePort;
		statusLine = "Changing level...";
		Connect(host, port); // resets the session and sends a fresh HELLO on a new socket
		return;
	}

	// The server may not be listening yet (it is busy loading the next map) or the first packet may have
	// been lost: keep sending HELLO until it answers with a CHALLENGE, for about half a minute.
	if (!sentLoginReply && !gaveUp)
	{
		if (netClock - lastHelloAt >= 1.0)
		{
			if (helloAttempts >= 30)
			{
				gaveUp = true;
				statusLine = "Could not reach " + remoteHost + ":" + std::to_string(remotePort);
				if (DebugNet())
					fprintf(stderr, "[Net] RemoteConnection: no answer from the server after %d HELLO attempts - giving up\n", helloAttempts);
			}
			else
			{
				std::vector<uint8_t> helloPacket = BuildHelloPacket();
				send(handle, (const char*)helloPacket.data(), (int)helloPacket.size(), 0);
				lastHelloAt = netClock;
				helloAttempts++;
				if (DebugNet())
					fprintf(stderr, "[Net] RemoteConnection: resent HELLO (attempt %d)\n", helloAttempts);
			}
		}
	}

	// SE_DEBUG_NET_RECONNECT_AFTER=<seconds>: force one level-change reconnect, to exercise that path
	// without waiting for the server to switch maps.
	static double forceReconnectAt = getenv("SE_DEBUG_NET_RECONNECT_AFTER") ? atof(getenv("SE_DEBUG_NET_RECONNECT_AFTER")) : 0.0;
	if (forceReconnectAt > 0.0 && loadedNetworkMap && netClock >= forceReconnectAt)
	{
		forceReconnectAt = 0.0;
		RequestLevelChange("forced by SE_DEBUG_NET_RECONNECT_AFTER");
	}

	// A connected game that goes silent has lost its server (e.g. it restarted): try to get back in.
	if (loadedNetworkMap && netClock - lastPacketAt > 20.0)
	{
		if (DebugNet())
			fprintf(stderr, "[Net] RemoteConnection: nothing from the server for 20 seconds - reconnecting\n");
		levelChangeRequested = true;
	}

	// SE_DEBUG_NET: what state is our own pawn in? (why is it, or isn't it, walking)
	static double nextPawnReport = 0;
	if (DebugNet() && possessedOwnPawn && netClock >= nextPawnReport && engine && engine->viewport && engine->viewport->Actor())
	{
		nextPawnReport = netClock + 2.0;
		UPlayerPawn* pawn = engine->viewport->Actor();
		fprintf(stderr, "[Net] PAWN %s state=%s physics=%d role=%d remoteRole=%d loc=(%.0f,%.0f,%.0f) vel=(%.0f,%.0f,%.0f) accel=(%.0f,%.0f,%.0f)\n",
			pawn->Name.ToString().c_str(), pawn->GetStateName().ToString().c_str(), (int)pawn->Physics(), (int)pawn->Role(), (int)pawn->RemoteRole(),
			pawn->Location().x, pawn->Location().y, pawn->Location().z, pawn->Velocity().x, pawn->Velocity().y, pawn->Velocity().z,
			pawn->Acceleration().x, pawn->Acceleration().y, pawn->Acceleration().z);
		{
			PointRegion& region = pawn->Region();
			fprintf(stderr, "[Net] PAWNZONE zone=%s zoneNumber=%d bWaterZone=%d ZoneGravity=(%.0f,%.0f,%.0f) headZone=%s\n",
				region.Zone ? region.Zone->Name.ToString().c_str() : "(none)", (int)region.ZoneNumber,
				region.Zone ? (int)region.Zone->GetBool("bWaterZone") : -1,
				region.Zone ? region.Zone->GetVector("ZoneGravity").x : 0.0f, region.Zone ? region.Zone->GetVector("ZoneGravity").y : 0.0f, region.Zone ? region.Zone->GetVector("ZoneGravity").z : 0.0f,
				pawn->GetUObject("HeadRegion") ? "?" : "-");
		}
		{
			static const auto wallStart = std::chrono::steady_clock::now();
			double wall = std::chrono::duration<double>(std::chrono::steady_clock::now() - wallStart).count();
			fprintf(stderr, "[Net] CLOCK wall=%.2f lastMoveTimeStamp=%.2f levelTimeSeconds=%.2f TimeDilation=%.3f\n", wall, lastMoveTimeStamp,
				engine->LevelInfo ? engine->LevelInfo->GetFloat("TimeSeconds") : -1.0f, engine->LevelInfo ? engine->LevelInfo->GetFloat("TimeDilation") : -1.0f);
		}
		fprintf(stderr, "[Net] PLAYER CurrentNetSpeed=%d ConfiguredLanSpeed=%d ConfiguredInternetSpeed=%d\n", (int)engine->viewport->GetInt("CurrentNetSpeed"), (int)engine->viewport->GetInt("ConfiguredLanSpeed"), (int)engine->viewport->GetInt("ConfiguredInternetSpeed"));
		fprintf(stderr, "[Net] PAWNINPUT aBaseY=%.1f aBaseX=%.1f aStrafe=%.1f aForward=%.1f bFire=%d bAltFire=%d\n", pawn->aBaseY(), pawn->aBaseX(), pawn->aStrafe(), pawn->aForward(), (int)pawn->bFire(), (int)pawn->bAltFire());
		if (UWeapon* weaponObj = pawn->Weapon())
		{
			vec3 pvo = weaponObj->GetVector("PlayerViewOffset");
			fprintf(stderr, "[Net] PAWNWEAPON %s state=%s role=%d PlayerViewOffset=(%.2f,%.2f,%.2f) FireOffset=(%.1f,%.1f,%.1f) Handedness=%.1f bHideWeapon=%d\n", weaponObj->Class->Name.ToString().c_str(), weaponObj->GetStateName().ToString().c_str(), (int)weaponObj->Role(),
				pvo.x, pvo.y, pvo.z, weaponObj->FireOffset().x, weaponObj->FireOffset().y, weaponObj->FireOffset().z, pawn->Handedness(), (int)weaponObj->GetBool("bHideWeapon"));
			fprintf(stderr, "[Net] PAWNVIEW FOVAngle=%.1f DefaultFOV=%.1f DesiredFOV=%.1f weapon DrawScale=%.2f PlayerViewScale=%.2f Mesh=%s PlayerViewMesh=%s\n", pawn->GetFloat("FOVAngle"), pawn->GetFloat("DefaultFOV"), pawn->GetFloat("DesiredFOV"),
				weaponObj->GetFloat("DrawScale"), weaponObj->GetFloat("PlayerViewScale"),
				weaponObj->GetUObject("Mesh") ? weaponObj->GetUObject("Mesh")->Name.ToString().c_str() : "-", weaponObj->GetUObject("PlayerViewMesh") ? weaponObj->GetUObject("PlayerViewMesh")->Name.ToString().c_str() : "-");
		}
	}

	// Resend reliable bunches the server hasn't acked yet: same ChSequence, fresh PacketId.
	for (PendingReliable& pending : pendingReliable)
	{
		if (netClock - pending.sentAt < 0.5)
			continue;
		BitWriter content;
		for (int i = 0; i < pending.contentBits; i++)
			content.WriteBit((pending.content[i / 8] >> (i % 8)) & 1);
		pending.packetId = AllocatePacketId();
		BitWriter packet;
		packet.WriteInt((uint32_t)pending.packetId, MAX_PACKETID);
		WriteBunch(packet, false, false, true, pending.chIndex, CHTYPE_Actor, pending.chSequence, content);
		std::vector<uint8_t> bytes = packet.Finish();
		send(handle, (const char*)bytes.data(), (int)bytes.size(), 0);
		pending.sentAt = netClock;
		if (DebugNet())
			fprintf(stderr, "[Net] RemoteConnection: resent reliable bunch (channel %d, sequence %d) as packet %d\n", pending.chIndex, pending.chSequence, pending.packetId);
	}

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

			lastPacketAt = netClock;
			ParsedPacket packet = ParsePacket((const uint8_t*)buffer, received);
			if (!packet.valid)
			{
				if (DebugNet())
					fprintf(stderr, "[Net] RemoteConnection: received data too short to contain a PacketId - ignoring\n");
				continue;
			}

			// Anything the server acks no longer needs resending.
			for (int ackedId : packet.acks)
				pendingReliable.erase(std::remove_if(pendingReliable.begin(), pendingReliable.end(),
					[ackedId](const PendingReliable& p) { return p.packetId == ackedId; }), pendingReliable.end());
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

							// The real engine sets the player's CurrentNetSpeed when the connection is negotiated (it is
							// the NETSPEED we announce). Scripts rely on it: PlayerPawn's move replication paces its sends
							// with 64/CurrentNetSpeed, so at 0 a released fire button or a stop was not reported to the
							// server for a second or more - the server kept auto-firing.
							if (engine && engine->viewport)
								engine->viewport->SetInt("CurrentNetSpeed", 20000);
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
						std::vector<uint8_t> joinPacket = BuildJoinPacket(AllocatePacketId(), packet.packetId, AllocateChSequence(0));
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
				std::vector<uint8_t> ackPacket = BuildAckPacket(AllocatePacketId(), packet.packetId);
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
