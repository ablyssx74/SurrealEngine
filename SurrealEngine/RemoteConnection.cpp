
#include "Precomp.h"
#include "RemoteConnection.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <vector>
#include <string>

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

	// LSB-first bit writer/reader matching UE1's wire format. Reverse-engineered this session
	// from a genuine Wireshark capture of a real UT99-for-Linux client joining a real UT99-for-
	// Linux server, then cross-validated by re-encoding a captured packet from scratch and
	// getting an exact byte-for-byte match, and separately by successfully parsing a live
	// server's real response during testing. Only covers what's needed for a reliable,
	// already-open control-channel bunch (what HELLO's response and our LOGIN reply both are) -
	// a brand-new channel opening (bOpen=1, like our own HELLO) needs one more bit whose exact
	// meaning isn't nailed down yet, which is why Connect() below still replays a captured HELLO
	// packet instead of building one with this.
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

		// Epic's classic "compact index" variable-length integer, as used throughout Unreal's
		// serialization: byte 0 holds a sign bit (always 0 here - we never write negative
		// lengths), a continue bit, and 6 magnitude bits; each following byte holds a continue
		// bit and 7 more magnitude bits.
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
		// content (built separately so its byte length is known before the bunch header, which
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

	class BitReader
	{
	public:
		BitReader(const uint8_t* data, int sizeBytes) : data(data), sizeBits(sizeBytes * 8) {}

		int RemainingBits() const { return sizeBits - bitPos; }

		int ReadBit()
		{
			if (bitPos >= sizeBits)
				return 0;
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
	};

	// UT99's connection-level challenge/response transform (UGameEngine::ChallengeResponse in
	// the real engine). Cracked this session by finding a real (CHALLENGE, RESPONSE) pair in a
	// genuine capture and testing hypotheses against it; the exact formula was then independently
	// confirmed against a full historical Unreal Engine 1 source tree. Written fresh here (not
	// copied) purely for UT99 wire-protocol interoperability: without computing the same value a
	// real client would, a real server rejects the login with "FAILURE CHALLENGE", which is
	// exactly what happened when this engine sent a stale, unrelated RESPONSE value earlier this
	// session.
	int32_t ChallengeResponse(int32_t challenge)
	{
		uint32_t c = (uint32_t)challenge;
		uint32_t result = (c * 237u) ^ 0x93fe92Ceu ^ (uint32_t)(challenge >> 16) ^ (c << 16);
		return (int32_t)result;
	}

	// Writes a reliable, already-open control-channel bunch (ChIndex=0) wrapping the given
	// content, which must already be a whole number of bytes (true for any content built purely
	// out of WriteString() calls). Caller is responsible for the packet-level header before this
	// and Finish() after it.
	void WriteControlBunch(BitWriter& packet, int chSequence, const BitWriter& content)
	{
		uint32_t contentBytes = (uint32_t)(content.GetBitCount() / 8);
		packet.WriteBit(0); // bOpen
		packet.WriteBit(0); // bClose
		packet.WriteBit(1); // bReliable
		packet.WriteBits(0, 10); // ChIndex - the control channel is always index 0
		packet.WriteBits((uint32_t)chSequence, 10);
		// The content length is split as quotient*4+remainder across a 2-bit remainder packed
		// into the top of the channel-type byte and a 7-bit quotient right after it - an unusual
		// split, but this is exactly what real captured packets do, verified by reconstructing
		// one from scratch and getting a byte-for-byte match against the original. The 7-bit
		// quotient caps content at 4*127+3 = 511 bytes, comfortably more than a login message.
		uint32_t quotient = contentBytes / 4;
		uint32_t remainder = contentBytes % 4;
		packet.WriteBits(1u /* CHTYPE_Control */ | (remainder << 6), 8);
		packet.WriteBits(quotient, 7);
		packet.AppendBits(content);
	}

	void WritePacketHeader(BitWriter& packet, int packetId, bool hasAck, int ackPacketId)
	{
		packet.WriteBits((uint32_t)packetId, 14);
		packet.WriteBit(hasAck ? 1 : 0);
		if (hasAck)
			packet.WriteBits((uint32_t)ackPacketId, 14);
	}

	// Builds our reply to the server's CHALLENGE: a NETSPEED message and a LOGIN message (with a
	// correctly-computed RESPONSE) in one reliable control-channel bunch, exactly mirroring what
	// a real client sends at this point in the handshake.
	std::vector<uint8_t> BuildLoginPacket(int packetId, int ackPacketId, int chSequence, int32_t response)
	{
		BitWriter content;
		content.WriteString("NETSPEED 20000");
		content.WriteString("LOGIN RESPONSE=" + std::to_string(response) +
			" URL=Index.unr?LAN?Name=TR30?Class=SkeletalChars.WarBoss?team=1?skin=?Face=?Voice=?OverrideClass=?Checksum=NoChecksum");

		BitWriter packet;
		WritePacketHeader(packet, packetId, true, ackPacketId);
		WriteControlBunch(packet, chSequence, content);
		return packet.Finish();
	}

	// Tries to parse a received packet as a single reliable control-channel bunch containing a
	// "CHALLENGE VER=... CHALLENGE=<n> ..." message, extracting the server's PacketId (to ack)
	// and the challenge integer. Returns false for anything that doesn't look like that (an
	// ack-only packet, a different message, malformed data, etc).
	bool ParseChallengePacket(const uint8_t* data, int size, int& outServerPacketId, int32_t& outChallenge)
	{
		BitReader br(data, size);
		outServerPacketId = (int)br.ReadBits(14);
		if (br.ReadBit() != 0) // HasAck
			br.ReadBits(14); // AckPacketId of our own packet - not needed here

		if (br.RemainingBits() < 23)
			return false;

		br.ReadBit(); br.ReadBit(); br.ReadBit(); // bOpen/bClose/bReliable - not needed
		uint32_t chIndex = br.ReadBits(10);
		br.ReadBits(10); // ChSequence - not needed
		if (chIndex != 0)
			return false;

		uint32_t combined = br.ReadBits(8);
		uint32_t remainder = (combined >> 6) & 0x3;
		uint32_t quotient = br.ReadBits(7);
		uint32_t contentBytes = quotient * 4 + remainder;
		if (contentBytes == 0 || (uint32_t)br.RemainingBits() < contentBytes * 8)
			return false;

		std::string text = br.ReadString();
		size_t pos = text.find("CHALLENGE=");
		if (text.find("CHALLENGE ") != 0 || pos == std::string::npos)
			return false;
		pos += strlen("CHALLENGE=");
		outChallenge = (int32_t)strtol(text.c_str() + pos, nullptr, 10);
		return true;
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

			// Second step of the handshake: once the server's CHALLENGE arrives, reply with a real
			// NETSPEED+LOGIN message built by our own bit-packer, using a RESPONSE value we
			// actually compute from the server's challenge (see ChallengeResponse above) instead
			// of a stale replayed one - which a real server correctly rejects with "FAILURE
			// CHALLENGE", as confirmed earlier this session.
			if (!sentLoginReply)
			{
				int serverPacketId = 0;
				int32_t challenge = 0;
				if (ParseChallengePacket((const uint8_t*)buffer, received, serverPacketId, challenge))
				{
					sentLoginReply = true;
					int32_t response = ChallengeResponse(challenge);
					if (DebugNet())
						fprintf(stderr, "[Net] RemoteConnection: parsed CHALLENGE=%d from server packet %d, computed RESPONSE=%d\n", challenge, serverPacketId, response);

					// Our packet 0 was the HELLO, so this is packet 1; the control channel's
					// first reliable bunch was HELLO (ChSequence=1), so this is ChSequence=2.
					std::vector<uint8_t> loginPacket = BuildLoginPacket(1, serverPacketId, 2, response);
					int sent = send(handle, (const char*)loginPacket.data(), (int)loginPacket.size(), 0);
					if (DebugNet())
						fprintf(stderr, "[Net] RemoteConnection: sent %d-byte NETSPEED+LOGIN reply (built with a real computed RESPONSE) -> %d\n", (int)loginPacket.size(), sent);
				}
				else if (DebugNet())
				{
					fprintf(stderr, "[Net] RemoteConnection: received data didn't parse as a CHALLENGE packet - not replying yet\n");
				}
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
