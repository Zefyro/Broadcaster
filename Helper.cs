using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;

namespace Broadcast;
internal static partial class Broadcaster
{
    internal static Int64 PingTimestamp;
    internal static PacketHeader CreateHeader(PacketOpcode opcode, IPAddress address, int extra_size)
    {
        PacketHeader header;
        UInt64 timestamp = ((UInt64)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()).ToBigEndian();
        header.magic = [0x43, 0x41, 0x53, 0x54];
        header.size = ((UInt16)(28 + extra_size)).ToBigEndian();
        header.opcode = ((UInt16)opcode).ToBigEndian();
        header.timestamp = timestamp;
        header.md5hash = 0;
        header.md5hash = HashHeader(header, address);
        return header;
    }
    internal static UInt128 HashHeader(PacketHeader header, IPAddress address)
    {
        List<byte> bytes = [];
        bytes.AddRange(address.GetAddressBytes());
        bytes.AddRange(header.magic);
        bytes.AddRange(header.size.ToBytes());
        bytes.AddRange(header.opcode.ToBytes());
        bytes.AddRange(header.timestamp.ToBytes());
        return BitConverter.ToUInt128(MD5.HashData([.. bytes]));
    }
    internal static bool MatchHeader(byte[] hash1, byte[] hash2)
    {
        for (int i = 0; i < hash1.Length; i++)
        {
            if (hash1[i] != hash2[i])
                return false;
        }
        return true;
    }
    internal static PacketHeader ReadPacketHeader(BinaryReader reader) => new()
    {
        magic = reader.ReadBytes(4),
        size = reader.ReadUInt16(),
        opcode = reader.ReadUInt16(),
        timestamp = reader.ReadUInt64(),
        md5hash = BitConverter.ToUInt128(reader.ReadBytes(16)),
    };
    internal static byte[] HeaderToBytes(PacketHeader header)
    {
        List<byte> bytes = [];
        bytes.AddRange(header.magic);
        bytes.AddRange(header.size.ToBytes());
        bytes.AddRange(header.opcode.ToBytes());
        bytes.AddRange(header.timestamp.ToBytes());
        bytes.AddRange(header.md5hash.ToBytes());
        return [.. bytes];
    }
    internal static DataPacket ReadDataPacket(BinaryReader reader, int size) => new()
    {
        data = reader.ReadBytes(size - 28),
    };
    internal static byte[] ToBytes(this UInt16 value) => BitConverter.GetBytes(value);
    internal static byte[] ToBytes(this UInt64 value) => BitConverter.GetBytes(value);
    internal static byte[] ToBytes(this UInt128 value) => BitConverter.GetBytes(value);
    internal static UInt16 ToBigEndian(this UInt16 value) => BitConverter.IsLittleEndian ? BinaryPrimitives.ReverseEndianness(value) : value;
    internal static UInt64 ToBigEndian(this UInt64 value) => BitConverter.IsLittleEndian ? BinaryPrimitives.ReverseEndianness(value) : value;
    internal static UInt128 ToBigEndian(this UInt128 value) => BitConverter.IsLittleEndian ? BinaryPrimitives.ReverseEndianness(value) : value;
}