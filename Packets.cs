namespace Broadcast;

internal enum PacketOpcode : UInt16
{
    SEND_MSG = 0x5000,
    ACKNOWLEDGE = 0xC8,
    CHANNEL_JOIN = 0xC001,
    CHANNEL_EXIT = 0xC002,
    CHANNEL_PUBLIC_KEY = 0xC010,
    CHANNEL_PING = 0xC020,
    CHANNEL_PONG = 0xC021,
}

internal struct PacketHeader
{
    internal Byte[] magic;
    internal UInt16 size;
    internal UInt16 opcode;
    internal UInt64 timestamp;
    internal UInt128 md5hash;
}

internal struct DataPacket
{
    internal Byte[]? data;
}