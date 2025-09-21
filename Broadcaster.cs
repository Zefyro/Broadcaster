using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Broadcast;

internal static class Broadcaster
{
    internal static readonly int Port = 12345;
    internal static readonly IPAddress BroadcastAddress = IPAddress.Broadcast;
    internal static readonly IPAddress Address = Dns.GetHostEntry(Dns.GetHostName()).AddressList.First(ip => ip.AddressFamily == AddressFamily.InterNetwork);

    static void Main(string[] args)
    {
        Console.WriteLine($"{Environment.UserName}@{Dns.GetHostName()} : {Address}");

        Thread listener = new(Listener);
        listener.Start();
        Thread sender = new(Sender);
        sender.Start();
        sender.Join();
    }
    internal static void Sender()
    {
        using UdpClient client = new();
        // TODO: Fix JOIN packet
        //client.Send([0x43, 0x41, 0x53, 0x54, 0x00, 0x04, 0xC0, 0x01], 8, new IPEndPoint(BroadcastAddress, Port));
        Console.WriteLine($"Ready to send UDP broadcast messages on port {Port}");
        while (true)
        {
            string? line = Console.ReadLine();
            if (string.IsNullOrEmpty(line))
                continue;

            byte[] text = Encoding.ASCII.GetBytes(line);

            UInt64 timestamp = ((UInt64)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()).ToBigEndian();

            PacketHeader header;
            header.magic = [0x43, 0x41, 0x53, 0x54];
            header.size = ((UInt16)(2 + 2 + 16 + 8 + text.Length)).ToBigEndian();
            header.opcode = ((UInt16)PacketOpcode.SEND_MSG).ToBigEndian();
            header.timestamp = timestamp;
            header.md5hash = 0;
            header.md5hash = HashHeader(header, Address);

            MessagePacket message;
            message.msg = text;

            List<byte> bytes = [];
            bytes.AddRange(HeaderToBytes(header));
            bytes.AddRange(message.msg);

            client.Send([.. bytes], bytes.Count, new IPEndPoint(BroadcastAddress, Port));

            Console.WriteLine($">>> {line}");
        }
    }
    internal static void Listener()
    {
        Console.WriteLine("Starting UDP broadcast listener...");
        using UdpClient client = new();
        client.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);

        IPEndPoint localEndPoint = new(IPAddress.Any, Port);
        client.Client.Bind(localEndPoint);

        Console.WriteLine($"Listening for broadcasts on port {Port}");
        IPEndPoint remoteEndPoint = new(IPAddress.Any, 0);

        try
        {
            while (true)
            {
                //if (remoteEndPoint.Address.ToString() == Address.ToString())
                //    continue;

                byte[] receivedBytes = client.Receive(ref remoteEndPoint);

                MemoryStream stream = new(receivedBytes);
                BinaryReader reader = new(stream);
                PacketHeader header = ReadPacketHeader(reader);

                switch ((PacketOpcode)BinaryPrimitives.ReverseEndianness(header.opcode))
                {
                    case PacketOpcode.SEND_MSG:
                        MessagePacket message = ReadMessagePacket(reader, header.size);

                        string msg = string.Empty;
                        if ((header.size - 28) > 0)
                        {
                            msg = Encoding.ASCII.GetString(message.msg!);
                        }

                        byte[] header_hash = HashHeader(header, remoteEndPoint.Address).ToBigEndian().ToBytes();
                        bool validHash = MatchHeader(header.md5hash.ToBytes(), header_hash);

                        Console.WriteLine(validHash ? "Hash Valid" : "Hash Invalid");
                        Console.WriteLine($"Received broadcast from {remoteEndPoint}: {Convert.ToHexString(HeaderToBytes(header))}\n<<< {msg}");
                        break;
                    case PacketOpcode.ACKNOWLEDGE:
                        Console.WriteLine($"{remoteEndPoint} >> ACK");
                        break;
                    case PacketOpcode.CHANNEL_JOIN:
                        Console.WriteLine($"{remoteEndPoint} >> JOIN");
                        // TODO: Fix ACK packet
                        //client.Send([0x43, 0x41, 0x53, 0x54, 0x00, 0x04, 0x00, 0xC8], 8, new IPEndPoint(BroadcastAddress, Port));
                        break;
                    case PacketOpcode.CHANNEL_EXIT:
                        Console.WriteLine($"{remoteEndPoint} >> EXIT");
                        break;
                    case PacketOpcode.CHANNEL_PING:
                        Console.WriteLine($"{remoteEndPoint} >> PING");
                        // TODO: Fix ACK packet
                        //client.Send([0x43, 0x41, 0x53, 0x54, 0x00, 0x04, 0x00, 0xC8], 8, new IPEndPoint(BroadcastAddress, Port));
                        break;
                    case PacketOpcode.CHANNEL_PUBLIC_KEY:
                        break;
                    default:
                        break;
                }
            }
        }
        catch (Exception e)
        {
            Console.WriteLine(e.ToString());
        }
    }
    internal static UInt128 HashHeader(PacketHeader header, IPAddress address)
    {
        List<byte> bytes = [];
        bytes.AddRange(address.GetAddressBytes());
        bytes.AddRange(header.magic);
        bytes.AddRange(header.size.ToBigEndian().ToBytes());
        bytes.AddRange(header.opcode.ToBigEndian().ToBytes());
        bytes.AddRange(header.timestamp.ToBigEndian().ToBytes());
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
    internal static MessagePacket ReadMessagePacket(BinaryReader reader, int size) => new()
    {
        msg = reader.ReadBytes(size - 28),
    };
    internal static byte[] ToBytes(this UInt16 value) => BitConverter.GetBytes(value);
    internal static byte[] ToBytes(this UInt64 value) => BitConverter.GetBytes(value);
    internal static byte[] ToBytes(this UInt128 value) => BitConverter.GetBytes(value);
    internal static UInt16 ToBigEndian(this UInt16 value) => BitConverter.IsLittleEndian ? BinaryPrimitives.ReverseEndianness(value) : value;
    internal static UInt64 ToBigEndian(this UInt64 value) => BitConverter.IsLittleEndian ? BinaryPrimitives.ReverseEndianness(value) : value;
    internal static UInt128 ToBigEndian(this UInt128 value) => BitConverter.IsLittleEndian ? BinaryPrimitives.ReverseEndianness(value) : value;
}