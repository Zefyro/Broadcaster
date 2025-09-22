using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

namespace Broadcast;

internal static partial class Broadcaster
{
    internal static readonly int Port = 12345;
    internal static readonly IPAddress BroadcastAddress = IPAddress.Broadcast;
    internal static readonly IPAddress Address = Dns.GetHostEntry(Dns.GetHostName()).AddressList.First(ip => ip.AddressFamily == AddressFamily.InterNetwork);

    internal static Dictionary<IPAddress, Guid> KnownClients = [];
    internal static Dictionary<Guid, string> KnownAliases = [];

    static void Main(string[] args)
    {
        Console.WriteLine($"{Environment.UserName}@{Dns.GetHostName()} : {Address}");

        using UdpClient client = new();

        Thread listener = new(() => Listener(client));
        listener.Start();
        Thread sender = new(() => Sender(client));
        sender.Start();
        sender.Join();
    }
    internal static void Sender(UdpClient client)
    {
        string? senderAlias = $"{Environment.UserName}@{Dns.GetHostName()}";
        PacketHeader header;
        header = CreateHeader(PacketOpcode.CHANNEL_JOIN, Address, senderAlias.Length);

        List<byte> joinPacket = [];
        joinPacket.AddRange(HeaderToBytes(header));
        joinPacket.AddRange(Encoding.ASCII.GetBytes(senderAlias));

        client.Send([.. joinPacket], joinPacket.Count, new IPEndPoint(BroadcastAddress, Port));
        Console.WriteLine($"Ready to send UDP broadcast messages on port {Port}");

        while (true)
        {
            string? line = Console.ReadLine();
            if (string.IsNullOrEmpty(line))
                continue;

            if (line.StartsWith('/'))
            {
                switch (line)
                {
                    case "/ping":
                        client.Send(HeaderToBytes(CreateHeader(PacketOpcode.CHANNEL_PING, Address, 0)), 32, new IPEndPoint(BroadcastAddress, Port));
                        break;
                    case "/quit":
                    case "/exit":
                    case "/stop":
                        client.Send(HeaderToBytes(CreateHeader(PacketOpcode.CHANNEL_EXIT, Address, 0)), 32, new IPEndPoint(BroadcastAddress, Port));
                        return;
                    case "/clear":
                        Console.Clear();
                        Console.WriteLine($"{Environment.UserName}@{Dns.GetHostName()} : {Address}");
                        break;
                    default:
                        Console.WriteLine("!! Invalid client command !!");
                        break;
                }
                continue;
            }

            byte[] text = Encoding.ASCII.GetBytes(line);
            header = CreateHeader(PacketOpcode.SEND_MSG, Address, text.Length);

            DataPacket message;
            message.data = text;

            List<byte> bytes = [];
            bytes.AddRange(HeaderToBytes(header));
            bytes.AddRange(message.data);

            client.Send([.. bytes], bytes.Count, new IPEndPoint(BroadcastAddress, Port));

            Console.WriteLine($">>> {line}");
        }
    }
    internal static void Listener(UdpClient client)
    {
        Console.WriteLine("Starting UDP broadcast listener...");
        client.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);

        IPEndPoint localEndPoint = new(IPAddress.Any, Port);
        client.Client.Bind(localEndPoint);

        Console.WriteLine($"Listening for broadcasts on port {Port}");
        IPEndPoint remoteEndPoint = new(IPAddress.Any, 0);

        try
        {
            while (true)
            {
                byte[] receivedBytes = client.Receive(ref remoteEndPoint);

                MemoryStream stream = new(receivedBytes);
                BinaryReader reader = new(stream);
                PacketHeader header = ReadPacketHeader(reader);

                if (Encoding.UTF8.GetString(header.magic) != "CAST")
                    continue;

                if (!KnownClients.TryGetValue(remoteEndPoint.Address, out Guid clientId))
                {
                    clientId = Guid.NewGuid();
                    KnownClients.Add(remoteEndPoint.Address, clientId);
                }

                bool hasAlias = KnownAliases.TryGetValue(KnownClients[remoteEndPoint.Address], out string? alias);

                byte[] header_hash = HashHeader(header, remoteEndPoint.Address).ToBytes();
                bool validHash = MatchHeader(header.md5hash.ToBytes(), header_hash);
                Console.Write(validHash ? "[Valid] " : "[Invalid] ");

                switch ((PacketOpcode)BinaryPrimitives.ReverseEndianness(header.opcode))
                {
                    case PacketOpcode.SEND_MSG:
                        DataPacket message = ReadDataPacket(reader, header.size);

                        string text = string.Empty;
                        if ((header.size - 28) > 0)
                        {
                            text = Encoding.UTF8.GetString(message.data!);
                        }

                        Console.WriteLine($"Received broadcast from {(hasAlias ? alias : clientId)}: {Convert.ToHexString(HeaderToBytes(header))}\n<<< {text}");
                        break;
                    case PacketOpcode.ACKNOWLEDGE:
                        Console.WriteLine($"{(hasAlias ? alias : clientId)} >> ACK");
                        break;
                    case PacketOpcode.CHANNEL_JOIN:
                        Console.WriteLine($"{remoteEndPoint} >> JOIN\n>> Added as {clientId}");

                        DataPacket hostName = ReadDataPacket(reader, header.size);
                        if (hostName.data!.Length > 0)
                        {
                            string t = string.Empty;
                            t = Encoding.UTF8.GetString(hostName.data);

                            KnownAliases.Add(clientId, t);

                            Console.WriteLine($"Added alias for {KnownClients[remoteEndPoint.Address]}: {t}");
                            
                        }

                        //DataPacket public_key = ReadDataPacket(reader, header.size);

                        client.Send(HeaderToBytes(CreateHeader(PacketOpcode.ACKNOWLEDGE, Address, 0)), 32, new IPEndPoint(BroadcastAddress, Port));
                        break;
                    case PacketOpcode.CHANNEL_EXIT:
                        Console.WriteLine($"{(hasAlias ? alias : clientId)} >> EXIT");
                        if ((remoteEndPoint.Address == Address) && (remoteEndPoint.Port == Port))
                            return;
                        break;
                    case PacketOpcode.CHANNEL_PING:
                        Console.WriteLine($"{(hasAlias ? alias : clientId)} >> PING");
                        PingTimestamp = header.timestamp;
                        client.Send(HeaderToBytes(CreateHeader(PacketOpcode.CHANNEL_PONG, Address, 0)), 32, new IPEndPoint(BroadcastAddress, Port));
                        break;
                    case PacketOpcode.CHANNEL_PONG:
                        Int64 pong = (Int64)BinaryPrimitives.ReverseEndianness(header.timestamp);
                        Int64 ping = (Int64)BinaryPrimitives.ReverseEndianness(PingTimestamp);
                        Int64 current = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

                        Console.WriteLine($"{(hasAlias ? alias : clientId)} >> PONG TO {ping - pong}ms FROM {current - pong}ms TOTAL {current - ping}ms");
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
}