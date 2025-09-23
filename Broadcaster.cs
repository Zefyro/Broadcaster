using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using PgpCore;

namespace Broadcast;

internal struct Client
{
    internal Guid guid;
    internal string name;
    internal string public_key;
    internal bool isPresent;
}

internal static partial class Broadcaster
{
    internal static readonly int Port = 12345;
    internal static readonly IPEndPoint BroadcastAddress = new(IPAddress.Broadcast, Port);
    internal static readonly IPAddress Address = Dns.GetHostEntry(Dns.GetHostName()).AddressList.First(ip => ip.AddressFamily == AddressFamily.InterNetwork);
    internal static string HostName = $"{Environment.UserName}@{Dns.GetHostName()}";
    internal static Dictionary<IPAddress, Client> KnownClients = [];
    internal static bool Debug = false;
    //internal static PgpPublicKey? PublicKey { get; private set; }
    //internal static PgpPrivateKey? PrivateKey { get; private set; }
    //internal static PgpSecretKey? SecretKey { get; private set; }
    static void Main(string[] args)
    {
        Console.WriteLine($"{HostName} : {Address}");

        Console.Write("Passphrase: ");
        string? password = Console.ReadLine();
        Console.Write("Generate new PGP keys? [y/N]: ");
        string? line = Console.ReadLine();

        PGP pgp = new();
        if (!string.IsNullOrEmpty(line) && line.Equals("y", StringComparison.CurrentCultureIgnoreCase))
            pgp.GenerateKey(new FileInfo("./public.asc"), new FileInfo("./private.asc"), HostName, password);

        string public_key = File.ReadAllText("./public.asc");
        string private_key = File.ReadAllText("./private.asc");

        //EncryptionKeys encryption_keys = new(public_key, private_key, password);
        //PublicKey = encryption_keys.PublicKey;
        //PrivateKey = encryption_keys.PrivateKey;
        //SecretKey = encryption_keys.SecretKey;

        using UdpClient client = new();
        Thread listener = new(() => Listener(client, public_key, private_key, password));
        listener.Start();
        Thread sender = new(() => Sender(client, public_key, private_key, password));
        sender.Start();
        sender.Join();
    }
    internal static void Sender(UdpClient client, string public_key, string private_key, string? password)
    {
        List<byte> join_bytes = [];
        join_bytes.AddRange(HeaderToBytes(CreateHeader(PacketOpcode.CHANNEL_JOIN, Address, public_key.Length)));
        join_bytes.AddRange(Encoding.UTF8.GetBytes(public_key));
        byte[] channel_join = [.. join_bytes];

        client.Send(channel_join, channel_join.Length, BroadcastAddress);
        Console.WriteLine($"Ready to send UDP broadcast messages on port {Port}");

        while (true)
        {
            string? line = Console.ReadLine();
            if (string.IsNullOrEmpty(line))
            {
                continue;
            }
            else if (line.StartsWith('/'))
            {
                switch (line)
                {
                    case "/ping":
                        PacketHeader ping = CreateHeader(PacketOpcode.CHANNEL_PING, Address, 0);
                        PingTimestamp = (Int64)BinaryPrimitives.ReverseEndianness(ping.timestamp);
                        client.Send(HeaderToBytes(ping), 32, BroadcastAddress);
                        break;
                    case "/quit":
                    case "/exit":
                    case "/stop":
                        return;
                    case "/clear":
                        Console.Clear();
                        Console.WriteLine($"{HostName} : {Address}");
                        break;
                    case "/debug":
                        Debug = !Debug;
                        Console.WriteLine($"Debug Mode: {Debug}");
                        break;
                    default:
                        Console.WriteLine("!! Invalid client command !!");
                        break;
                }
                continue;
            }

            PGP message_key = new(new EncryptionKeys(public_key));
            byte[] message_bytes = Encoding.UTF8.GetBytes(line);
            PacketHeader message_header = CreateHeader(PacketOpcode.SEND_MSG, Address, message_bytes.Length);

            List<byte> unencrypted_bytes = [];
            unencrypted_bytes.AddRange(HeaderToBytes(message_header));
            unencrypted_bytes.AddRange(message_bytes);

            MemoryStream unencrypted = new([.. unencrypted_bytes]);
            MemoryStream encrypted = new();
            message_key.EncryptStream(unencrypted, encrypted);

            bool success = encrypted.TryGetBuffer(out ArraySegment<byte> encrypted_byte_array);
            if (!success)
            {
                Console.WriteLine("Error while encrypting message.");
                continue;
            }
            byte[] encrypted_bytes = [.. encrypted_byte_array];

            client.Send(encrypted_bytes, encrypted_bytes.Length, BroadcastAddress);
            Console.WriteLine($">>> {line}");
        }
    }
    internal static void Listener(UdpClient client, string public_key, string private_key, string? password)
    {
        Console.WriteLine("Starting UDP broadcast listener...");
        client.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        client.Client.Bind(new IPEndPoint(IPAddress.Any, Port));
        Console.WriteLine($"Listening for broadcasts on port {Port}");
        IPEndPoint remoteEndPoint = new(IPAddress.Any, 0);

        try
        {
            while (true)
            {
                // TODO: The client shouldn't trust the packet, so make sure it's not anything malicious.
                byte[] received_bytes = client.Receive(ref remoteEndPoint);

                MemoryStream stream = new(received_bytes);
                BinaryReader reader = new(stream);
                PacketHeader header = ReadPacketHeader(reader);

                if (Encoding.UTF8.GetString(header.magic) != "CAST")
                {
                    // Try to decrypt the packet if magic is not correct
                    MemoryStream enctryped = new(received_bytes);
                    MemoryStream decrypted = new();
                    PGP pgp = new(new EncryptionKeys(private_key, password));
                    pgp.DecryptStream(enctryped, decrypted);

                    bool success = decrypted.TryGetBuffer(out ArraySegment<byte> decrypted_byte_array);
                    if (!success)
                    {
                        Console.WriteLine("Error while decrypting packet.");
                        continue;
                    }
                    byte[] decrypted_bytes = [.. decrypted_byte_array];

                    // Create new packet header because just assinging to the previous one does not work.
                    MemoryStream unencrypted_stream = new(decrypted_bytes);
                    BinaryReader unencrypted_reader = new(unencrypted_stream);
                    PacketHeader unencrypted_header = ReadPacketHeader(unencrypted_reader);
                    reader = unencrypted_reader;
                    header = unencrypted_header;

                    // Ignore packets not directed at this client
                    if (Encoding.UTF8.GetString(header.magic) != "CAST")
                    {
                        Console.WriteLine($"Packet from {remoteEndPoint} was not directed at this client");
                        continue;
                    }
                }
                
                // Store/Read info about the client that sent a packet
                if (!KnownClients.TryGetValue(remoteEndPoint.Address, out Client connectedClient))
                {
                    connectedClient.guid = new();
                    connectedClient.isPresent = true;
                    connectedClient.name = remoteEndPoint.Address.ToString();
                    KnownClients.Add(remoteEndPoint.Address, connectedClient);
                }

                // Validate the header hash, the client can read packets with an invalid hash.
                // Does nothing with the information but the client can mark them as "unconfirmed" later.
                byte[] header_hash = HashHeader(header, remoteEndPoint.Address).ToBytes();
                bool validHash = MatchHeader(header.md5hash.ToBytes(), header_hash);
                Console.Write(validHash ? "[Valid] " : "[Invalid] ");

                switch ((PacketOpcode)BinaryPrimitives.ReverseEndianness(header.opcode))
                {
                    case PacketOpcode.SEND_MSG:
                        // Read the data from a message packet.
                        DataPacket message = ReadDataPacket(reader, header.size);
                        string text = !((header.size - 28) > 0) ? string.Empty : Encoding.UTF8.GetString(message.data!);
                        
                        Console.Write($"[{connectedClient.name}] >> SEND ");
                        if (Debug)
                        {
                            string hex = Convert.ToHexString(HeaderToBytes(header));
                            hex += " + " + Convert.ToHexString(message.data!);
                            Console.Write(hex[0..8] + " ");
                            Console.Write(hex[8..12] + " ");
                            Console.Write(hex[12..16] + " ");
                            Console.Write(hex[16..32] + " ");
                            Console.Write(hex[32..64]);
                            Console.Write(hex[64..]);
                        }
                        Console.WriteLine($"\n<<< {text}");
                        break;
                    case PacketOpcode.ACKNOWLEDGE:
                        Console.WriteLine($"[{connectedClient.name}] >> ACK");
                        break;
                    case PacketOpcode.CHANNEL_JOIN:
                        Console.WriteLine($"[{remoteEndPoint}] >> JOIN\n>> Added as [{connectedClient.name}]");

                        // Read the data from a join packet.
                        DataPacket join_packet = ReadDataPacket(reader, header.size);
                        string join_key = !((header.size - 28) > 0) ? string.Empty : Encoding.UTF8.GetString(join_packet.data!);

                        // Check if the join key is real
                        if (string.IsNullOrEmpty(join_key))
                        {
                            if (!string.IsNullOrEmpty(connectedClient.public_key))
                                Console.WriteLine($"!! [{connectedClient.name}] did not provide a public key !!");
                            break;
                        }

                        // If the join key exists encrypt a public key to send back
                        PGP pkey = new(new EncryptionKeys(join_key));
                        byte[] public_key_bytes = Encoding.UTF8.GetBytes(public_key);
                        PacketHeader key_header = CreateHeader(PacketOpcode.CHANNEL_PUBLIC_KEY, Address, public_key_bytes.Length);

                        List<byte> unencrypted_bytes = [];
                        unencrypted_bytes.AddRange(HeaderToBytes(key_header));
                        unencrypted_bytes.AddRange(public_key_bytes);

                        MemoryStream unencrypted = new([.. unencrypted_bytes]);
                        MemoryStream encrypted = new();
                        pkey.EncryptStream(unencrypted, encrypted);

                        bool success = encrypted.TryGetBuffer(out ArraySegment<byte> encrypted_byte_array);
                        if (!success)
                        {
                            Console.WriteLine("Error while encrypting public key.");
                            continue;
                        }
                        byte[] encrypted_bytes = [.. encrypted_byte_array];

                        client.Send([.. encrypted_bytes], encrypted_bytes.Length, BroadcastAddress);
                        break;
                    case PacketOpcode.CHANNEL_EXIT:
                        Console.WriteLine($"[{connectedClient.name}] >> EXIT");
                        break;
                    case PacketOpcode.CHANNEL_PING:
                        Console.WriteLine($"[{connectedClient.name}] >> PING");
                        client.Send(HeaderToBytes(CreateHeader(PacketOpcode.CHANNEL_PONG, Address, 0)), 32, BroadcastAddress);
                        break;
                    case PacketOpcode.CHANNEL_PONG:
                        Int64 current = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                        Console.WriteLine($"[{connectedClient.name}] >> PONG {current - PingTimestamp}ms");
                        break;
                    case PacketOpcode.CHANNEL_PUBLIC_KEY:
                        Console.WriteLine($"[{connectedClient.name}] >> PUBLIC_KEY");
                        break;
                    default:
                        break;
                }
            }
        }
        catch (Exception e)
        {
            if (e is not EndOfStreamException)
                Console.WriteLine(e.ToString());
        }
    }
}