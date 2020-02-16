using Overby.Extensions.AsyncBinaryReaderWriter;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Win2Socks.Plugin;

namespace TrojanPlugin {
    public sealed class PluginClient : IPluginClient {
        public Socket UnderlyingSocket => _tcpClient.Client;

        private bool IsTcp => _protocolType == ClientProtocolType.Tcp;

        private readonly IPEndPoint _proxyServer;
        private readonly ClientProtocolType _protocolType;
        private readonly string _domain;
        private readonly byte[] _passwordHash;

        private readonly TcpClient _tcpClient;
        private SslStream _sslStream;
        private AsyncBinaryReader _udpReader;
        private readonly SemaphoreSlim _lock = new SemaphoreSlim(1, 1);

        private bool _disposed;

        private static readonly byte[] CRLF = new byte[] { (byte)'\r', (byte)'\n' };

        internal PluginClient(IPEndPoint proxyServer, ClientProtocolType type, string domain, byte[] passwordHash) {
            _proxyServer = proxyServer;
            _protocolType = type;
            _domain = domain;
            _passwordHash = passwordHash;

            switch (type) {
                case ClientProtocolType.Tcp:
                case ClientProtocolType.Udp:
                    _tcpClient = new TcpClient(proxyServer.AddressFamily);
                    break;
                default:
                    throw new NotImplementedException();
            }
        }

        public void Dispose() {
            if (!_disposed) {
                _tcpClient?.Dispose();
                _sslStream?.Dispose();
                _udpReader?.Dispose();

                _disposed = true;
            }
        }

        public async Task ConnectAsync(IPAddress address, int port) {
            await ConnectAsync(writer => {
                writer.Write((byte)(address.AddressFamily == AddressFamily.InterNetworkV6 ? AddressType.IPv6 : AddressType.IPv4));
                writer.Write(address.GetAddressBytes());
            }, port);
        }

        public async Task ConnectAsync(string host, int port) {
            await ConnectAsync(writer => {
                writer.Write((byte)AddressType.Domain);
                writer.Write((byte)host.Length);
                writer.Write(Encoding.UTF8.GetBytes(host));
            }, port);
        }

        public Task WriteAsync(byte[] buffer, int offset, int count) => _sslStream.WriteAsync(buffer, offset, count);

        public Task<int> ReadAsync(byte[] buffer, int offset, int count) => _sslStream.ReadAsync(buffer, offset, count);

        public async Task<int> SendAsync(byte[] datagram, IPAddress address, int port) {
            // +------+----------+----------+--------+---------+----------+
            // | ATYP | DST.ADDR | DST.PORT | Length |  CRLF   | Payload  |
            // +------+----------+----------+--------+---------+----------+
            // |  1   | Variable |    2     |   2    | X'0D0A' | Variable |
            // +------+----------+----------+--------+---------+----------+

            const int AddressTypeSize = 1,
                      PortSize = 2,
                      PayloadLengthSize = 2;

            var addressBytes = address.GetAddressBytes();
            var buffer = new byte[AddressTypeSize + addressBytes.Length + PortSize + PayloadLengthSize + CRLF.Length + datagram.Length];

            using (var stream = new MemoryStream(buffer))
            using (var writer = new BinaryWriter(stream)) {
                writer.Write((byte)(address.AddressFamily == AddressFamily.InterNetworkV6 ? AddressType.IPv6 : AddressType.IPv4));
                writer.Write(addressBytes);
                writer.Write(IPAddress.HostToNetworkOrder((short)port));
                writer.Write(IPAddress.HostToNetworkOrder((short)datagram.Length));
                writer.Write(CRLF);
                writer.Write(datagram);
            }

            // async lock
            await _lock.WaitAsync();

            try {
                await _sslStream.WriteAsync(buffer, 0, buffer.Length);

            } finally {
                _lock.Release();
            }

            return buffer.Length;
        }

        public async Task<UdpReceiveResult> ReceiveAsync() {
            // +------+----------+----------+--------+---------+----------+
            // | ATYP | DST.ADDR | DST.PORT | Length |  CRLF   | Payload  |
            // +------+----------+----------+--------+---------+----------+
            // |  1   | Variable |    2     |   2    | X'0D0A' | Variable |
            // +------+----------+----------+--------+---------+----------+

            var addressType = (AddressType)await _udpReader.ReadByteAsync();
            if (addressType == AddressType.Domain)
                throw new NotSupportedException();

            var address = new IPAddress(await _udpReader.ReadBytesAsync(addressType == AddressType.IPv4 ? 4 : 16));
            var port = IPAddress.NetworkToHostOrder(await _udpReader.ReadInt16Async());
            var payloadLength = IPAddress.NetworkToHostOrder(await _udpReader.ReadInt16Async());
            await _udpReader.ReadInt16Async(); // skip the CRLF
            var payload = await _udpReader.ReadBytesAsync(payloadLength);

            return new UdpReceiveResult(payload, new IPEndPoint(address, port));
        }

        private async Task ConnectAsync(Action<BinaryWriter> writeAddress, int port) {
            await _tcpClient.ConnectAsync(_proxyServer.Address, _proxyServer.Port);

            _sslStream = new SslStream(_tcpClient.GetStream());
            await _sslStream.AuthenticateAsClientAsync(_domain);

            if (_protocolType == ClientProtocolType.Udp)
                _udpReader = new AsyncBinaryReader(new BufferedStream(_sslStream), Encoding.UTF8);

            // +-----------------------+---------+----------------+---------+
            // | hex(SHA224(password)) |  CRLF   | Trojan Request |  CRLF   |
            // +-----------------------+---------+----------------+---------+
            // |           56          | X'0D0A' |    Variable    | X'0D0A' |
            // +-----------------------+---------+----------------+---------+
            // 
            // where Trojan Request is a SOCKS5 - like request:
            // 
            // +-----+------+----------+----------+
            // | CMD | ATYP | DST.ADDR | DST.PORT |
            // +-----+------+----------+----------+
            // |  1  |  1   | Variable |    2     |
            // +-----+------+----------+----------+

            using (var stream = new MemoryStream(256))
            using (var writer = new BinaryWriter(stream)) {
                writer.Write(_passwordHash);
                writer.Write(CRLF);
                writer.Write((byte)(IsTcp ? Command.Connect : Command.UdpAssociate));

                // write IP address or hostname
                writeAddress(writer);

                writer.Write(IPAddress.HostToNetworkOrder((short)port));
                writer.Write(CRLF);

                // it always true because we use MemoryStream(int capacity) constructor
                stream.TryGetBuffer(out var buffer);

                await _sslStream.WriteAsync(buffer.Array, buffer.Offset, buffer.Count);
            }
        }

        enum Command {
            Connect = 0x1,
            UdpAssociate = 0x3
        }

        enum AddressType {
            IPv4 = 0x1,
            Domain = 0x3,
            IPv6 = 0x4
        }
    }
}
