using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using Win2Socks.Plugin;

namespace TrojanPlugin {
    public class ClientBuilder : IClientBuilder {
        private readonly string _domain;
        private readonly byte[] _passwordHash;

        internal ClientBuilder(string domain, byte[] passwordHash) {
            _domain = domain;
            _passwordHash = passwordHash;
        }

        public IPluginClient Build(IPEndPoint proxyServer, ClientProtocolType protocolType) => 
            new PluginClient(proxyServer, protocolType, _domain, _passwordHash);
    }
}
