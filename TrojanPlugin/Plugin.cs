using System;
using System.Composition;
using Win2Socks.Plugin;
using HashLib;
using System.Text;
using System.Linq;
using System.Diagnostics;
using TrojanPlugin.Properties;

namespace TrojanPlugin {
    [Export(typeof(IPlugin))]
    public class Plugin : IPlugin {
        public string Name => "Trojan";

        public Guid UniqueId { get; } = new Guid("97d11b0b-b44b-4cc1-9da5-746482cb60e8");

        public bool SupportsTcp => true;

        public bool SupportsUdp => true;

        public string ArgumentsEditor => null;

#if DEBUG
        public Plugin() {
            Debugger.Launch();
        }
#endif

        public IClientBuilder CreateClientBuilder(string arguments) {
            if (string.IsNullOrWhiteSpace(arguments))
                throw new ArgumentException(Resources.ArgumentsCanNotBeNull);

            var parts = arguments.Split(new[] { ':' }, 2, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2)
                throw new FormatException(Resources.InvalidArgumentsFormat);

            var domain = parts[0];
            var password = parts[1];

            var passwordHash = Encoding.UTF8.GetBytes(HashFactory.Crypto.CreateSHA224()
                                                                        .ComputeString(password, Encoding.UTF8)
                                                                        .GetBytes()
                                                                        .ToHexString());

            return new ClientBuilder(domain, passwordHash);
        }
    }
}
