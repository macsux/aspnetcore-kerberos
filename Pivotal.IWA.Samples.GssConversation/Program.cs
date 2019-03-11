using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.GssKerberos;
using Microsoft.AspNetCore.Authentication.GssKerberos.Disposables;
using Microsoft.AspNetCore.Authentication.GssKerberos.Native;
using static Microsoft.AspNetCore.Authentication.GssKerberos.Native.Krb5Interop;

namespace Pivotal.IWA.Samples.GssConversation
{
    class Program
    {
        public static void Main()
        {
            var clientSPN = "iwaclient@ALMIREX.DC";
            var serviceSPN = "iwasvc@ALMIREX.DC";
            EnsureTGT(clientSPN);
            using (var clientCredentials = GssCredentials.FromKeytab(clientSPN, CredentialUsage.Both))
            using (var serverCredentials = GssCredentials.FromKeytab(serviceSPN, CredentialUsage.Accept))
            {
                using (var initiator = new GssInitiator(credential: clientCredentials, spn: serviceSPN))
                using (var acceptor = new GssAcceptor(credential: serverCredentials))
                using (var acceptor2 = new GssAcceptor(credential: serverCredentials))
                {
                    var token = initiator.Initiate(null);
                    
                    token = acceptor.Accept(token);
                    token = initiator.Initiate(token);

                }
            }
        }

        public static void EnsureTGT(string principal)
        {
            ProcessStartInfo cmdsi = new ProcessStartInfo("kinit");
            cmdsi.Arguments = $"-k -i {principal}";
            cmdsi.UseShellExecute = false;
            cmdsi.RedirectStandardOutput = true;
            cmdsi.RedirectStandardError = true;
            Process proc = Process.Start(cmdsi);
            string output = proc.StandardError.ReadToEnd();

            if (!string.IsNullOrWhiteSpace(output))
            {
                throw new Exception(output);
            }

            proc.WaitForExit();
        }
    }
}



