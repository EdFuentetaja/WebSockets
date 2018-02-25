
using System;
using System.Diagnostics;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using WebSocketSharp.Server;

namespace WebSocketCSServer
{
    public class WebSocketServerWrapper : WebSocketServer, IDisposable
    {
        #region Private stuff

        /// <summary>
        /// Here we validate the client certificate. In this implementation we only require that the certificate is trusted and not expired.
        /// Additional logic can be added here.
        /// </summary>
        /// <param name="a_sender"></param>
        /// <param name="a_certificate"></param>
        /// <param name="a_chain"></param>
        /// <param name="a_sslPolicyErrors"></param>
        /// <returns></returns>
        private bool ValidateClientCertificate(object a_sender, X509Certificate a_certificate, X509Chain a_chain, SslPolicyErrors a_sslPolicyErrors)
        {
            if (a_sslPolicyErrors == SslPolicyErrors.None)
            {
                // No errors, does nothing
            }
            else if ((a_sslPolicyErrors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0)
            {
                // I'm not very sure under what circumnstance this might happen...
                Console.WriteLine("RemoteCertificateNameMismatch error");
            }
            else if ((a_sslPolicyErrors & SslPolicyErrors.RemoteCertificateChainErrors) != 0)
            {
                Console.WriteLine("Received client certificate chain is not trusted");
            }
            else if ((a_sslPolicyErrors & SslPolicyErrors.RemoteCertificateNotAvailable) != 0)
            {
                Console.WriteLine("No client certificate received");
            }

            return (a_sslPolicyErrors == SslPolicyErrors.None);
        }

        #endregion

        /// <summary>
        /// Insecure (ws) connection constructor.
        /// </summary>
        /// <param name="a_address"></param>
        /// <param name="a_port"></param>
        public WebSocketServerWrapper(System.Net.IPAddress a_address, UInt16 a_port)
            : base(a_address, a_port, false)
        {
            // Does nothing
        }

        /// <summary>
        /// Secure (wss) connection constructor.
        /// </summary>
        /// <param name="a_address"></param>
        /// <param name="a_port"></param>
        /// <param name="a_pfxServerCertificatePath"></param>
        /// <param name="a_pfxPassword"></param>
        /// <param name="a_requireClientCertificate">Set to true to request a client certificate.</param>
        public WebSocketServerWrapper(System.Net.IPAddress a_address, UInt16 a_port, string a_pfxServerCertificatePath, string a_pfxPassword, bool a_requireClientCertificate)
            : base(a_address, a_port, true)
        {
            SslConfiguration.ServerCertificate = new X509Certificate2(a_pfxServerCertificatePath, a_pfxPassword);
            Debug.Assert(SslConfiguration.ServerCertificate.HasPrivateKey);

            string subject = SslConfiguration.ServerCertificate.Subject;
            string cn = SslConfiguration.ServerCertificate.GetNameInfo(X509NameType.SimpleName, false);
            Console.WriteLine("Using Server certificate with CN: " + cn);

            // Print Subject Alternative Names, this information is useful to troubleshoot SSL handshake errors
            {
                bool somethingFound = false;
                Oid san_oid = new Oid("2.5.29.17"); // Code for "Subject Alternative Name"
                foreach (X509Extension extension in SslConfiguration.ServerCertificate.Extensions)
                {
                    // Create an AsnEncodedData object using the extensions information.
                    AsnEncodedData asndata = new AsnEncodedData(extension.Oid, extension.RawData);
                    if (asndata.Oid.Value == san_oid.Value)
                    {
                        if (!somethingFound)
                        {
                            Console.WriteLine("Subject Alternative Names:");
                            somethingFound = true;
                        }
                        Console.WriteLine("    " + asndata.Format(true));
                    }
                }
                if (!somethingFound)
                {
                    Console.WriteLine("No Subject Alternative Names found in the certificate. It is not going to validate well on modern browsers.");
                }
            }

            // SSL2, SSL3 and TLS1.0 are either insecure or obsolete
            SslConfiguration.EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls11 | System.Security.Authentication.SslProtocols.Tls12;

            if (a_requireClientCertificate)
            {
                SslConfiguration.ClientCertificateRequired = true;
                SslConfiguration.ClientCertificateValidationCallback = new RemoteCertificateValidationCallback(ValidateClientCertificate);
                Console.WriteLine("A client certificate will be required");
            }
        }

        public string Url
        {
            get
            {
                return ((IsSecure ? "wss" : "ws") + "://" + Address.ToString() + ":" + Port.ToString());
            }
        }

        void IDisposable.Dispose()
        {
            this.Stop();
        }
    }
}
