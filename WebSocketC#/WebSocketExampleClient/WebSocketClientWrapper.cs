/*
 * Copyright (c) 2018, Eduardo Fuentetaja. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the WebSocket++ Project nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL PETER THORSON BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

using System;
using System.Diagnostics;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using WebSocketSharp;

namespace WebSocketCSClient
{
    public class WebSocketClientWrapper : WebSocket
    {
        #region Private stuff

        private X509Certificate2 clientCertificate;

        /// <summary>
        /// Troubleshoot the server certificate validation. Additional validation logic can be added here.
        /// </summary>
        /// <param name="a_sender"></param>
        /// <param name="a_certificate"></param>
        /// <param name="a_chain"></param>
        /// <param name="a_sslPolicyErrors"></param>
        /// <returns></returns>
        private bool RemoteCertificateValidation(object a_sender, X509Certificate a_certificate, X509Chain a_chain, SslPolicyErrors a_sslPolicyErrors)
        {
            if (a_sslPolicyErrors == SslPolicyErrors.None)
            {
                // Does nothing
            }
            else if ((a_sslPolicyErrors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0)
            {
                // This happens because the name (CN) on the certificate doesn't match the host
                Console.WriteLine("Certificate name should match the host name I'm suppossed to connect to, but it doesn't");
                Console.WriteLine("Certificate subject: " + a_certificate.Subject);
                Console.WriteLine("Expected host name: " + Url.Host);
            }
            else if ((a_sslPolicyErrors & SslPolicyErrors.RemoteCertificateChainErrors) != 0)
            {
                // Check that whoever signed the certificate the server is sending here is a CA in this machine
                Console.WriteLine("Received server certificate chain is not trusted");
            }
            else if ((a_sslPolicyErrors & SslPolicyErrors.RemoteCertificateNotAvailable) != 0)
            {
                Console.WriteLine("No server certificate received");
            }

            return (a_sslPolicyErrors == SslPolicyErrors.None);
        }

        /// <summary>
        /// Return the client certificate.
        /// </summary>
        /// <param name="a_sender"></param>
        /// <param name="a_targetHost"></param>
        /// <param name="a_localCertificates"></param>
        /// <param name="a_remoteCertificate"></param>
        /// <param name="a_acceptableIssuers"></param>
        /// <returns></returns>
        private X509Certificate LocalCertificateSelectionCallback(object a_sender, string a_targetHost, X509CertificateCollection a_localCertificates, X509Certificate a_remoteCertificate, string[] a_acceptableIssuers)
        {
            Debug.Assert(clientCertificate != null);
            return clientCertificate;
        }

        #endregion

        /// <summary>
        /// Constructor. The URL to connect to is composed as <wss or ws>://<a_hostName>:<a_port><a_path>
        /// </summary>
        /// <param name="a_hostName">The host name to connect to.</param>
        /// <param name="a_port">The port number.</param>
        /// <param name="a_path">Path. Should start with a slash character /</param>
        /// <param name="a_secure">To decice between wss or ws schemes.</param>
        public WebSocketClientWrapper(string a_hostName, UInt16 a_port, string a_path, bool a_secure) : 
            base((a_secure ? "wss" : "ws") + "://" + a_hostName.ToString() + ":" + a_port.ToString() + a_path)
        {
            if (a_secure)
            {
                Console.WriteLine("A valid server certificate is required");
                SslConfiguration.EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12;
                SslConfiguration.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(RemoteCertificateValidation);
                SslConfiguration.CheckCertificateRevocation = true;
            }
        }

        /// <summary>
        /// Setup the client certificate to send to the server upon connection.
        /// </summary>
        /// <param name="a_pfxClientCertificatePath">Path to the pfx file with the client certificate.</param>
        /// <param name="a_pfxPassword">Password to the pfx file.</param>
        public void SetupClientAuthentication(string a_pfxClientCertificatePath, string a_pfxPassword)
        {
            if (IsSecure)
            {
                clientCertificate = new X509Certificate2(a_pfxClientCertificatePath, a_pfxPassword);
                SslConfiguration.ClientCertificateSelectionCallback = new LocalCertificateSelectionCallback(LocalCertificateSelectionCallback);
                Console.WriteLine("A client certificate will be provided");
                Console.WriteLine("Client certificated issued by: " + clientCertificate.Issuer);
            }
            else
            {
                Debug.WriteLine("Cannot setup client authentication under an insecure connection");
            }
        }
    }
}
