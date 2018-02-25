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
using WebSocketSharp;
using WebSocketSharp.Server;

namespace WebSocketCSServer
{
    class main
    {
        public class MyWSService : WebSocketBehavior
        {
            protected override void OnMessage(MessageEventArgs a_eventArgs)
            {
                string msg = "Data received: [" + a_eventArgs.Data + "]";
                Console.WriteLine(msg);
                Send(msg);
            }

            protected override void OnOpen()
            {
                Console.WriteLine("New client connection");

                if (Context.QueryString.Count > 0)
                {
                    string foo = Context.QueryString["foo"];
                    Console.WriteLine("Query string foo: " + foo);
                }
            }

            protected override void OnClose(CloseEventArgs a_eventArgs)
            {
                Console.WriteLine("Client connection closed");
            }
        }

        static void Main(string[] a_args)
        {
            const string SERVER_PFX_CERTIFICATE = "..\\..\\..\\..\\certificate_server\\server.pfx";
            const string SERVER_PFX_PASSWORD = "secretpassword";

            // Nonsecure ws://
            //using (WebSocketServerWrapper wssw = new WebSocketServerWrapper(System.Net.IPAddress.Parse("127.0.0.1"), 8080))

            // Secure wss://
            bool requireClientCertificate = true;
            using (WebSocketServerWrapper wssw = new WebSocketServerWrapper(System.Net.IPAddress.Parse("127.0.0.1"), 8080, SERVER_PFX_CERTIFICATE, SERVER_PFX_PASSWORD, requireClientCertificate))
            {
                string path = "/hello"; // Be sure to start it with a /
                wssw.AddWebSocketService<MyWSService>(path);
                WebSocketServiceHost host;
                wssw.WebSocketServices.TryGetServiceHost(path, out host);
                Debug.Assert(host != null);

                wssw.Start();
                if (wssw.IsListening)
                {
                    Console.WriteLine("Server listening on: " + wssw.Url + path);
                    Console.WriteLine("Enter some text to push to the client. Enter exit to finish...");
                    while (true)
                    {
                        string text = Console.ReadLine();
                        if (text.Equals("exit"))
                        {
                            break;
                        }
                        else
                        {
                            Console.WriteLine("Sending " + text + " to " + host.Sessions.Count + " client(s)");
                            host.Sessions.Broadcast(text);
                        }
                    }
                }
                else
                {
                    Console.WriteLine("Error setting up the server");
                }
                wssw.Stop();
            }
        }
    }
}
