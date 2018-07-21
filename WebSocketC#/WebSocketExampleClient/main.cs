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
using WebSocketSharp;

namespace WebSocketCSClient
{
    class main
    {
        private static void ws_OnMessage(object a_sender, MessageEventArgs a_eventArgs)
        {
            Console.WriteLine("Server says: " + a_eventArgs.Data);
        }

        private static void ws_OnClose(object sender, CloseEventArgs e)
        {
            Console.WriteLine("Server closed the connection " + e.Code + " " + e.Reason + " " + e.WasClean);
        }

        static void wscw_OnError(object sender, ErrorEventArgs e)
        {
            Console.WriteLine("OnError triggered " + e.Message + " " + e.Exception);
        }

        static void Main(string[] a_args)
        {
            const string CLIENT_PFX_CERTIFICATE = "..\\..\\..\\..\\certificate_client\\client.pfx";
            const string CLIENT_PFX_PASSWORD = "secretpassword";
            // Additionally install as CA the server certificate
            bool secure = false;
            using (WebSocketClientWrapper wscw = new WebSocketClientWrapper("127.0.0.1", 8080, "/hello", secure))
            {
                wscw.SetupClientAuthentication(CLIENT_PFX_CERTIFICATE, CLIENT_PFX_PASSWORD);

                wscw.OnMessage += ws_OnMessage;
                wscw.OnClose += ws_OnClose;
                wscw.OnError += wscw_OnError;


                Console.WriteLine("Going to connect to: " + wscw.Url);
                wscw.Connect();
                if (wscw.IsAlive)
                {
                    wscw.Send("Hello from C#!");

                    while (true)
                    {
                        Console.WriteLine("Connection stablished. Enter some text to send to the server. Enter exit to finish...");
                        string text = Console.ReadLine();
                        if (text.Equals("exit"))
                        {
                            break;
                        }
                        else
                        {
                            wscw.Send(text);
                        }
                    }
                }
                else
                {
                    Console.WriteLine("Couldn't connect");
                }

                wscw.Close();
            }
        }
    }
}
