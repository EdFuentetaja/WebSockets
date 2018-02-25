
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
