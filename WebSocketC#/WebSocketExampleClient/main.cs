
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

        static void Main(string[] a_args)
        {
            const string CLIENT_PFX_CERTIFICATE = "..\\..\\..\\..\\certificate_client\\client.pfx";
            const string CLIENT_PFX_PASSWORD = "secretpassword";
            // Additionally install as CA the server certificate
            bool secure = true;
            using (WebSocketClientWrapper wscw = new WebSocketClientWrapper("127.0.0.1", 8080, "/hello", secure))
            {
                wscw.SetupClientAuthentication(CLIENT_PFX_CERTIFICATE, CLIENT_PFX_PASSWORD);

                wscw.OnMessage += ws_OnMessage;

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
