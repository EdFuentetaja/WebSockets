
#include "broadcaster_handler.hpp"

/**
 * \brief A simple implementation that echoes the message from the web socket client broadcasting
 * it to all the connected clients.
 */
class example_broadcast_handler : public broadcaster_handler<example_broadcast_handler>
{
public:
    template<class WebSocket, class ConstBufferSequence>
    void on_read(WebSocket& websocket, ConstBufferSequence const& bs)
    {
        char const* msg = boost::asio::buffer_cast<char const*>(boost::beast::buffers_front(bs.data()));
        size_t length = boost::asio::buffer_size(bs.data());
        std::string s_msg = std::string(msg, length);

        std::cout << "Received " << s_msg << " going to broadcast it..." << std::endl;

        broadcast_text(s_msg);
    }

    // Returns an error message to HTTP request
    template<class Body, class Allocator, class Send>
    void handle_request(http::request<Body, http::basic_fields<Allocator> >&& req, Send&& send)
    {
        // Returns a server error response
        auto const server_error =
            [&req](boost::beast::string_view what)
        {
            http::response<http::string_body> res{ http::status::internal_server_error, req.version() };
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "text/html");
            res.keep_alive(req.keep_alive());
            res.body() = "An error occurred: '" + what.to_string() + "'";
            res.prepare_payload();
            return res;
        };

        std::cout << "Request method: " << req.method() << std::endl;
        std::cout << "Request path  : " << req.target() << std::endl;

        // Handle an unknown error
        std::cout << "HTTP response is SERVER ERROR" << std::endl;
        return send(server_error("Sorry we are not taking any HTTP requests here"));
    }
};

int main(int argc, char* argv[])
{
    // Check command line arguments.
    if (argc != 4)
    {
        std::cerr <<
            "Usage: main_broadcaster <address> <port> <threads>\n" <<
            "Example:\n" <<
            "    main_broadcaster 0.0.0.0 8080 1\n";
        return EXIT_FAILURE;
    }
    auto const address = boost::asio::ip::make_address(argv[1]);
    auto const port = static_cast<unsigned short>(std::atoi(argv[2]));
    auto const thread_count = std::max<int>(1, std::atoi(argv[3]));

    // The io_context is required for all I/O
    boost::asio::io_context ioc{ thread_count };

    example_broadcast_handler the_handler;

    int timeout_seconds = 15;

    // Create a listening port
    std::shared_ptr<listener<example_broadcast_handler> > the_listener = std::make_shared<listener<example_broadcast_handler> >(
        ioc,
        tcp::endpoint{ address, port },
        the_handler,
        timeout_seconds);

    // Configure SSL: certificates, passwords, etc.
    {
        // This holds the self-signed certificate used by the server
        const std::string CA_DIRECTORY = "..\\..\\certificate_server\\CA";
        const std::string SERVER_PFX_CERTIFICATE = "..\\..\\certificate_server\\server.pfx";
        // This is to avoid having a string in the executable file with the PFX password in the clear. In practice, nobody can help protecting
        // the password from a hacker with the execurable file and a debugger. At least we are making it a bit more time consuming.
        std::stringstream SERVER_PFX_PASSWORD;
        SERVER_PFX_PASSWORD << "s" << "e" << "c" << "r" << "e" << "t" << "p" << "a" << "s" << "s" << "w" << "o" << "r" << "d";
        const std::string DH_FILE = "..\\..\\certificate_server\\dh.pem";

        bool require_client_certificate = true;
        bool accept_selfsigned_certificates = false;

        the_listener->setup_tls(CA_DIRECTORY, SERVER_PFX_CERTIFICATE, SERVER_PFX_PASSWORD.str(), DH_FILE, require_client_certificate, accept_selfsigned_certificates);
        SERVER_PFX_PASSWORD.clear();    // Remove the password from memory
    }

    // Launch the listening port
    the_listener->run();

    // Run the I/O service on the requested number of threads
    std::vector<std::thread> threads;
    threads.reserve(thread_count - 1);
    for (auto i = thread_count - 1; i > 0; --i)
        threads.emplace_back(
            [&ioc]
    {
        ioc.run();
    });

    std::cout << "Server going to listen on " << address << ":" << port << " ..." << std::endl;
    ioc.run();

    return EXIT_SUCCESS;
}
