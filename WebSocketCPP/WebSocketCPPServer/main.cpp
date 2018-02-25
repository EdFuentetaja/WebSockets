
#include "server.hpp"

#include <iostream>

/**
 * \brief A simple echo server to demonstrate how it works. The PARENT template can be a WebSocketServerWrapper or a SecureWebSocketServerWrapper
 */
template <typename PARENT>
class EchoServer : public PARENT
{
public:
    // IServer
    virtual void on_message(websocketpp::connection_hdl hdl, typename IServer::message_ptr msg)
    {
        std::cout << "on_message called with hdl: " << hdl.lock().get()
                  << " and message: " << msg->get_payload()
                  << std::endl;

        try {
            send(hdl, msg->get_payload(), msg->get_opcode());
        } catch (const websocketpp::lib::error_code& e) {
            std::cout << "Echo failed because: " << e << "(" << e.message() << ")" << std::endl;
        }
    }

    // IServer
    virtual void on_open(websocketpp::connection_hdl hdl)
    {
        PARENT::connection_ptr con = get_con_from_hdl(hdl);
        websocketpp::uri_ptr puri = con->get_uri();
        std::cout << "on_open" << std::endl;
        std::cout << puri->str() << std::endl;
        std::cout << "Scheme: " << puri->get_scheme() << std::endl;
        std::cout << "Secure?: " << puri->get_secure() << std::endl;
        std::cout << "Host: " << puri->get_host() << std::endl;
        std::cout << "Port: " << puri->get_port() << std::endl;
        std::cout << "Resource: " << puri->get_resource() << std::endl;
        std::cout << "Query: " << puri->get_query() << std::endl;

        if (std::string("/hello") != puri->get_resource()) {
            con->close(websocketpp::close::status::policy_violation, "Invalid resource");
        }
    }

    // IServer
    virtual void on_close(websocketpp::connection_hdl hdl)
    {
        PARENT::connection_ptr con = get_con_from_hdl(hdl);
        websocketpp::uri_ptr puri = con->get_uri();
        std::cout << "on_close" << std::endl;
        std::cout << puri->str() << std::endl;
        // ...
    }

    // IServer
    virtual void on_fail(websocketpp::connection_hdl hdl)
    {
        server::connection_ptr con = get_con_from_hdl(hdl);
        std::cerr << "Connection error: " << con->get_ec() << " " << con->get_ec().message()  << std::endl;
    }
};

websocketpp::lib::shared_ptr<IServer> make_webserver(const websocketpp::lib::asio::ip::tcp::endpoint& a_endpoint)
{
    websocketpp::lib::shared_ptr<EchoServer<WebSocketServerWrapper> > server = websocketpp::lib::make_shared<EchoServer<WebSocketServerWrapper> >();
    server->setup(a_endpoint);

    return server;
}

websocketpp::lib::shared_ptr<IServer> make_secure_webserver(const websocketpp::lib::asio::ip::tcp::endpoint& a_endpoint, bool a_require_client_certificate)
{
    const std::string CA_DIRECTORY = "..\\certificate_server\\CA";
    const std::string SERVER_PFX_CERTIFICATE = "..\\certificate_server\\server.pfx";
    // This is to avoid having a string in the executable file with the PFX password in the clear. In practice, nobody can help protecting
    // the password from a hacker with the execurable file and a debugger. At least we are making it a bit more time consuming.
    std::stringstream SERVER_PFX_PASSWORD;
    SERVER_PFX_PASSWORD << "s" << "e" << "c" << "r" << "e" << "t" << "p" << "a" << "s" << "s" << "w" << "o" << "r" << "d";
    const std::string DH_FILE = "..\\certificate_server\\dh.pem";

    websocketpp::lib::shared_ptr<EchoServer<SecureWebSocketServerWrapper> > server = websocketpp::lib::make_shared<EchoServer<SecureWebSocketServerWrapper> >();

    server->setup(a_endpoint, SERVER_PFX_CERTIFICATE, SERVER_PFX_PASSWORD.str(), DH_FILE);
    SERVER_PFX_PASSWORD.clear();    // Remove the password from memory
    if (a_require_client_certificate) {
        server->require_client_certificate(CA_DIRECTORY);
    }

    return server;
}

int main(int argc, char* argv[])
{
    std::string host = "127.0.0.1";
    uint16_t port = 8080;
    websocketpp::lib::asio::ip::tcp::endpoint endpoint(websocketpp::lib::asio::ip::address::from_string(host), port);

    websocketpp::lib::shared_ptr<IServer> server;
    
    //server = make_webserver(endpoint);
    //server = make_secure_webserver(endpoint, false);
    server = make_secure_webserver(endpoint, true);

    server->start();

    std::cout << (server->is_secure()? "Secure WebSocket" : "WebSocket") << " server running at ";
    std::cout << (server->is_secure()? "wss" : "ws") << "://" << endpoint.address() << ":" << endpoint.port() << std::endl;
    std::cout << "Type \"exit\" to quit or something else to broadcast to all the clients..." << std::endl;
    for (;;) {
        std::string line;
        std::cin >> line;
        if (line == "exit") {
            break;
        } else {
            server->broadcast(line);
        }
    }

    server->stop();

    return 0;
}
