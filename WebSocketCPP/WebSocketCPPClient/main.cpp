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

#include "client.hpp"

/**
 * \brief A custom extension of a connection. The template allow for it to be secured (wss://) or non-secured (ws://)
 */
template<typename CONFIG>
class MyConnection : public ConnectionWrapper_Base<CONFIG>
{
public:
    typedef WebSocketEndPointWrapper_Base<websocketpp::client<CONFIG>, MyConnection<CONFIG> > WebSocketEndPoint;
    typedef SecureWebSocketEndPointWrapper_Base<MyConnection<CONFIG> > SecureWebSocketEndPoint;
    typedef websocketpp::lib::shared_ptr<WebSocketEndPointWrapper_Base<websocketpp::client<CONFIG>, MyConnection<CONFIG> > > WebSocketEndPoint_ptr;

    MyConnection<CONFIG>()
    {
        // Does nothing
    }

    MyConnection<CONFIG>(websocketpp::connection_hdl a_hdl) : ConnectionWrapper_Base<CONFIG>(a_hdl)
    {
        // Does nothing
    }

    // ConnectionWrapper_Base
    virtual void on_open(websocketpp::connection_hdl a_hdl)
    {
        assert(a_hdl.lock() == hdl.lock());

        websocketpp::client<CONFIG>::connection_ptr con = get_connection_ptr(hdl);
        std::string server = con->get_response_header("Server");

        std::cout << server << std::endl;
    }

    // ConnectionWrapper_Base
    virtual void on_fail(websocketpp::connection_hdl a_hdl)
    {
        assert(a_hdl.lock() == hdl.lock());

        websocketpp::client<CONFIG>::connection_ptr con = get_connection_ptr(hdl);
        std::string error_reason;
        if (con) {
            error_reason = con->get_ec().message();
        } else {
            error_reason = "Invalid connection";
        }

        std::cerr << "Connection failed " << error_reason << std::endl;
    }

    // ConnectionWrapper_Base
    virtual void on_close(websocketpp::connection_hdl a_hdl) 
    {
        assert(a_hdl.lock() == hdl.lock());

        websocketpp::client<CONFIG>::connection_ptr con = get_connection_ptr(hdl);
        if (con) {
            std::cout << "close code: " << con->get_remote_close_code() << " (" << websocketpp::close::status::get_string(con->get_remote_close_code()) << "), close reason: " << con->get_remote_close_reason() << std::endl;
        }
    }

    // ConnectionWrapper_Base
    virtual void on_message(websocketpp::connection_hdl a_hdl, typename CONFIG::message_type::ptr msg) 
    {
        assert(a_hdl.lock() == hdl.lock());

        if (msg->get_opcode() == websocketpp::frame::opcode::text) {
            std::cout << "Text message received: " << msg->get_payload() << std::endl;
        } else {
            std::cout << "Message received: " << websocketpp::utility::to_hex(msg->get_payload()) << std::endl;
        }
    }
};

typedef MyConnection<websocketpp::config::asio_client> MyConnection_type;
typedef MyConnection<websocketpp::config::asio_tls_client> MySecureConnection_type;

/**
 * \brief Example of the construction of a non-secured endpoint. This endpoint allow for non-secured connection.
 */
MyConnection_type::WebSocketEndPoint_ptr make_endpoint()
{
    MyConnection_type::WebSocketEndPoint_ptr endpoint = websocketpp::lib::make_shared<MyConnection_type::WebSocketEndPoint>();

    return endpoint;
}

/**
 * \brief Example of the construction of a secured endpoint. This endpoint allow for secured connection.
 * \param a_provide_client_centificate Set to true to enable the client certificate, meaning that upon connection we are sending a certificate to the server. The server needs to find this certificate valid.
 */
MySecureConnection_type::WebSocketEndPoint_ptr make_secure_endpoint(bool a_provide_client_centificate)
{
    const std::string CA_DIRECTORY = "..\\certificate_client\\CA";
    const std::string DH_FILE = "..\\certificate_client\\dh.pem";

    const std::string CLIENT_PFX_CERTIFICATE = "..\\certificate_client\\client.pfx";
    // This is to avoid having a string in the executable file with the PFX password in the clear. In practice, nobody can help protecting
    // the password from a hacker with the execurable file and a debugger. At least we are making it a bit more time consuming.
    std::stringstream CLIENT_PFX_PASSWORD;
    CLIENT_PFX_PASSWORD << "s" << "e" << "c" << "r" << "e" << "t" << "p" << "a" << "s" << "s" << "w" << "o" << "r" << "d";


    websocketpp::lib::shared_ptr<MySecureConnection_type::SecureWebSocketEndPoint> endpoint = websocketpp::lib::make_shared<MySecureConnection_type::SecureWebSocketEndPoint>();

    endpoint->setup(CA_DIRECTORY, DH_FILE);
    if (a_provide_client_centificate) {
        endpoint->provide_client_certificate(CLIENT_PFX_CERTIFICATE, CLIENT_PFX_PASSWORD.str());
    }

    return endpoint;
}

int main(int argc, char *argv[])
{
    // Non-secured version
    typedef MyConnection_type Connection;
    Connection::WebSocketEndPoint_ptr endpoint = endpoint = make_endpoint();

    // Secured version
    //typedef MySecureConnection_type Connection;
    //Connection::WebSocketEndPoint_ptr endpoint = make_secure_endpoint(false);
    //Connection::WebSocketEndPoint_ptr endpoint = make_secure_endpoint(true);

    websocketpp::lib::shared_ptr<Connection> connection = endpoint->connect("127.0.0.1", 8080, "/hello");
    if (connection) {
        std::cout << "Created connection to " << endpoint->get_puri()->str() << " with hdl " << connection->get_handle().lock().get() << std::endl;

        while (connection->get_state() == websocketpp::session::state::connecting) {
            // Active wait...
            boost::this_thread::sleep_for(boost::chrono::milliseconds(100));
        }

        if (connection->get_state() != websocketpp::session::state::open) {
            std::cerr << "Connection to " << endpoint->get_puri()->str() << " failed" << std::endl;
        } else {
            std::cout << "Client connected, type \"exit\" to quit or something else to send to the server..." << std::endl;
            connection->send("Hello from C++!");
            for (;;) {
                std::string line;
                std::cin >> line;
                if (line == "exit") {
                    break;
                } else {
                    connection->send(line);
                }
            }

            int close_code = websocketpp::close::status::normal;
            std::string reason = "done";
            connection->close(close_code, reason);
        }
    } else {
        std::cout << "Error connecting to " << endpoint->get_puri()->str() << std::endl;
    }

    return 0;
}
