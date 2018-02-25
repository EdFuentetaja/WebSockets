
#ifndef CLIENT_HPP__F2BEF6C9236D4F37A0366E3707644826
#define CLIENT_HPP__F2BEF6C9236D4F37A0366E3707644826

#include <websocketpp/config/asio_client.hpp>
#include <websocketpp/client.hpp>
#include <websocketpp/common/thread.hpp>
#include <websocketpp/common/memory.hpp>

#include <iostream>
#include <fstream>

// There is one dependency with boost below, on the call to set_verify_callback
#include <boost/bind.hpp>


#include <PEMExtractor.hpp>


/**
 * \brief This class is responsible for creating connections.
 */
template <typename PARENT, typename CONNECTION>
class WebSocketEndPointWrapper_Base : public PARENT
{
protected:
    websocketpp::lib::thread thread;
    websocketpp::uri_ptr puri;

public:
    WebSocketEndPointWrapper_Base<PARENT, CONNECTION>()
    {
        clear_access_channels(websocketpp::log::alevel::all);
        clear_error_channels(websocketpp::log::elevel::all);

        init_asio();
        start_perpetual();

        thread = websocketpp::lib::thread(&client::run, this);
    }

    virtual ~WebSocketEndPointWrapper_Base<PARENT, CONNECTION>() 
    {
        stop_perpetual();

        stop();

        if (thread.joinable()) {
            thread.join();
        }
    }

    /**
     * \ brief Returns the URI we used for the last connect.
     */
    websocketpp::uri_ptr get_puri()
    {
        return puri;
    }

    /**
     * \brief Attempts to create a connection to a given URI.
     */
    websocketpp::lib::shared_ptr<CONNECTION> connect(websocketpp::uri_ptr a_puri) 
    {
        websocketpp::lib::shared_ptr<CONNECTION> connection;

        websocketpp::lib::error_code ec;
        client::connection_ptr con;
        
        con = get_connection(a_puri, ec);

        if (ec) {
            std::cerr << "Connect initialization error: " << ec.message() << std::endl;
        } else {
            connection = websocketpp::lib::make_shared<CONNECTION>(con->get_handle());

            con->set_open_handler(websocketpp::lib::bind(&CONNECTION::on_open, connection.get(), websocketpp::lib::placeholders::_1));
            con->set_fail_handler(websocketpp::lib::bind(&CONNECTION::on_fail, connection.get(), websocketpp::lib::placeholders::_1));
            con->set_close_handler(websocketpp::lib::bind(&CONNECTION::on_close, connection.get(), websocketpp::lib::placeholders::_1));
            con->set_message_handler(websocketpp::lib::bind(&CONNECTION::on_message, connection.get(),websocketpp::lib::placeholders::_1, websocketpp::lib::placeholders::_2));

            PARENT::connect(con);

            puri = a_puri;
        }

        return connection;
    }

    /**
     * \brief Attempts to create a connection to a given hostname, port and address.
     */
    websocketpp::lib::shared_ptr<CONNECTION> connect(std::string a_hostname, uint16_t a_port, std::string a_address)
    {
        websocketpp::uri_ptr some_puri = websocketpp::uri_ptr(new websocketpp::uri(transport_type::is_secure(), a_hostname, a_port, a_address));
        return WebSocketEndPointWrapper_Base<PARENT, CONNECTION>::connect(some_puri);
    }
};

/**
 * \brief This class is responsible for creating secured connections. It takes care of configuring the TLS connection.
 */
template <typename CONNECTION>
class SecureWebSocketEndPointWrapper_Base : public WebSocketEndPointWrapper_Base<websocketpp::client<websocketpp::config::asio_tls_client>, CONNECTION>
{
private:
    typedef websocketpp::lib::shared_ptr<websocketpp::lib::asio::ssl::context> context_ptr;

    websocketpp::lib::shared_ptr<char[]> client_certificate;
    websocketpp::lib::asio::const_buffer client_certificate_cb;

    websocketpp::lib::shared_ptr<char[]> client_certificate_pk;
    websocketpp::lib::asio::const_buffer client_certificate_pk_cb;

    websocketpp::lib::shared_ptr<char[]> dh_data;
    websocketpp::lib::asio::const_buffer dh_data_cb;

    std::string ca_path;

    /**
     * \brief Configures the TLS layer, setting the client certificate if it's used.
     */
    context_ptr on_tls_init(websocketpp::connection_hdl)
    {
        context_ptr ctx = websocketpp::lib::make_shared<websocketpp::lib::asio::ssl::context>(websocketpp::lib::asio::ssl::context::sslv23);

        try {
            // Disable currently insecure SSLV2, SSLV3 and TLSv1
            ctx->set_options(websocketpp::lib::asio::ssl::context::default_workarounds |
                             websocketpp::lib::asio::ssl::context::no_sslv2 |
                             websocketpp::lib::asio::ssl::context::no_sslv3 |
                             websocketpp::lib::asio::ssl::context::no_tlsv1 |
                             websocketpp::lib::asio::ssl::context::single_dh_use);

            // Verify the server certificate:
            ctx->set_verify_mode(websocketpp::lib::asio::ssl::verify_peer | websocketpp::lib::asio::ssl::verify_fail_if_no_peer_cert);
            ctx->set_verify_callback(boost::bind(&SecureWebSocketEndPointWrapper_Base<CONNECTION>::verify_certificate_cb, this, boost::placeholders::_1, boost::placeholders::_2));
            ctx->add_verify_path(ca_path.c_str());

            // Set the DH data, apparently required for the DH stuff to work. See also comments on the setup method
            ctx->use_tmp_dh(dh_data_cb);

            // And this seems to be needed by the ECDHE ciphers
            SSL_CTX_set_ecdh_auto(ctx->native_handle(), 1);

            // Set the client certificate and its private key
            if (client_certificate_cb.data() != NULL) {
                ctx->use_certificate_chain(client_certificate_cb);
            }
            if (client_certificate_pk_cb.data() != NULL) {
                ctx->use_private_key(client_certificate_pk_cb, websocketpp::lib::asio::ssl::context::file_format::pem);
            }

        } catch (std::exception& e) {
            std::cerr << e.what() << std::endl;
        }

        return ctx;
    }

public:
    SecureWebSocketEndPointWrapper_Base<CONNECTION>() : WebSocketEndPointWrapper_Base< websocketpp::client<websocketpp::config::asio_tls_client>, CONNECTION>()
    {
        set_tls_init_handler(websocketpp::lib::bind(&SecureWebSocketEndPointWrapper_Base<CONNECTION>::on_tls_init, this, websocketpp::lib::placeholders::_1));
    }

    /**
     * \param a_ca_path The path to our trusted certifying authorities (CA). OpenSSL will trust any certificates in this folder as CA. See the notes for more details.
     * \param a_dhFilePath Path to the "DH" file with some Diffie-Hellman stuff. This file is required when we use DH ciphers
     */
    void setup(const std::string& a_ca_path, const std::string& a_dhFilePath)
    {
        ca_path = a_ca_path;

        // Read the DH file
        // This is required since we are going to propose using DH ciphers
        // See https://wiki.openssl.org/index.php/Diffie-Hellman_parameters
        // Better to generate the file offline, it takes a long time...
        // Example method of generating this file:
        // `openssl dhparam -out dh.pem 2048`
        // Mozilla Intermediate suggests 1024 as the minimum size to use
        // Mozilla Modern suggests 2048 as the minimum size to use.
        {
            // use ios::ate to get positioned at the end of the file, so tellg will come up with the length of the file:
            std::ifstream in (a_dhFilePath, std::ios::in | std::ios::binary | std::ios::ate);
            if (! in.is_open()) {
                std::cerr << "Error opening file: " << a_dhFilePath << std::endl;
                throw new std::invalid_argument (a_dhFilePath);
            }

            unsigned int length = (unsigned int)in.tellg();

            dh_data = websocketpp::lib::make_shared<char[]>(length);
            in.seekg(0, std::ios::beg);
            in.read(dh_data.get(), length);
            in.close();

            dh_data_cb = websocketpp::lib::asio::const_buffer(dh_data.get(), length);
        }
    }

    /**
     * \param a_pfxClientCertificatePath Path to the PFX file containing a valid certificate and its private key, both in PEM format.
     * \param a_pfxPassword Password to open the PFX file. This is required since PFX files are encrypted.
     */
    void provide_client_certificate(const std::string& a_pfxClientCertificatePath, const std::string& a_pfxPassword)
    {
        {
            // Read the client certificate
            PEMExtractor extractor;
            int result = extractor.process_p12_file(a_pfxClientCertificatePath, a_pfxPassword);
            if (result == 0) {
                char* buffer;
                unsigned int length;
        
                length = extractor.get_certificate(&buffer);
                client_certificate = websocketpp::lib::make_shared<char[]>(length);
                memcpy(client_certificate.get(), buffer, length);
                client_certificate_cb = websocketpp::lib::asio::const_buffer(client_certificate.get(), length);

                length = extractor.get_private_key(&buffer);
                client_certificate_pk = websocketpp::lib::make_shared<char[]>(length);
                memcpy(client_certificate_pk.get(), buffer, length);
                client_certificate_pk_cb = websocketpp::lib::asio::const_buffer(client_certificate_pk.get(), length);
            } else {
                std::cerr << "Error processing pfx file: " << a_pfxClientCertificatePath << std::endl;
                throw new std::invalid_argument (a_pfxClientCertificatePath);
            }
            extractor.reset();
        }
    }

    /**
     * \brief Here is where we add any custom code to verify the incoming server certificate.
     */
    bool verify_certificate_cb(bool preverified, websocketpp::lib::asio::ssl::verify_context& ctx)
    {
        // So far nothing. Before calling here the SSL layer has verified whether the certificate is trusted and not expired.

        return preverified;
    }
};

/**
 * \brief An skeleton of a connection. The code here can be reused by different implementations.
 */
template<typename CONFIG>
class ConnectionWrapper_Base
{
protected:
    websocketpp::connection_hdl hdl;

    typename websocketpp::client<CONFIG>::connection_ptr get_connection_ptr(websocketpp::connection_hdl a_hdl) const
    {
        return websocketpp::lib::static_pointer_cast<websocketpp::client<CONFIG>::connection_type>(a_hdl.lock());
    }

public:
    ConnectionWrapper_Base<CONFIG>()
    {
        // Does nothing
    }

    ConnectionWrapper_Base<CONFIG>(websocketpp::connection_hdl a_hdl) : hdl(a_hdl)
    {
        // Does nothing
    }

    virtual ~ConnectionWrapper_Base<CONFIG>()
    {
        // Does nothing
    }
    
    websocketpp::connection_hdl get_handle() const
    {
        return hdl;
    }

    websocketpp::session::state::value get_state() const
    {
        websocketpp::client<CONFIG>::connection_ptr con = get_connection_ptr(hdl);
        return con? con->get_state() : (websocketpp::session::state::value)-1;
    }

    /**
     * \brief Callback method. Called when the connection is just opened.
     */
    virtual void on_open(websocketpp::connection_hdl a_hdl)
    {
        // Does nothing, to be overriden
    }

    /**
     * \brief Callback method. Called when the connection fails.
     */
    virtual void on_fail(websocketpp::connection_hdl a_hdl)
    {
        // Does nothing, to be overriden
    }

    /**
     * \brief Callback method. Called when the connection closes.
     */
    virtual void on_close(websocketpp::connection_hdl a_hdl) 
    {
        // Does nothing, to be overriden
    }

    /**
     * \brief Callback method. Called when we receive an asynchronous message from the server.
     */
    virtual void on_message(websocketpp::connection_hdl a_hdl, typename CONFIG::message_type::ptr msg) 
    {
        // Does nothing, to be overriden
    }
    
    /**
     * \brief To send a message to the server.
     */
    void send(std::string message) 
    {
        websocketpp::client<CONFIG>::connection_ptr con = get_connection_ptr(hdl);
        if (con) {
            con->send(message, websocketpp::frame::opcode::text);
        }
    }

    /**
     * \brief To close the connection.
     */
    void close(websocketpp::close::status::value code, std::string reason) 
    {
        websocketpp::client<CONFIG>::connection_ptr con = get_connection_ptr(hdl);
        if (con) {
            websocketpp::lib::error_code ec;
                
            con->close(code, reason, ec);
        }
    }
};

#endif // #ifndef CLIENT_HPP__F2BEF6C9236D4F37A0366E3707644826
