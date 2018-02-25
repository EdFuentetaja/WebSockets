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

#ifndef SERVER_HPP__E586C29E14AB4D2F9621DCC4AF574035
#define SERVER_HPP__E586C29E14AB4D2F9621DCC4AF574035

#include <websocketpp/config/asio.hpp>
#include <websocketpp/server.hpp>

#include <iostream>
#include <fstream>
#include <set>

// owner_less should be added in websocketpp::lib namespace
#ifdef ASIO_STANDALONE
    // Sorry I haven't tested this. I'm not using a C11 compiler
    #include <memory>
    namespace websocketpp
    {
    namespace lib
    {
        typedef std::owner_less<websocketpp::connection_hdl> owner_less_connection_hdl;
    }
    }
#else
    #include <boost/smart_ptr/owner_less.hpp>
    namespace websocketpp
    {
    namespace lib
    {
        typedef boost::owner_less<websocketpp::connection_hdl> owner_less_connection_hdl;
    }
    }
#endif

// There is another dependency with boost below, on the call to set_verify_callback
#include <boost/bind.hpp>

#include <PEMExtractor.hpp>

/**
 * \brief A simple server interface. Makes clearly available the methods that are meant to be overriden and called.
 */
class IServer
{
public:
    // pull out the type of messages sent by our config
    typedef websocketpp::config::asio::message_type::ptr message_ptr;

    ~IServer()
    {
        // Does nothing
    }

    virtual void broadcast(const std::string& a_text) = 0;

    virtual void broadcast(const void* a_data, size_t a_length) = 0;

    virtual void on_message(websocketpp::connection_hdl hdl, message_ptr msg)
    {
        // Does nothing, to be overriden
    }

    virtual void on_open(websocketpp::connection_hdl hdl)
    {
        // Does nothing, to be overriden
    }

    virtual void on_close(websocketpp::connection_hdl hdl)
    {
        // Does nothing, to be overriden
    }

    virtual void on_fail(websocketpp::connection_hdl hdl)
    {
        // Does nothing, to be overriden
    }

    virtual void start() = 0;

    virtual void stop() = 0;

    virtual bool is_secure() const = 0;
};

/**
 * \brief A plain websocket server. Keeps track of all the connected clients and allow for broadcast calls to them.
 */
template <typename PARENT>
class WebSocketServerWrapper_Base : public PARENT, public IServer
{
protected:
    websocketpp::lib::asio::ip::tcp::endpoint endpoint;

    websocketpp::lib::thread the_thread;
    websocketpp::lib::mutex startstop_mutex;
    websocketpp::lib::mutex connections_mutex;

    typedef std::set<websocketpp::connection_hdl, websocketpp::lib::owner_less_connection_hdl> ConnectionSet;
    ConnectionSet connections;

    /**
     * \brief Adds the connection to the list of connections and calls on_open.
     * \param a_hdl The connection.
     */
    void server_on_open(websocketpp::connection_hdl a_hdl)
    {
        {
            websocketpp::lib::mutex::scoped_lock lock(connections_mutex);
            connections.insert(a_hdl);
        }

        on_open(a_hdl);
    }

    /**
     * \brief Removes the connection to the list of connections and calls on_open.
     * \param a_hdl The connection.
     */
    void server_on_close(websocketpp::connection_hdl a_hdl)
    {
        {
            websocketpp::lib::mutex::scoped_lock lock(connections_mutex);
            connections.erase(a_hdl);
        }

        on_close(a_hdl);
    }

public:
    WebSocketServerWrapper_Base<PARENT>()
    {
        // Register our message handlers
        set_message_handler(websocketpp::lib::bind(&WebSocketServerWrapper_Base<PARENT>::on_message, this, websocketpp::lib::placeholders::_1, websocketpp::lib::placeholders::_2));
        //set_http_handler(websocketpp::lib::bind(&WebSocketServerWrapper_Base<PARENT>::on_http, this, websocketpp::lib::placeholders::_1));
        set_open_handler(websocketpp::lib::bind(&WebSocketServerWrapper_Base<PARENT>::server_on_open, this, websocketpp::lib::placeholders::_1));
        set_close_handler(websocketpp::lib::bind(&WebSocketServerWrapper_Base<PARENT>::server_on_close, this, websocketpp::lib::placeholders::_1));
        set_fail_handler(websocketpp::lib::bind(&IServer::on_fail, this, websocketpp::lib::placeholders::_1));
    }

    virtual ~WebSocketServerWrapper_Base<PARENT>()
    {
        // Does nothing
    }

    /*
    void on_http(websocketpp::connection_hdl a_hdl)
    {
        SecureWebSocketServerWrapper::connection_ptr con = get_con_from_hdl(a_hdl);
    
        con->set_body("Hello World!");
        con->set_status(websocketpp::http::status_code::ok);
    }
    */

    /**
     * \param a_endpoint The local TCP endpoint we are going to listen from. This call should go before start.
     */
    void setup(const websocketpp::lib::asio::ip::tcp::endpoint& a_endpoint)
    {
        endpoint = a_endpoint;
    }

    /**
     * \brief Starts the websocket server. Runs in its own thread. This call returns inmediately.
     */
    void start()
    {
        websocketpp::lib::mutex::scoped_lock lock(startstop_mutex);

        // Initialize ASIO
        init_asio();

        // Listen
        listen(endpoint);

        // Start the server accept loop
        start_accept();

        // Start the ASIO io_service run loop in a new thread
        the_thread = websocketpp::lib::thread(&WebSocketServerWrapper_Base<PARENT>::run, this);
    }

    /**
     * \brief Stops the websocket server.
     */
    void stop()
    {
        websocketpp::lib::mutex::scoped_lock lock(startstop_mutex);

        PARENT::stop();
        if (the_thread.joinable()) {
            the_thread.join();
        }

        reset();
    }

    /**
     * \brief Sends a text to all our connected clients.
     * \param a_test The text to send.
     */
    // IServer
    virtual void broadcast(const std::string& a_text)
    {
        websocketpp::lib::mutex::scoped_lock lock(connections_mutex);

        for (ConnectionSet::iterator it=connections.begin(); it != connections.end(); ++it) {
            send(*it, a_text, websocketpp::frame::opcode::text);
        }
        std::cout << "Message sent to " << connections.size() << " client" << ((connections.size() == 1)? "" : "s") << std::endl;
    }

    /**
     * \brief Sends some binary data to all our connected clients.
     * \param a_test The pointer to the binary data to send.
     * \param a_lenth Length in bytes of the data to send.
     */
    // IServer
    virtual void broadcast(const void* a_data, size_t a_length)
    {
        websocketpp::lib::mutex::scoped_lock lock(connections_mutex);

        for (ConnectionSet::iterator it=connections.begin(); it != connections.end(); ++it) {
            send(*it, a_data, a_length, websocketpp::frame::opcode::binary);
        }
    }

    /**
     * \brief Says true, this is a plain websocket server, not secure.
     */
    // IServer
    virtual bool is_secure() const
    {
        return false;
    }
};

typedef WebSocketServerWrapper_Base< websocketpp::server<websocketpp::config::asio> > WebSocketServerWrapper;

/**
 * \brief A secure websocket server. Extends the plain websocket server adding the setup of all the SSL configuration to run over a wss connection.
 */
class SecureWebSocketServerWrapper : public WebSocketServerWrapper_Base< websocketpp::server<websocketpp::config::asio_tls> >
{
private:
    bool require_client_certificate_flag;
    bool accept_selfsigned_certificates_flag;

    websocketpp::lib::shared_ptr<char[]> server_certificate;
    websocketpp::lib::asio::const_buffer server_certificate_cb;

    websocketpp::lib::shared_ptr<char[]> server_certificate_pk;
    websocketpp::lib::asio::const_buffer server_certificate_pk_cb;

    websocketpp::lib::shared_ptr<char[]> dh_data;
    websocketpp::lib::asio::const_buffer dh_data_cb;

    std::string ca_path;

    typedef websocketpp::lib::shared_ptr<websocketpp::lib::asio::ssl::context> context_ptr;

    /**
     * \brief Callback method that helps to setup the TLS configuration for the incoming connection.
     * \param hdl Connection handle. Not really used.
     */
    context_ptr on_tls_init(websocketpp::connection_hdl a_hdl)
    {
        namespace asiossl = websocketpp::lib::asio::ssl;

        //std::cout << "on_tls_init called with hdl: " << a_hdl.lock().get() << std::endl;

        context_ptr ctx = websocketpp::lib::make_shared<asiossl::context>(asiossl::context::sslv23);

        try {
            // Disable currently insecure SSLV2, SSLV3 and TLSv1
            // Tell that the server chooses the cipher
            ctx->set_options(asiossl::context::default_workarounds |
                                asiossl::context::no_sslv2 |
                                asiossl::context::no_sslv3 |
                                asiossl::context::no_tlsv1 |
                                asiossl::context::single_dh_use | 
                                SSL_OP_CIPHER_SERVER_PREFERENCE         // The server gets to choose the cipher
                                );

            if (require_client_certificate_flag) {
                // Demand a client certificate
                std::cout << "A client certificate will be required" << std::endl;
                ctx->set_verify_mode(asiossl::verify_peer | asiossl::verify_fail_if_no_peer_cert);
                // This is another dependency with boost
                ctx->set_verify_callback(boost::bind(&SecureWebSocketServerWrapper::verify_certificate, this, boost::placeholders::_1, boost::placeholders::_2));
                if (! ca_path.empty()) {
                    ctx->add_verify_path(ca_path.c_str());
                }
            } else {
                // Client certificate not required
                ctx->set_verify_mode(asiossl::verify_none);
            }

            // Set the server certificate
            ctx->use_certificate_chain(server_certificate_cb);
            ctx->use_private_key(server_certificate_pk_cb, websocketpp::lib::asio::ssl::context::file_format::pem);

            // Set the ciphers
            // Recomended list of ciphers and its order from
            // https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices

            std::string ciphers = 
                "ECDHE-ECDSA-AES256-GCM-SHA384" ":"
                "ECDHE-RSA-AES256-GCM-SHA384" ":"
                "ECDHE-ECDSA-AES128-GCM-SHA256" ":"
                "ECDHE-RSA-AES128-GCM-SHA256" ":"
                "ECDHE-ECDSA-AES256-SHA384" ":"
                "ECDHE-RSA-AES256-SHA384" ":"
                "ECDHE-ECDSA-AES128-SHA256" ":"
                "ECDHE-RSA-AES128-SHA256" ":"
                "DHE-RSA-AES256-GCM-SHA384" ":"
                "DHE-RSA-AES256-SHA256" ":"
                "DHE-RSA-AES128-GCM-SHA256" ":"
                "DHE-RSA-AES128-SHA256" ":"
                "ECDHE-ECDSA-AES256-SHA" ":"
                "ECDHE-RSA-AES256-SHA" ":"
                "ECDHE-ECDSA-AES128-SHA" ":"
                "ECDHE-RSA-AES128-SHA" ":"
                "DHE-RSA-AES256-SHA" ":"
                "DHE-RSA-AES128-SHA" ":"
                "AES256-GCM-SHA384" ":" // Added as a last resort for the Chrome browser in case the ECDHE ciphers don't work...
                "AES256-SHA";           //   "

            if (SSL_CTX_set_cipher_list(ctx->native_handle(), ciphers.c_str()) != 1) {
                std::cerr << "Error setting cipher list" << std::endl;
            }

            // Set the DH data, apparently required for the DH stuff to work. See also comments on the setup method
            ctx->use_tmp_dh(dh_data_cb);

            // And this seems to be needed by the ECDHE ciphers
            SSL_CTX_set_ecdh_auto(ctx->native_handle(), 1);

        } catch (std::exception& e) {
            std::cerr << "on_tls_init exception: " << e.what() << std::endl;
        }
        return ctx;
    }

public:
    SecureWebSocketServerWrapper() : require_client_certificate_flag(false), accept_selfsigned_certificates_flag(false)
    {
        // Register on_tls_init message handlers
        set_tls_init_handler(websocketpp::lib::bind(&SecureWebSocketServerWrapper::on_tls_init, this, websocketpp::lib::placeholders::_1));
    }

    virtual ~SecureWebSocketServerWrapper()
    {
        // Does nothing
    }

    bool verify_certificate(bool a_preverified, websocketpp::lib::asio::ssl::verify_context& a_ctx)
    {
        std::cout << "Verifying client certificate, preverification status: " << a_preverified << std::endl;

        X509_STORE_CTX *cts = a_ctx.native_handle();
        X509* cert = X509_STORE_CTX_get_current_cert(cts);
        if (cts->error != 0) {
            std::cerr << "CTX error: " << cts->error << std::endl;

            int32_t depth = X509_STORE_CTX_get_error_depth(cts);
            std::cerr << "CTX error depth: " << depth << std::endl;

            switch (cts->error)
            {
            case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
                std::cerr << "Error, X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT" << std::endl;
                break;
            case X509_V_ERR_CERT_NOT_YET_VALID:
            case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
                std::cerr << "Error, certificate not yet valid!!" << std::endl;
                break;
            case X509_V_ERR_CERT_HAS_EXPIRED:
            case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
                std::cerr << "Error, certificate expired.." << std::endl;
                break;
            case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
            case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
                if (accept_selfsigned_certificates_flag) {
                    a_preverified = true;
                } else {
                    std::cerr << "Error, self signed certificates are not accepted" << std::endl;
                }
                break;
            default:
                break;
            }
        }

        // Get the certificate subject:
        int8_t subject_name[256];
        const int32_t name_length = sizeof(subject_name);
        X509_NAME_oneline(X509_get_subject_name(cert), reinterpret_cast<char*>(subject_name), name_length);
        std::cout << "Certificate subject: " << subject_name << std::endl;
            
        // Get the issuer's subject:
        X509* issuer = X509_STORE_CTX_get0_current_issuer(cts);
        if (issuer != NULL) {
            X509_NAME *xn = X509_get_issuer_name(issuer);

            X509_NAME_oneline(X509_get_subject_name(issuer), reinterpret_cast<char*>(subject_name), name_length);
            std::cout << "Certificate issuer subject: " << subject_name << std::endl;
        }

        // Explore the certificate chain:
        {
            STACK_OF(X509) *ca = X509_STORE_CTX_get_chain(cts);
            if (ca != NULL) {
                unsigned int n = sk_X509_num(ca);

                for (unsigned int i = 0; i < n; i++) {
                    std::cout << "--------------------------------" << std::endl;
                    std::cout << "#" << (i+1) << std::endl;

                    X509* ccc = sk_X509_value(ca, i);
                    char *subj = X509_NAME_oneline(X509_get_subject_name(ccc), NULL, 0);
                    char *issuer = X509_NAME_oneline(X509_get_issuer_name(ccc), NULL, 0);
                    std::cout << "Subject: " << subj << std::endl;
                    std::cout << "Issuer : " << issuer << std::endl;

                    /*{
                        // Get the whole certificate text
                        BIO* cert_bio = BIO_new(BIO_s_mem());
                        int result = PEM_write_bio_X509_AUX(cert_bio, ccc);
                        if (!result) {
                            ERR_print_errors_fp(stderr);
                        } else {
                            char* buffer;
                            unsigned int length = (unsigned int)BIO_get_mem_data(cert_bio, &buffer);
                            std::string certificate_text(buffer, length);
                            std::cout << certificate_text << std::endl;
                            BIO_free(cert_bio);
                        }
                    }*/
                }
                std::cout << "--------------------------------" << std::endl;
                //sk_X509_pop_free(ca, X509_free);
            }
        }

        // Add here some additional validations if required...

        return a_preverified;
    }

    /**
     * \param a_endpoint The TCP endpoint, already set with host or port.
     * \param a_pfxServerCertificatePath Path to the PFX file containing a valid certificate and its private key, both in PEM format.
     * \param a_pfxPassword Password to open the PFX file. This is required since PFX files are encrypted.
     * \param a_dhFilePath Path to the "DH" file with some Diffie-Hellman stuff. This file is required when we use DH ciphers
     */
    void setup(const websocketpp::lib::asio::ip::tcp::endpoint& a_endpoint, const std::string& a_pfxServerCertificatePath, const std::string& a_pfxPassword, const std::string& a_dhFilePath)
    {
        WebSocketServerWrapper_Base< websocketpp::server<websocketpp::config::asio_tls> >::setup(a_endpoint);

        // Read the server certificate
        {
            PEMExtractor extractor;
            int result = extractor.process_p12_file(a_pfxServerCertificatePath, a_pfxPassword);
            if (result == 0) {
                char* buffer;
                unsigned int length;
        
                length = extractor.get_certificate(&buffer);
                server_certificate = websocketpp::lib::make_shared<char[]>(length);
                memcpy(server_certificate.get(), buffer, length);
                server_certificate_cb = websocketpp::lib::asio::const_buffer(server_certificate.get(), length);

                length = extractor.get_private_key(&buffer);
                server_certificate_pk = websocketpp::lib::make_shared<char[]>(length);
                memcpy(server_certificate_pk.get(), buffer, length);
                server_certificate_pk_cb = websocketpp::lib::asio::const_buffer(server_certificate_pk.get(), length);
            } else {
                std::cerr << "Error processing pfx file: " << a_pfxServerCertificatePath << std::endl;
                throw new std::invalid_argument (a_pfxServerCertificatePath);
            }
            extractor.reset();
        }

        // Read the DH file
        // This is required since we are going to propose using DH ciphers
        // See https://wiki.openssl.org/index.php/Diffie-Hellman_parameters
        // Better to generate the file offline, it takes a long time...
        // Example method of generating this file:
        // `openssl dhparam -out dh.pem 2048`
        // Mozilla Intermediate suggests 1024 as the minimum size to use
        // Mozilla Modern suggests 2048 as the minimum size to use.
        if (! a_dhFilePath.empty()){
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
     * \brief Call this method the tell the server to require a valid client certificate.
     * \paramc a_path The path to our trusted certifying authorities (CA). OpenSSL will trust any certificates in this folder as CA. See the notes for more details.
     * \param a_accept_selfsigned_certificates Set to true to accept self-signed certificates by the client.
     */
    void require_client_certificate(const std::string& a_ca_path, bool a_accept_selfsigned_certificates = false)
    {
        ca_path = a_ca_path;
        require_client_certificate_flag = true;
        accept_selfsigned_certificates_flag = a_accept_selfsigned_certificates;
    }

    /**
     * \brief Says true, this is a secure websocket server.
     */
    // IServer
    virtual bool is_secure() const
    {
        return true;
    }
};

#endif // SERVER_HPP__E586C29E14AB4D2F9621DCC4AF574035
