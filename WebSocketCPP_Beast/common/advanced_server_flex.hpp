
#ifndef ADVANCED_SERVER_FLEX_HPP__64F22BDF4707468A831AB64826D4A71E
#define ADVANCED_SERVER_FLEX_HPP__64F22BDF4707468A831AB64826D4A71E

//
// Copyright (c) 2016-2017 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/boostorg/beast
//

//------------------------------------------------------------------------------
//
// This is the original Advanced server, flex (plain + SSL) example from Beast with some
// modifications that allows "handlers" to take specific action when data is received.
//
//------------------------------------------------------------------------------



#include "detect_ssl.hpp"
#include "ssl_stream.hpp"

#include <PEMExtractor.hpp>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/config.hpp>
#include <boost/thread.hpp>
#include <algorithm>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <fstream>

using tcp = boost::asio::ip::tcp;               // from <boost/asio/ip/tcp.hpp>
namespace ssl = boost::asio::ssl;               // from <boost/asio/ssl.hpp>
namespace http = boost::beast::http;            // from <boost/beast/http.hpp>
namespace websocket = boost::beast::websocket;  // from <boost/beast/websocket.hpp>


//-------------------------------------------------
std::ostream& operator<<(std::ostream& os,
    const std::chrono::time_point<std::chrono::steady_clock, std::chrono::steady_clock::duration>& timep)
{
    os << timep.time_since_epoch().count();
    return os;
}

std::ostream& operator<<(std::ostream& os,
    const std::chrono::duration<long long, std::nano>& duration)
{
    os << duration.count();
    return os;
}
//-------------------------------------------------


//------------------------------------------------------------------------------

// Report a failure
void
fail(boost::system::error_code ec, char const* what)
{
    std::cerr << what << ": " << ec.message() << "\n";
}

//------------------------------------------------------------------------------

// Calls the handler when some data is read, a HTTP request is received and when
// the connection is open and closed, so the handler can decide what to do.
// This uses the Curiously Recurring Template Pattern so that
// the same code works with both SSL streams and regular sockets.
template<class Derived, class Handler>
class websocket_session
{
private:
    // Access the derived class, this is part of
    // the Curiously Recurring Template Pattern idiom.
    Derived&
    derived()
    {
        return static_cast<Derived&>(*this);
    }

    boost::beast::multi_buffer buffer_;

    Handler& handler_;

    enum ping_state { ping_initial, ping_requested };

    ping_state ping_state_ = ping_initial;

protected:
    boost::asio::strand<
        boost::asio::io_context::executor_type> strand_;
    boost::asio::steady_timer timer_;
    int timeout_seconds_;

    void wait_on_timer()
    {
        if (timeout_seconds_ > 0) {
            // Set the timer
            timer_.expires_after(std::chrono::seconds(timeout_seconds_));

            std::cout << "websocket_session::Wait on the timer " << timeout_seconds_ << " s" << std::endl;

            // Wait on the timer
            timer_.async_wait(
                boost::asio::bind_executor(
                    strand_,
                    std::bind(
                        &websocket_session::on_timer,
                        derived().shared_from_this(),
                        std::placeholders::_1)));
        }
    }

public:
    // Construct the session
    explicit
    websocket_session(boost::asio::io_context& ioc, Handler& handler, int timeout_seconds)
        : strand_(ioc.get_executor())
        , timer_(ioc)
        , handler_(handler)
        , timeout_seconds_(timeout_seconds)
    {
        std::cout << "    websocket_base::websocket_session" << std::endl;
        handler_.on_created(this);
    }

    ~websocket_session()
    {
        std::cout << "    websocket_base::~websocket_session" << std::endl;
        handler_.on_destroyed(this);
    }

    // Start the asynchronous operation
    template<class Body, class Allocator>
    void do_accept(http::request<Body, http::basic_fields<Allocator> > req)
    {
        wait_on_timer();

        // Accept the websocket handshake
        derived().ws().async_accept(
            req,
            boost::asio::bind_executor(
                strand_,
                std::bind(
                    &websocket_session::on_accept,
                    derived().shared_from_this(),
                    std::placeholders::_1)));
    }

    void on_accept(boost::system::error_code ec)
    {
        std::cout << "websocket_session::on_accept" << std::endl;

        // Happens when the timer closes the socket
        if (ec == boost::asio::error::operation_aborted)
            return;

        if (ec)
            return fail(ec, "accept");

        // Read a message
        do_read();
    }


    // Called when the timer expires.
    void on_timer(boost::system::error_code ec)
    {
        if (ec != boost::asio::error::operation_aborted)
        {
            std::cout << "websocket_session::on_timer " << (timer_.expiry() - std::chrono::steady_clock::now()) << std::endl;

            // Timer was not cancelled, take necessary action.
            if (ec) {
                fail(ec, "timer");
            } else {
                // If this is the first time the timer expired,
                // send a ping to see if the other end is there.
                if (derived().ws().is_open() && ping_state_ == ping_initial) {
                    // Note that we are sending a ping
                    ping_state_ = ping_requested;

                    wait_on_timer();

                    std::cout << "Calling ping ..." << std::endl;

                    // Now send the ping
                    derived().ws().async_ping({},
                        boost::asio::bind_executor(
                            strand_,
                            std::bind(
                                &websocket_session::on_ping,
                                derived().shared_from_this(),
                                std::placeholders::_1)));
                } else {
                    // The timer expired while trying to handshake,
                    // or we sent a ping and it never completed or
                    // we never got back a control frame, so close.

                    derived().do_timeout();
                }
            }
        }
    }

    // Called after a ping is sent.
    void on_ping(boost::system::error_code ec)
    {
        // Happens when the timer closes the socket
        if (ec == boost::asio::error::operation_aborted) {
            return;
        }

        if (ec) {
            return fail(ec, "ping");
        }

        // Note that the ping was sent.
        std::cout << "Pong received!" << std::endl;
        ping_state_ = ping_initial;
    }

    void on_control_callback(websocket::frame_type kind, boost::beast::string_view payload)
    {
        boost::ignore_unused(kind, payload);

        // Note that there is activity
        activity();
    }

    void do_read()
    {
        // Clear the buffer
        buffer_.consume(buffer_.size());

        wait_on_timer();

        // Read a message into our buffer
        derived().ws().async_read(
            buffer_,
            boost::asio::bind_executor(
                strand_,
                std::bind(
                    &websocket_session::on_read,
                    derived().shared_from_this(),
                    std::placeholders::_1,
                    std::placeholders::_2)));
    }

    void on_read(boost::system::error_code ec, std::size_t bytes_transferred)
    {
        timer_.cancel();

        boost::ignore_unused(bytes_transferred);

        // Happens when the timer closes the socket
        if (ec == boost::asio::error::operation_aborted) {
            return;
        }

        // This indicates that the websocket_session was closed
        if (ec == websocket::error::closed) {
            return;
        }

        if (ec == boost::asio::error::basic_errors::connection_reset) {
            derived().do_shutdown();
            return;
        }

        std::cout << "websocket_session::on_read " << ec << std::endl;

        if (ec) {
            fail(ec, "read");
        }

        handler_.on_read(*this, buffer_);

        // Clear the buffer
        buffer_.consume(buffer_.size());

        // Do another read
        do_read();
    }

    void on_write(std::shared_ptr<std::string> s, boost::system::error_code ec, std::size_t bytes_transferred)
    {
        std::cout << "websocket_session::on_write " << *s << std::endl;

        boost::ignore_unused(bytes_transferred);

        // Happens when the timer closes the socket
        if (ec == boost::asio::error::operation_aborted) {
            return;
        }

        if (ec) {
            return fail(ec, "write");
        }
    }

    //template <class ConstBufferSequence>
    //void async_write_text(ConstBufferSequence const& bs)
    void async_write_text(std::string const& messageData)
    {
        async_write_text(std::make_shared<std::string>(messageData));
    }

    //template <class ConstBufferSequence>
    //void async_write_text(ConstBufferSequence const& bs)
    void async_write_text(char const* messageData, size_t length)
    {
        async_write_text(std::make_shared<std::string>(messageData, length));
    }

    void async_write_text(std::shared_ptr<std::string>& messageData)
    {
        std::cout << "            async_write: " << *messageData << std::endl;

        derived().ws().text(true);

        derived().ws().async_write(
            boost::asio::buffer(*messageData),
            boost::asio::bind_executor(
                strand_,
                std::bind(
                    &websocket_session::on_write,
                    derived().shared_from_this(),
                    messageData,
                    std::placeholders::_1,
                    std::placeholders::_2)));
    }

};

// Handles a plain WebSocket connection
template<class Handler>
class plain_websocket_session
    : public websocket_session<plain_websocket_session<Handler>, Handler>
    , public std::enable_shared_from_this<plain_websocket_session<Handler> >
{
private:
    websocket::stream<tcp::socket> ws_;
    bool closing_ = false;

public:
    // Create the session
    explicit
    plain_websocket_session(tcp::socket socket, Handler& handler, int timeout_seconds)
        : websocket_session<plain_websocket_session<Handler>, Handler>(
            socket.get_executor().context(), handler, timeout_seconds)
        , ws_(std::move(socket))
    {
    }

    // Called by the base class
    websocket::stream<tcp::socket>& ws()
    {
        return ws_;
    }

    // Start the asynchronous operation
    template<class Body, class Allocator>
    void run(http::request<Body, http::basic_fields<Allocator> > req)
    {
        // Accept the WebSocket upgrade request
        do_accept(std::move(req));
    }

    void do_shutdown()
    {
        // This is so the close can have a timeout
        if (closing_) {
            return;
        }
        closing_ = true;

        std::cout << "Closing the plain_websocket_session::do_shutdown" << std::endl;

        // Close the WebSocket Connection
        ws_.async_close(
            websocket::close_code::normal,
            boost::asio::bind_executor(
                strand_,
                std::bind(
                    &plain_websocket_session::on_close,
                    shared_from_this(),
                    std::placeholders::_1)));
    }

    void on_close(boost::system::error_code ec)
    {
        // Happens when the shutdown times out
        if (ec == boost::asio::error::operation_aborted) {
            return;
        }

        if (ec) {
            return fail(ec, "shutdown");
        }

        ws_.next_layer().shutdown(tcp::socket::shutdown_both, ec);
    }

    void do_timeout()
    {
        std::cout << "plain_websocket_session::do_timeout" << std::endl;

        do_shutdown();
    }
};

// Handles an SSL WebSocket connection
template <class Handler>
class ssl_websocket_session
    : public websocket_session<ssl_websocket_session<Handler>, Handler>
    , public std::enable_shared_from_this<ssl_websocket_session<Handler> >
{
private:
    websocket::stream<ssl_stream<tcp::socket> > ws_;
    boost::asio::strand<
        boost::asio::io_context::executor_type> strand_;
    bool closing_ = false;

public:
    // Create the http_session
    explicit
    ssl_websocket_session(ssl_stream<tcp::socket> stream, Handler& handler, int timeout_seconds)
        : websocket_session<ssl_websocket_session<Handler>, Handler>(
            stream.get_executor().context(), handler, timeout_seconds)
        , ws_(std::move(stream))
        , strand_(ws_.get_executor())
    {
    }

    // Called by the base class
    websocket::stream<ssl_stream<tcp::socket> >& ws()
    {
        return ws_;
    }

    // Start the asynchronous operation
    template<class Body, class Allocator>
    void run(http::request<Body, http::basic_fields<Allocator> > req)
    {
        // Accept the WebSocket upgrade request
        do_accept(std::move(req));
    }

    void do_shutdown()
    {
        // This is so the close can have a timeout
        if (closing_) {
            return;
        }
        closing_ = true;

        std::cout << "Closing the ssl_websocket_session::do_shutdown" << std::endl;

        // Perform the SSL shutdown
        ws_.next_layer().async_shutdown(
            boost::asio::bind_executor(
                strand_,
                std::bind(
                    &ssl_websocket_session::on_shutdown,
                    shared_from_this(),
                    std::placeholders::_1)));
    }

    void on_shutdown(boost::system::error_code ec)
    {
        // Happens when the shutdown times out
        if (ec == boost::asio::error::operation_aborted) {
            return;
        }

        if (ec) {
            return fail(ec, "shutdown");
        }

        // At this point the connection is closed gracefully
    }

    void do_timeout()
    {
        std::cout << "ssl_websocket_session::do_timeout" << std::endl;

        do_shutdown();
    }
};

template<class Body, class Allocator, class Handler>
void
make_websocket_session(
    tcp::socket socket,
    http::request<Body, http::basic_fields<Allocator> > req,
    Handler& handler,
    int timeout_seconds)
{
    std::make_shared<plain_websocket_session<Handler> >(
        std::move(socket), handler, timeout_seconds)->run(std::move(req));
}

template<class Body, class Allocator, class Handler>
void
make_websocket_session(
    ssl_stream<tcp::socket> stream,
    http::request<Body, http::basic_fields<Allocator> > req,
    Handler& handler,
    int timeout_seconds)
{
    std::make_shared<ssl_websocket_session<Handler> >(
        std::move(stream), handler, timeout_seconds)->run(std::move(req));
}

//------------------------------------------------------------------------------

// Handles an HTTP server connection.
// This uses the Curiously Recurring Template Pattern so that
// the same code works with both SSL streams and regular sockets.
template<class Derived, class Handler>
class http_session
{
private:
    // Access the derived class, this is part of
    // the Curiously Recurring Template Pattern idiom.
    Derived&
    derived()
    {
        return static_cast<Derived&>(*this);
    }

    // This queue is used for HTTP pipelining.
    class queue
    {
        enum
        {
            // Maximum number of responses we will queue
            limit = 8
        };

        // The type-erased, saved work item
        struct work
        {
            virtual ~work() = default;
            virtual void operator()() = 0;
        };

        http_session<Derived, Handler>& self_;
        std::vector<std::unique_ptr<work> > items_;

    public:
        explicit
        queue(http_session<Derived, Handler>& self)
            : self_(self)
        {
            static_assert(limit > 0, "queue limit must be positive");
            items_.reserve(limit);
        }

        // Returns `true` if we have reached the queue limit
        bool
        is_full() const
        {
            return items_.size() >= limit;
        }

        // Called when a message finishes sending
        // Returns `true` if the caller should initiate a read
        bool
        on_write()
        {
            BOOST_ASSERT(! items_.empty());
            auto const was_full = is_full();
            items_.erase(items_.begin());
            if(! items_.empty())
                (*items_.front())();
            return was_full;
        }

        // Called by the HTTP handler to send a response.
        template<bool isRequest, class Body, class Fields>
        void
        operator()(http::message<isRequest, Body, Fields>&& msg)
        {
            // This holds a work item
            struct work_impl : work
            {
                http_session<Derived, Handler>& self_;
                http::message<isRequest, Body, Fields> msg_;

                work_impl(
                    http_session<Derived, Handler>& self,
                    http::message<isRequest, Body, Fields>&& msg)
                    : self_(self)
                    , msg_(std::move(msg))
                {
                }

                void
                operator()()
                {
                    http::async_write(
                        self_.derived().stream(),
                        msg_,
                        boost::asio::bind_executor(
                            self_.strand_,
                            std::bind(
                                &http_session<Derived, Handler>::on_write,
                                self_.derived().shared_from_this(),
                                std::placeholders::_1,
                                msg_.need_eof())));
                }
            };

            // Allocate and store the work
            items_.emplace_back(new work_impl(self_, std::move(msg)));

            // If there was no previous work, start this one
            if(items_.size() == 1)
                (*items_.front())();
        }
    };

    http::request<http::string_body> req_;
    queue queue_;

protected:
    boost::asio::steady_timer timer_;
    boost::asio::strand<boost::asio::io_context::executor_type> strand_;
    boost::beast::flat_buffer buffer_;

    Handler& handler_;

    int timeout_seconds_;

    void wait_on_timer()
    {
        if (timeout_seconds_ > 0) {
            std::cout << "http_session::on_timer " << (timer_.expiry() - std::chrono::steady_clock::now()) << std::endl;

            // Set the timer
            timer_.expires_after(std::chrono::seconds(timeout_seconds_));

            // Wait on the timer
            timer_.async_wait(
                boost::asio::bind_executor(
                    strand_,
                    std::bind(
                        &http_session<Derived, Handler>::on_timer,
                        derived().shared_from_this(),
                        std::placeholders::_1)));
        }
    }

public:
    // Construct the session
    http_session<Derived, Handler>(
        boost::asio::io_context& ioc,
        boost::beast::flat_buffer buffer,
        Handler& handler,
        int timeout_seconds) :
        queue_(*this)
        , timer_(ioc)
        , strand_(ioc.get_executor())
        , buffer_(std::move(buffer))
        , handler_(handler)
        , timeout_seconds_(timeout_seconds)
    {
        // Does nothing
    }

    void
    do_read()
    {
        wait_on_timer();

        // Read a request
        http::async_read(
            derived().stream(),
            buffer_,
            req_,
            boost::asio::bind_executor(
                strand_,
                std::bind(
                    &http_session<Derived, Handler>::on_read,
                    derived().shared_from_this(),
                    std::placeholders::_1)));
    }

    // Called when the timer expires.
    void
    on_timer(boost::system::error_code ec)
    {
        if (ec != boost::asio::error::operation_aborted)
        {
            std::cout << "http_session::on_timer" << std::endl;

            // Timer was not cancelled, take necessary action.
            if (ec) {
                fail(ec, "timer");
            }
            else {
                derived().do_timeout(ec);
            }
        }
    }

    void
    on_read(boost::system::error_code ec)
    {
        // Happens when the timer closes the socket
        if (ec == boost::asio::error::operation_aborted) {
            return;
        }

        // This means they closed the connection
        if (ec == http::error::end_of_stream) {
            return derived().do_eof();
        }

        if (ec) {
            return fail(ec, "read");
        }

        timer_.cancel();

        // See if it is a WebSocket Upgrade
        if (websocket::is_upgrade(req_)) {
            // Transfer the stream to a new WebSocket session
            make_websocket_session(
                derived().release_stream(),
                std::move(req_),
                handler_,
                timeout_seconds_);
        } else {
            // Send the response
            handler_.handle_request(std::move(req_), queue_);

            // If we aren't at the queue limit, try to pipeline another request
            if (!queue_.is_full()) {
                do_read();
            }
        }
    }

    void
    on_write(boost::system::error_code ec, bool close)
    {
        std::cout << "http_session::on_write" << std::endl;

        // Happens when the timer closes the socket
        if (ec == boost::asio::error::operation_aborted) {
            return;
        }

        if (ec) {
            return fail(ec, "write");
        }

        if (close) {
            // This means we should close the connection, usually because
            // the response indicated the "Connection: close" semantic.
            return derived().do_eof();
        } else if (queue_.on_write()) {
            // Inform the queue that a write completed
            // Read another request
            do_read();
        }
    }
};

// Handles a plain HTTP connection
template <class Handler>
class plain_http_session
    : public http_session<plain_http_session<Handler>, Handler>
    , public std::enable_shared_from_this<plain_http_session<Handler> >
{
private:
    tcp::socket socket_;
    boost::asio::strand<
        boost::asio::io_context::executor_type> strand_;

public:
    // Create the http_session
    plain_http_session<Handler> (
        tcp::socket socket,
        boost::beast::flat_buffer buffer,
        Handler& handler,
        int timeout_seconds)
        : http_session<plain_http_session<Handler>, Handler >(
            socket.get_executor().context(),
            std::move(buffer),
            handler,
            timeout_seconds)
        , socket_(std::move(socket))
        , strand_(socket_.get_executor())
    {
        std::cout << "plain_http_session::plain_http_session" << std::endl;

        handler_.on_created(this);
    }

    ~plain_http_session<Handler> ()
    {
        std::cout << "plain_http_session::~plain_http_session" << std::endl;

        handler_.on_destroyed(this);
    }


    // Called by the base class
    tcp::socket&
    stream()
    {
        return socket_;
    }

    // Called by the base class
    tcp::socket
    release_stream()
    {
        return std::move(socket_);
    }

    // Start the asynchronous operation
    void
    run()
    {
        do_read();
    }

    void
    do_eof()
    {
        // Send a TCP shutdown
        boost::system::error_code ec;
        socket_.shutdown(tcp::socket::shutdown_send, ec);

        // At this point the connection is closed gracefully
    }

    void
    do_timeout(boost::system::error_code ec)
    {
        std::cout << "plain_http_session::do_timeout Closing the socket" << std::endl;

        // Closing the socket cancels all outstanding operations. They
        // will complete with boost::asio::error::operation_aborted
        socket_.shutdown(tcp::socket::shutdown_both, ec);
        socket_.close(ec);
    }
};

// Handles an SSL HTTP connection
template <class Handler>
class ssl_http_session
    : public http_session<ssl_http_session<Handler>, Handler>
    , public std::enable_shared_from_this<ssl_http_session<Handler> >
{
private:
    ssl_stream<tcp::socket> stream_;
    boost::asio::strand<
        boost::asio::io_context::executor_type> strand_;
    bool eof_ = false;

public:
    // Create the http_session
    ssl_http_session(
        tcp::socket socket,
        ssl::context& ctx,
        boost::beast::flat_buffer buffer,
        Handler& handler,
        int timeout_seconds)
        : http_session<ssl_http_session<Handler>, Handler>(
            socket.get_executor().context(),
            std::move(buffer),
            handler,
            timeout_seconds)
        , stream_(std::move(socket), ctx)
        , strand_(stream_.get_executor())
    {
        std::cout << "ssl_http_session::ssl_http_session" << std::endl;

        handler_.on_created(this);
    }

    ~ssl_http_session<Handler>()
    {
        std::cout << "ssl_http_session::~ssl_http_session" << std::endl;

        handler_.on_destroyed(this);
    }

    // Called by the base class
    ssl_stream<tcp::socket>&
    stream()
    {
        return stream_;
    }

    // Called by the base class
    ssl_stream<tcp::socket>
    release_stream()
    {
        return std::move(stream_);
    }

    // Start the asynchronous operation
    void
    run()
    {
        do_handshake();
    }

    void
    do_handshake()
    {
        wait_on_timer();

        // Perform the SSL handshake
        // Note, this is the buffered version of the handshake.
        stream_.async_handshake(
            ssl::stream_base::server,
            buffer_.data(),
            boost::asio::bind_executor(
                strand_,
                std::bind(
                    &ssl_http_session::on_handshake,
                    shared_from_this(),
                    std::placeholders::_1,
                    std::placeholders::_2)));
    }

    void
    on_handshake(
        boost::system::error_code ec,
        std::size_t bytes_used)
    {
        // Happens when the handshake times out
        if (ec == boost::asio::error::operation_aborted) {
            return;
        }

        if (ec) {
            return fail(ec, "handshake");
        }

        // Consume the portion of the buffer used by the handshake
        buffer_.consume(bytes_used);

        do_read();
    }

    void
    do_eof()
    {
        // If this is true it means we timed out performing the shutdown
        if (eof_) {
            return;
        }

        eof_ = true;

        wait_on_timer();

        // Perform the SSL shutdown
        stream_.async_shutdown(
            boost::asio::bind_executor(
                strand_,
                std::bind(
                    &ssl_http_session::on_shutdown,
                    shared_from_this(),
                    std::placeholders::_1)));
    }

    void
    on_shutdown(boost::system::error_code ec)
    {
        // Happens when the shutdown times out
        if (ec == boost::asio::error::operation_aborted) {
            return;
        }

        if (ec) {
            return fail(ec, "shutdown");
        }

        // At this point the connection is closed gracefully
    }

    void
    do_timeout(boost::system::error_code ec)
    {
        std::cout << "ssl_http_session::do_timeout" << std::endl;

        do_eof();
    }
};

//------------------------------------------------------------------------------

// Detects SSL handshakes
template <class Handler>
class session_detector : public std::enable_shared_from_this<session_detector<Handler> >
{
private:
    tcp::socket socket_;
    ssl::context& ctx_;
    boost::asio::strand<
        boost::asio::io_context::executor_type> strand_;
    boost::beast::flat_buffer buffer_;
    Handler& handler_;
    int timeout_seconds_;

public:
    explicit
    session_detector<Handler> (
        tcp::socket socket,
        ssl::context& ctx,
        Handler& handler,
        int timeout_seconds)
        : socket_(std::move(socket))
        , ctx_(ctx)
        , strand_(socket_.get_executor())
        , handler_(handler)
        , timeout_seconds_(timeout_seconds)
    {
    }

    // Launch the detector
    void
    run()
    {
        async_detect_ssl(
            socket_,
            buffer_,
            boost::asio::bind_executor(
                strand_,
                std::bind(
                    &session_detector<Handler>::on_detect,
                    shared_from_this(),
                    std::placeholders::_1,
                    std::placeholders::_2)));

    }

    void
    on_detect(boost::system::error_code ec, boost::tribool result)
    {
        if (ec) {
            return fail(ec, "detect");
        }

        if (result) {
            // Launch SSL session
            std::make_shared<ssl_http_session<Handler> >(
                std::move(socket_),
                ctx_,
                std::move(buffer_),
                handler_,
                timeout_seconds_)->run();
        } else {
            // Launch plain session
            std::make_shared<plain_http_session<Handler> >(
                std::move(socket_),
                std::move(buffer_),
                handler_,
                timeout_seconds_)->run();
        }
    }
};

// Accepts incoming connections and launches the sessions
template <class Handler>
class listener : public std::enable_shared_from_this<listener<Handler> >
{
private:
    // The SSL context is required, and holds certificates
    ssl::context ctx_{ ssl::context::sslv23 };
    tcp::acceptor acceptor_;
    tcp::socket socket_;
    Handler& handler_;
    int timeout_seconds_;

    bool accept_selfsigned_certificates_flag_;

    /**
     * \brief Verifies the client certificate, returning true when it finds it valid.
     * This implementation comes with the standard checks but it could be extended on
     * any way.
     */
    bool verify_certificate(bool a_preverified, boost::asio::ssl::verify_context& a_ctx)
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
                // A self-signed certificate by the client. Validate only if we are configured to do so
                if (accept_selfsigned_certificates_flag_) {
                    a_preverified = true;
                }
                else {
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
                    std::cout << "#" << (i + 1) << std::endl;

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

public:
    listener<Handler>(
        boost::asio::io_context& ioc,
        tcp::endpoint endpoint,
        Handler& handler,
        int timeout_seconds)
        : acceptor_(ioc)
        , socket_(ioc)
        , handler_(handler)
        , timeout_seconds_(timeout_seconds)
    {
        boost::system::error_code ec;

        // Open the acceptor
        acceptor_.open(endpoint.protocol(), ec);
        if (ec) {
            fail(ec, "open");
            return;
        }

        // Allow address reuse
        acceptor_.set_option(boost::asio::socket_base::reuse_address(true), ec);
        if (ec) {
            fail(ec, "set_option");
            return;
        }

        // Bind to the server address
        acceptor_.bind(endpoint, ec);
        if (ec) {
            fail(ec, "bind");
            return;
        }

        // Start listening for connections
        acceptor_.listen(
            boost::asio::socket_base::max_listen_connections, ec);
        if (ec) {
            fail(ec, "listen");
            return;
        }
    }

    // Start accepting incoming connections
    void run()
    {
        if (!acceptor_.is_open()) {
            return;
        }
        do_accept();
    }

    void do_accept()
    {
        acceptor_.async_accept(
            socket_,
            std::bind(
                &listener::on_accept,
                shared_from_this(),
                std::placeholders::_1));
    }

    void on_accept(boost::system::error_code ec)
    {
        if (ec) {
            fail(ec, "accept");
        } else {
            // Create the detector http_session and run it
            std::make_shared<session_detector<Handler> >(
                std::move(socket_),
                ctx_,
                handler_,
                timeout_seconds_)->run();
        }

        // Accept another connection
        do_accept();
    }

    /**
     * \brief Safe settings for the TLS setup
     * \param a_ca_path Path to the directory where we keep our trusted authority certificates
     * \param a_pfxServerCertificatePath Path the the file with the server certificate, in PFX format
     * \param a_pfxPassword Password to the PFX server certificate.
     * \param a_dhFilePath Path to a file with some Diffie-Hellman nonsense, see below.
     * \param a_require_client_certificate_flag Pass true when you want to request a valid client certificate from the client.
     * \param a_accept_selfsigned_certificates_flag Pass true to accept self-signed certificates from the client (only makes sense
     * when a_require_client_certificate_flag is also true
     */
    void setup_tls(std::string const& a_ca_path, std::string const& a_pfxServerCertificatePath, std::string const& a_pfxPassword,
                   std::string const& a_dhFilePath, bool a_require_client_certificate_flag, bool a_accept_selfsigned_certificates_flag)
    {
        accept_selfsigned_certificates_flag_ = a_accept_selfsigned_certificates_flag;

        // Read the server certificate
        {
            PEMExtractor extractor;
            int result = extractor.process_p12_file(a_pfxServerCertificatePath, a_pfxPassword);
            if (result == 0) {
                char* buffer;
                unsigned int length;

                length = extractor.get_certificate(&buffer);
                boost::shared_array<char> server_certificate = boost::shared_array<char>(new char[length]);
                memcpy(server_certificate.get(), buffer, length);
                boost::asio::const_buffer server_certificate_cb = boost::asio::const_buffer(server_certificate.get(), length);

                length = extractor.get_private_key(&buffer);
                boost::shared_array<char> server_certificate_pk = boost::shared_array<char>(new char[length]);
                memcpy(server_certificate_pk.get(), buffer, length);
                boost::asio::const_buffer server_certificate_pk_cb = boost::asio::const_buffer(server_certificate_pk.get(), length);

                // Set the server certificate
                ctx_.use_certificate_chain(server_certificate_cb);
                ctx_.use_private_key(server_certificate_pk_cb, boost::asio::ssl::context::file_format::pem);
            }
            else {
                std::cerr << "Error processing pfx file: " << a_pfxServerCertificatePath << std::endl;
                throw new std::invalid_argument(a_pfxServerCertificatePath);
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
        if (!a_dhFilePath.empty()) {
            // use ios::ate to get positioned at the end of the file, so tellg will come up with the length of the file:
            std::ifstream in(a_dhFilePath, std::ios::in | std::ios::binary | std::ios::ate);
            if (!in.is_open()) {
                std::cerr << "Error opening file: " << a_dhFilePath << std::endl;
                throw new std::invalid_argument(a_dhFilePath);
            }

            unsigned int length = (unsigned int)in.tellg();

            boost::shared_array<char> dh_data = boost::shared_array<char>(new char[length]);
            in.seekg(0, std::ios::beg);
            in.read(dh_data.get(), length);
            in.close();

            boost::asio::const_buffer dh_data_cb = boost::asio::const_buffer(dh_data.get(), length);

            // Set the DH data, apparently required for the DH stuff to work. See also comments on the setup method
            ctx_.use_tmp_dh(dh_data_cb);
        }

        // Disable currently insecure SSLV2, SSLV3 and TLSv1
        // Tell that the server chooses the cipher
        ctx_.set_options(boost::asio::ssl::context::default_workarounds |
            boost::asio::ssl::context::no_sslv2 |
            boost::asio::ssl::context::no_sslv3 |
            boost::asio::ssl::context::no_tlsv1 |
            boost::asio::ssl::context::single_dh_use |
            SSL_OP_CIPHER_SERVER_PREFERENCE         // The server gets to choose the cipher
        );

        if (a_require_client_certificate_flag) {
            // Demand a client certificate
            std::cout << "A client certificate will be required" << std::endl;
            ctx_.set_verify_mode(boost::asio::ssl::verify_peer | boost::asio::ssl::verify_fail_if_no_peer_cert);
            // This is another dependency with boost
            ctx_.set_verify_callback(
                std::bind(
                    &listener::verify_certificate,
                    this,
                    std::placeholders::_1,
                    std::placeholders::_2));
            if (!a_ca_path.empty()) {
                ctx_.add_verify_path(a_ca_path.c_str());
            }
        }
        else {
            // Client certificate not required
            ctx_.set_verify_mode(boost::asio::ssl::verify_none);
        }

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

        if (SSL_CTX_set_cipher_list(ctx_.native_handle(), ciphers.c_str()) != 1) {
            std::cerr << "Error setting cipher list" << std::endl;
        }

        // And this seems to be needed by the ECDHE ciphers
        SSL_CTX_set_ecdh_auto(ctx_.native_handle(), 1);
    }
};

#endif // ADVANCED_SERVER_FLEX_HPP__64F22BDF4707468A831AB64826D4A71E
