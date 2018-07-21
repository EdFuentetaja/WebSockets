
#ifndef BROADCASTER_HANDLER_HPP__18253FB6D0264813B58325300D467A9F
#define BROADCASTER_HANDLER_HPP__18253FB6D0264813B58325300D467A9F

#include "advanced_server_flex.hpp"

template <class Handler> class plain_websocket_session;
template <class Handler> class ssl_websocket_session;
template <class Derived, class Handler> class websocket_session;

template <class Handler> class plain_http_session;
template <class Handler> class ssl_http_session;
template <class Derived, class Handler> class http_session;

/**
* \brief A handler with the capability to broadcast text among all the connected web socket
* clients.
*/
template <class Handler>
class broadcaster_handler
{
private:
    std::list<websocket_session<plain_websocket_session<Handler>, Handler>*> plain_ws_items_;
    std::list<websocket_session<ssl_websocket_session<Handler>, Handler>*> ssl_ws_items_;
    std::list<http_session<plain_http_session<Handler>, Handler>*> plain_http_items_;
    std::list<http_session<ssl_http_session<Handler>, Handler>*> ssl_http_items_;

    boost::mutex plain_ws_mutex_;
    boost::mutex ssl_ws_mutex_;
    boost::mutex plain_http_mutex_;
    boost::mutex ssl_http_mutex_;

public:
    broadcaster_handler<Handler>()
    {
        // Does nothing
    }

    // Plain web socket: adds the client to the list
    void on_created(websocket_session<plain_websocket_session<Handler>, Handler>* a_item)
    {
        std::cout << "        broadcaster_base::on_created plain ws" << std::endl;
        boost::mutex::scoped_lock lock(plain_ws_mutex_);
        plain_ws_items_.push_back(a_item);
    }

    // Plain web socket: removes the client from the list
    void on_destroyed(websocket_session<plain_websocket_session<Handler>, Handler>* a_item)
    {
        std::cout << "        broadcaster_base::on_destroyed plain ws" << std::endl;
        boost::mutex::scoped_lock lock(plain_ws_mutex_);
        plain_ws_items_.remove(a_item);
    }

    // SSL web socket: adds the client to the list
    void on_created(websocket_session<ssl_websocket_session<Handler>, Handler>* a_item)
    {
        std::cout << "        broadcaster_base::on_created ssl ws" << std::endl;
        boost::mutex::scoped_lock lock(ssl_ws_mutex_);
        ssl_ws_items_.push_back(a_item);
    }

    // SSL web socket: removes the client from the list
    void on_destroyed(websocket_session<ssl_websocket_session<Handler>, Handler>* a_item)
    {
        std::cout << "        broadcaster_base::on_destroyed ssl ws" << std::endl;
        boost::mutex::scoped_lock lock(ssl_ws_mutex_);
        ssl_ws_items_.remove(a_item);
    }

    // Plain HTTP: adds the client to the list
    void on_created(http_session<plain_http_session<Handler>, Handler>* a_item)
    {
        std::cout << "        broadcaster_base::on_created plain http" << std::endl;
        boost::mutex::scoped_lock lock(plain_http_mutex_);
        plain_http_items_.push_back(a_item);
    }

    // Plain HTTP: removes the client from the list
    void on_destroyed(http_session<plain_http_session<Handler>, Handler>* a_item)
    {
        std::cout << "        broadcaster_base::on_destroyed plain http" << std::endl;
        boost::mutex::scoped_lock lock(plain_http_mutex_);
        plain_http_items_.remove(a_item);
    }

    // SSL HTTP: adds the client to the list
    void on_created(http_session<ssl_http_session<Handler>, Handler>* a_item)
    {
        std::cout << "        broadcaster_base::on_created ssl http" << std::endl;
        boost::mutex::scoped_lock lock(ssl_http_mutex_);
        ssl_http_items_.push_back(a_item);
    }

    // SSL HTTP: removes the client from the list
    void on_destroyed(http_session<ssl_http_session<Handler>, Handler>* a_item)
    {
        std::cout << "        broadcaster_base::on_destroyed ssl http" << std::endl;
        boost::mutex::scoped_lock lock(ssl_http_mutex_);
        ssl_http_items_.remove(a_item);
    }

    // Broadcast some text to all the SSL and plain web socket clients connected
    void broadcast_text(std::string const& messageData)
    {
        {
            boost::mutex::scoped_lock lock(plain_ws_mutex_);
            std::for_each(plain_ws_items_.begin(), plain_ws_items_.end(), [&messageData](websocket_session<plain_websocket_session<Handler>, Handler>* ws)
            {
                ws->async_write_text(messageData);
            });
        }
        {
            boost::mutex::scoped_lock lock(ssl_ws_mutex_);
            std::for_each(ssl_ws_items_.begin(), ssl_ws_items_.end(), [&messageData](websocket_session<ssl_websocket_session<Handler>, Handler>* ws)
            {
                ws->async_write_text(messageData);
            });
        }
    }
};

#endif // BROADCASTER_HANDLER_HPP__18253FB6D0264813B58325300D467A9F
