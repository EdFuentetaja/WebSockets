
#ifndef DEFAULT_HANDLER_HPP__0CA484BA246046A39BBD5A1D038D7A56
#define DEFAULT_HANDLER_HPP__0CA484BA246046A39BBD5A1D038D7A56

#include "advanced_server_flex.hpp"

/**
* \brief A default_handler implementation. This is for the convenience of concrete handlers who doesn't care about on_created/on_destroyed notifications.
*/
template <class Handler>
class default_handler
{
public:
    // Plain web sockets
    void on_created(websocket_session<plain_websocket_session<Handler>, Handler>* a_item)
    {
        // Does nothing
    }

    void on_destroyed(websocket_session<plain_websocket_session<Handler>, Handler>* a_item)
    {
        // Does nothing
    }

    // SSL web sockets
    void on_created(websocket_session<ssl_websocket_session<Handler>, Handler>* a_item)
    {
        // Does nothing
    }

    void on_destroyed(websocket_session<ssl_websocket_session<Handler>, Handler>* a_item)
    {
        // Does nothing
    }

    // Plain HTTP
    void on_created(http_session<plain_http_session<Handler>, Handler>* a_item)
    {
        // Does nothing
    }

    void on_destroyed(http_session<plain_http_session<Handler>, Handler>* a_item)
    {
        // Does nothing
    }

    // SSL HTTP
    void on_created(http_session<ssl_http_session<Handler>, Handler>* a_item)
    {
        // Does nothing
    }

    void on_destroyed(http_session<ssl_http_session<Handler>, Handler>* a_item)
    {
        // Does nothing
    }
};

#endif // DEFAULT_HANDLER_HPP__0CA484BA246046A39BBD5A1D038D7A56
