
#include "default_handler.hpp"

/**
 * \brief This concrete handler implements a HTTP file server. It encapsulates the file-serving functionality from the original
 * advanced_server_flex.cpp example from Vinnie Franco. I believe this is a cleaner design.
 */
class example_httpfileserver_handler : public default_handler<example_httpfileserver_handler>
{
private:
    std::string const& doc_root_;

    // Return a reasonable mime type based on the extension of a file.
    static boost::beast::string_view mime_type(boost::beast::string_view path)
    {
        using boost::beast::iequals;
        auto const ext = [&path]
        {
            auto const pos = path.rfind(".");
            if (pos == boost::beast::string_view::npos)
                return boost::beast::string_view{};
            return path.substr(pos);
        }();

        if (iequals(ext, ".htm"))  return "text/html";
        if (iequals(ext, ".html")) return "text/html";
        if (iequals(ext, ".php"))  return "text/html";
        if (iequals(ext, ".css"))  return "text/css";
        if (iequals(ext, ".txt"))  return "text/plain";
        if (iequals(ext, ".js"))   return "application/javascript";
        if (iequals(ext, ".json")) return "application/json";
        if (iequals(ext, ".xml"))  return "application/xml";
        if (iequals(ext, ".swf"))  return "application/x-shockwave-flash";
        if (iequals(ext, ".flv"))  return "video/x-flv";
        if (iequals(ext, ".png"))  return "image/png";
        if (iequals(ext, ".jpe"))  return "image/jpeg";
        if (iequals(ext, ".jpeg")) return "image/jpeg";
        if (iequals(ext, ".jpg"))  return "image/jpeg";
        if (iequals(ext, ".gif"))  return "image/gif";
        if (iequals(ext, ".bmp"))  return "image/bmp";
        if (iequals(ext, ".ico"))  return "image/vnd.microsoft.icon";
        if (iequals(ext, ".tiff")) return "image/tiff";
        if (iequals(ext, ".tif"))  return "image/tiff";
        if (iequals(ext, ".svg"))  return "image/svg+xml";
        if (iequals(ext, ".svgz")) return "image/svg+xml";
        return "application/text";
    }

    // Append an HTTP rel-path to a local filesystem path.
    // The returned path is normalized for the platform.
    static std::string path_cat(boost::beast::string_view base, boost::beast::string_view path)
    {
        if (base.empty())
            return path.to_string();
        std::string result = base.to_string();
#if BOOST_MSVC
        char constexpr path_separator = '\\';
        if (result.back() == path_separator)
            result.resize(result.size() - 1);
        result.append(path.data(), path.size());
        for (auto& c : result)
            if (c == '/')
                c = path_separator;
#else
        char constexpr path_separator = '/';
        if (result.back() == path_separator)
            result.resize(result.size() - 1);
        result.append(path.data(), path.size());
#endif
        return result;
    }

public:
    example_httpfileserver_handler(std::string const& doc_root) : doc_root_(doc_root)
    {
        // Does nothing
    }

    // This implementation ignores web socket calls...
    template<class WebSocket, class ConstBufferSequence>
    void on_read(WebSocket& websocket, ConstBufferSequence const& bs)
    {
        char const* msg = boost::asio::buffer_cast<char const*>(boost::beast::buffers_front(bs.data()));
        size_t length = boost::asio::buffer_size(bs.data());
        std::string s_msg = std::string(msg, length);

        std::cout << "Received " << s_msg << " through websocket. Going to ignore it." << std::endl;
    }

    // This function produces an HTTP response for the given
    // request. The type of the response object depends on the
    // contents of the request, so the interface requires the
    // caller to pass a generic lambda for receiving the response.
    template<class Body, class Allocator, class Send>
    void handle_request(http::request<Body, http::basic_fields<Allocator> >&& req, Send&& send)
    {
        // Returns a bad request response
        auto const bad_request =
            [&req](boost::beast::string_view why)
        {
            http::response<http::string_body> res{ http::status::bad_request, req.version() };
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "text/html");
            res.keep_alive(req.keep_alive());
            res.body() = why.to_string();
            res.prepare_payload();
            return res;
        };

        // Returns a not found response
        auto const not_found =
            [&req](boost::beast::string_view target)
        {
            http::response<http::string_body> res{ http::status::not_found, req.version() };
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "text/html");
            res.keep_alive(req.keep_alive());
            res.body() = "The resource '" + target.to_string() + "' was not found.";
            res.prepare_payload();
            return res;
        };

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

        // Make sure we can handle the method
        if (req.method() != http::verb::get &&
            req.method() != http::verb::head)
            return send(bad_request("Unknown HTTP-method"));

        // Request path must be absolute and not contain "..".
        if (req.target().empty() ||
            req.target()[0] != '/' ||
            req.target().find("..") != boost::beast::string_view::npos)
            return send(bad_request("Illegal request-target"));

        // Build the path to the requested file
        std::string path = path_cat(doc_root_, req.target());
        if (req.target().back() == '/')
            path.append("index.html");

        // Attempt to open the file
        boost::beast::error_code ec;
        http::file_body::value_type body;
        body.open(path.c_str(), boost::beast::file_mode::scan, ec);

        if (ec == boost::system::errc::no_such_file_or_directory) {
            // Handle the case where the file doesn't exist
            std::cout << "HTTP response is NOT FOUND" << std::endl;
            return send(not_found(req.target()));
        }
        else if (ec) {
            // Handle an unknown error
            std::cout << "HTTP response is SERVER ERROR" << std::endl;
            return send(server_error(ec.message()));
        }
        else if (req.method() == http::verb::head) {
            // Respond to HEAD request
            http::response<http::empty_body> res{ http::status::ok, req.version() };
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, mime_type(path));
            res.content_length(body.size());
            res.keep_alive(req.keep_alive());
            std::cout << "HTTP response is OK, sending header" << std::endl;
            return send(std::move(res));
        }
        else {
            // Respond to GET request
            http::response<http::file_body> res{
                std::piecewise_construct,
                std::make_tuple(std::move(body)),
                std::make_tuple(http::status::ok, req.version()) };
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, mime_type(path));
            res.content_length(body.size());
            res.keep_alive(req.keep_alive());
            std::cout << "HTTP response is OK, sending header & body" << std::endl;
            return send(std::move(res));
        }
    }
};

int main(int argc, char* argv[])
{
    // Check command line arguments.
    if (argc != 5)
    {
        std::cerr <<
            "Usage: main_httpfileserver <address> <port> <doc_root> <threads>\n" <<
            "Example:\n" <<
            "    main_httpfileserver 0.0.0.0 8080 . 1\n";
        return EXIT_FAILURE;
    }
    auto const address = boost::asio::ip::make_address(argv[1]);
    auto const port = static_cast<unsigned short>(std::atoi(argv[2]));
    std::string const doc_root = argv[3];
    auto const thread_count = std::max<int>(1, std::atoi(argv[4]));

    // The io_context is required for all I/O
    boost::asio::io_context ioc{ thread_count };

    example_httpfileserver_handler the_handler(doc_root);

    int timeout_seconds = 15;

    // Create a listening port
    std::shared_ptr<listener<example_httpfileserver_handler> > the_listener = std::make_shared<listener<example_httpfileserver_handler> >(
        ioc,
        tcp::endpoint{ address, port },
        the_handler,
        timeout_seconds);

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

    std::cout << "Server going to listen on " << address << ":" << port << ", doc root is: " << doc_root << " ..." << std::endl;
    ioc.run();

    return EXIT_SUCCESS;
}
