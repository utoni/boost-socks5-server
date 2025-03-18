#include <atomic>
#include <boost/asio.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/core/noncopyable.hpp>
#include <boost/noncopyable.hpp>
#include <boost/system/detail/error_code.hpp>
#include <boost/system/error_code.hpp>
#include <cstdint>
#include <memory>
#include <string_view>

#include "fastbuffer.hpp"

namespace SOCKS5 {
class ProxySessionBase : private boost::noncopyable {
public:
  using CompletionHandler = std::function<void(std::size_t length)>;
  ProxySessionBase(std::uint32_t session_id,
                   boost::asio::ip::tcp::socket &&client_socket,
                   std::size_t buffer_size = BUFSIZ);
  ProxySessionBase(std::uint32_t session_id,
                   boost::asio::ip::tcp::socket &&client_socket,
                   ContiguousStreamBuffer &&input_buffer, ContiguousStreamBuffer &&output_buffer);
  void async_read(const CompletionHandler &handler,
                  std::size_t expected_length = 0);

protected:
  std::uint32_t m_sessionId;
  ContiguousStreamBuffer m_inBuf;
  ContiguousStreamBuffer m_outBuf;
  boost::asio::ip::tcp::socket m_clientSocket;
};

class ProxySessionAuth : private ProxySessionBase,
                         public std::enable_shared_from_this<ProxySessionAuth> {
public:
  ProxySessionAuth(std::uint32_t session_id,
                   boost::asio::ip::tcp::socket &&client_socket);
  void start();

private:
  void recv_client_greeting(std::size_t length);
  void send_server_greeting(bool auth_supported);
  void recv_connection_request(std::size_t length);
  void process_connection_request();
  void send_server_response(std::uint8_t proxy_cmd, std::uint8_t status_code);
  void resolve_destination_host(std::uint8_t proxy_cmd,
                                const std::string_view &host,
                                std::uint16_t port);
  void connect_to_destination(std::uint8_t proxy_cmd);
  void handle_write(const boost::system::error_code &ec, std::size_t length);
  void handle_response_write(std::uint8_t proxy_cmd, std::uint8_t status_code,
                             const boost::system::error_code &ec,
                             std::size_t length);

  boost::asio::ip::tcp::resolver m_resolver;
  boost::asio::ip::tcp::endpoint m_endpoint;
  boost::asio::ip::tcp::socket m_destinationSocket;
};

class ProxySessionTcp : private ProxySessionBase,
                        public std::enable_shared_from_this<ProxySessionTcp> {
public:
  explicit ProxySessionTcp(std::uint32_t session_id,
                           boost::asio::ip::tcp::socket &&client_socket,
                           boost::asio::ip::tcp::socket &&destination_socket,
                           std::size_t buffer_size = 65535);
  void start();

private:
  void recv_from_both();
  void recv_from_destination(const boost::system::error_code &ec,
                             std::size_t length);
  void recv_from_client(std::size_t length);
  void handle_client_write(const boost::system::error_code &ec,
                           std::size_t length);
  void handle_destination_write(const boost::system::error_code &ec,
                                std::size_t length);

  boost::asio::ip::tcp::socket m_destinationSocket;
};

class ProxyServer : private boost::noncopyable {
public:
  ProxyServer(boost::asio::io_context &ioc,
              const boost::asio::ip::tcp::endpoint &local_endpoint);
  ProxyServer(boost::asio::io_context &ioc, const std::string &listen_addr,
              std::uint16_t listen_port);
  void start();

private:
  void async_accept();

  std::atomic<uint32_t> m_nextSessionId;
  boost::asio::ip::tcp::acceptor m_acceptor;
};
}; // namespace SOCKS5
