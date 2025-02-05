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
#include <vector>

namespace SOCKS5 {
class StreamBuffer : public boost::noncopyable {
public:
  explicit StreamBuffer(std::size_t size)
      : m_bufferUsed{0}, m_bufferSize{size} {
    m_buffer = new std::uint8_t[size];
  }
  StreamBuffer(StreamBuffer &&moveable) {
    m_bufferUsed = moveable.m_bufferUsed;
    m_bufferSize = moveable.m_bufferSize;
    m_buffer = moveable.m_buffer;
    moveable.m_buffer = nullptr;
  }
  ~StreamBuffer() { delete[] m_buffer; }
  void operator+=(std::size_t commit_size) { m_bufferUsed += commit_size; }
  void operator+=(const std::initializer_list<uint8_t> &to_add) {
    std::copy(to_add.begin(), to_add.end(), &m_buffer[m_bufferUsed]);
    m_bufferUsed += to_add.size();
  }
  void operator-=(std::size_t consume_size) { m_bufferUsed -= consume_size; }
  auto operator+() {
    return boost::asio::buffer(&m_buffer[m_bufferUsed],
                               m_bufferSize - m_bufferUsed);
  }
  auto operator-() { return boost::asio::buffer(&m_buffer[0], m_bufferUsed); }
  auto operator[](std::size_t index) const { return m_buffer[index]; }
  const auto *operator()(std::size_t index = 0) const {
    return &m_buffer[index];
  }
  auto size() const { return m_bufferUsed; }
  auto getHealth() const {
    return (static_cast<float>(m_bufferUsed) /
            static_cast<float>(m_bufferSize));
  }

private:
  std::size_t m_bufferUsed;
  std::size_t m_bufferSize;
  std::uint8_t *m_buffer;
};

class ProxySessionBase : public boost::noncopyable {
public:
  ProxySessionBase(std::uint32_t session_id,
                   boost::asio::ip::tcp::socket &&client_socket,
                   std::size_t buffer_size = BUFSIZ);
  ProxySessionBase(std::uint32_t session_id,
                   boost::asio::ip::tcp::socket &&client_socket,
                   StreamBuffer &&input_buffer, StreamBuffer &&output_buffer);

  std::uint32_t m_sessionId;
  StreamBuffer m_inBuf;
  StreamBuffer m_outBuf;
  boost::asio::ip::tcp::socket m_clientSocket;
};

class ProxySessionAuth : public ProxySessionBase,
                         public std::enable_shared_from_this<ProxySessionAuth> {
public:
  ProxySessionAuth(std::uint32_t session_id,
                   boost::asio::ip::tcp::socket &&client_socket);
  void start();

private:
  void recv_client_greeting(const boost::system::error_code &ec,
                            std::size_t length);
  void send_server_greeting(bool auth_supported);
  void recv_connection_request(const boost::system::error_code &ec,
                               std::size_t length);
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
};

class ProxySessionTcp : public ProxySessionBase,
                        public std::enable_shared_from_this<ProxySessionTcp> {
public:
  explicit ProxySessionTcp(ProxySessionBase &base,
                           std::size_t buffer_size = 65535);
  void start(boost::asio::ip::tcp::endpoint &destination);

private:
  void recv_from_both();
  void recv_from_destination(const boost::system::error_code &ec,
                             std::size_t length);
  void recv_from_client(const boost::system::error_code &ec,
                        std::size_t length);
  void handle_client_write(const boost::system::error_code &ec,
                           std::size_t length);
  void handle_destination_write(const boost::system::error_code &ec,
                                std::size_t length);

  boost::asio::ip::tcp::socket m_destinationSocket;
};

class ProxyServer : public boost::noncopyable {
public:
  ProxyServer(boost::asio::io_context &ioc,
              const boost::asio::ip::tcp::endpoint &local_endpoint);
  ProxyServer(boost::asio::io_context &ioc, const std::string &listen_addr,
              std::uint16_t listen_port);
  void start();

private:
  void async_accept();

  uint32_t m_nextSessionId;
  boost::asio::ip::tcp::acceptor m_acceptor;
};
}; // namespace SOCKS5
