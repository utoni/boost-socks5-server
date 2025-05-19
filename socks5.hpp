#include <atomic>
#include <boost/asio.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/deadline_timer.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/core/noncopyable.hpp>
#include <boost/date_time/posix_time/posix_time_duration.hpp>
#include <boost/noncopyable.hpp>
#include <boost/system/detail/error_code.hpp>
#include <boost/system/error_code.hpp>
#include <boost/variant.hpp>
#include <cstdint>
#include <memory>
#include <string_view>

#include "fastbuffer.hpp"

namespace SOCKS5 {
class DestinationSocketBase : private boost::noncopyable {
public:
  virtual ~DestinationSocketBase() {}

  template <typename Callback>
  void connect_tcp(boost::asio::ip::address &address, uint16_t port,
                   Callback &&handler) {
    do_connect_tcp(address, port, std::forward<Callback>(handler));
  }
  template <typename Callback>
  void tcp_bind(boost::asio::ip::address &address, uint16_t port,
                Callback &&handler) {
    do_bind_tcp(address, port, std::forward<Callback>(handler));
  }
  template <typename Callback>
  void udp_bind(boost::asio::ip::address &address, uint16_t port,
                Callback &&handler) {
    do_bind_udp(address, port, std::forward<Callback>(handler));
  }
  template <typename Callback>
  bool read(boost::asio::mutable_buffer buffer, Callback &&handler) {
    return do_read(buffer, std::forward<Callback>(handler));
  }
  template <typename Callback>
  bool write(boost::asio::mutable_buffer buffer, std::size_t length,
             Callback &&handler) {
    return do_write(buffer, length, std::forward<Callback>(handler));
  }
  virtual bool cancel() = 0;

protected:
  virtual void
  do_connect_tcp(boost::asio::ip::address &address, uint16_t port,
                 std::function<void(boost::system::error_code)>) = 0;
  virtual void do_bind_tcp(boost::asio::ip::address &address, uint16_t port,
                           std::function<void(boost::system::error_code)>) = 0;
  virtual void do_bind_udp(boost::asio::ip::address &address, uint16_t port,
                           std::function<void(boost::system::error_code)>) = 0;
  virtual bool
      do_read(boost::asio::mutable_buffer,
              std::function<void(boost::system::error_code, std::size_t)>) = 0;
  virtual bool
  do_write(boost::asio::mutable_buffer, std::size_t,
           std::function<void(boost::system::error_code, std::size_t)>) = 0;
};

template <typename Executor>
class AsyncDestinationSocket
    : public DestinationSocketBase,
      public std::enable_shared_from_this<AsyncDestinationSocket<Executor>> {
public:
  AsyncDestinationSocket(const Executor &exec) : m_strand(exec) {}
  ~AsyncDestinationSocket() {}

private:
  void do_connect_tcp(
      boost::asio::ip::address &address, uint16_t port,
      std::function<void(boost::system::error_code)> handler) override;
  void do_bind_tcp(boost::asio::ip::address &address, uint16_t port,
                   std::function<void(boost::system::error_code)>) override;
  void do_bind_udp(boost::asio::ip::address &address, uint16_t port,
                   std::function<void(boost::system::error_code)>) override;
  bool do_read(boost::asio::mutable_buffer buffer,
               std::function<void(boost::system::error_code, std::size_t)>
                   handler) override;
  bool
  do_write(boost::asio::mutable_buffer buffer, std::size_t length,
           std::function<void(boost::system::error_code, std::size_t)> handler);
  bool cancel() override;

  boost::asio::strand<Executor> m_strand;
  boost::optional<boost::variant<
      boost::asio::ip::tcp::socket,   // TCP connect
      boost::asio::ip::tcp::acceptor, // TCP bind (not implemented)
      boost::asio::ip::udp::socket    // UDP bind (not implemented)
      >>
      m_socket;
};

class ProxyBase : private boost::noncopyable {
public:
  ProxyBase(std::uint32_t session_id,
            boost::asio::ip::tcp::socket &&client_socket,
            std::size_t buffer_size = BUFSIZ);
  ProxyBase(std::uint32_t session_id,
            boost::asio::ip::tcp::socket &&client_socket,
            ContiguousStreamBuffer &&input_buffer,
            ContiguousStreamBuffer &&output_buffer);

protected:
  std::uint32_t m_sessionId;
  ContiguousStreamBuffer m_inBuf;
  ContiguousStreamBuffer m_outBuf;
  boost::asio::ip::tcp::socket m_clientSocket;
};

class ProxyAuth : private ProxyBase,
                  public std::enable_shared_from_this<ProxyAuth> {
public:
  ProxyAuth(std::uint32_t session_id,
            boost::asio::ip::tcp::socket &&client_socket);
  template <typename GetDsCallback> void start(GetDsCallback &&handler) {
    m_getDestinationSocket = std::forward<GetDsCallback>(handler);
    start_internal();
  }

private:
  void start_internal();
  void recv_client_greeting(const boost::system::error_code &ec,
                            std::size_t length);
  void recv_client_greeting(std::size_t length);
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

  std::function<std::unique_ptr<DestinationSocketBase>(
      boost::asio::any_io_executor)>
      m_getDestinationSocket;
  std::unique_ptr<DestinationSocketBase> m_destinationSocket;
  boost::asio::ip::tcp::resolver m_resolver;
  boost::asio::ip::address m_destinationAddress;
  std::uint16_t m_destinationPort;
};

class ProxySession : private ProxyBase,
                     public std::enable_shared_from_this<ProxySession> {
public:
  explicit ProxySession(std::uint32_t session_id,
                        boost::asio::ip::tcp::socket &&client_socket,
                        std::unique_ptr<DestinationSocketBase> &&dest_socket,
                        std::size_t buffer_size = 65535);
  void start();

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

  std::unique_ptr<DestinationSocketBase> m_destinationSocket;
};

class ProxyServer : private boost::noncopyable {
public:
  ProxyServer(boost::asio::io_context &ioc,
              const boost::asio::ip::tcp::endpoint &local_endpoint);
  ProxyServer(boost::asio::io_context &ioc, const std::string &listen_addr,
              std::uint16_t listen_port);
  void start();
  void stop();

protected:
  virtual void async_accept();

  std::atomic<uint32_t> m_nextSessionId;
  boost::asio::ip::tcp::acceptor m_acceptor;
};

// End Of Minimal Implementation

class LoggingProxyServer : public ProxyServer {
public:
  LoggingProxyServer(boost::asio::io_context &ioc,
                     const std::string &listen_addr, std::uint16_t listen_port);
  void start();
  void stop();

private:
  void async_timer();
  void async_accept() override;

  boost::asio::deadline_timer m_StatusLogger;
};
}; // namespace SOCKS5
