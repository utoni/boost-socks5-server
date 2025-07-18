#include "socks5.hpp"

#include <boost/asio/completion_condition.hpp>
#include <boost/asio/impl/write.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/address_v6.hpp>
#include <boost/asio/placeholders.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/strand.hpp>
#include <boost/bind/bind.hpp>
#include <boost/system/detail/error_code.hpp>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>

using namespace SOCKS5;
using namespace boost;
using namespace boost::asio;
using boost::asio::io_context;
using boost::asio::ip::tcp;
using namespace boost::system;

static std::mutex g_loggingMutex;

template <typename Executor>
void AsyncDestinationSocket<Executor>::do_connect_tcp(
    boost::asio::ip::tcp::resolver::results_type::const_iterator &it,
    std::function<void(system::error_code)> handler) {
  m_socket.emplace(tcp::socket(m_strand));
  auto &tcp_socket = boost::get<tcp::socket>(*m_socket);
  tcp_socket.async_connect(it->endpoint(), std::move(handler));
}

template <typename Executor>
bool AsyncDestinationSocket<Executor>::do_read(
    BufferBase &buffer,
    std::function<void(system::error_code, std::size_t)> handler) {
  if (m_socket) {
    if (auto *s = boost::get<tcp::socket>(&*m_socket)) {
      s->async_read_some(+buffer, std::move(handler));
      return true;
    }
  }
  return false;
}

template <typename Executor>
bool AsyncDestinationSocket<Executor>::do_write(
    BufferBase &buffer, std::size_t length,
    std::function<void(system::error_code, std::size_t)> handler) {
  if (m_socket) {
    if (auto *s = boost::get<tcp::socket>(&*m_socket)) {
      async_write(*s, -buffer, transfer_exactly(length), std::move(handler));
      return true;
    }
  }
  return false;
}

template <typename Executor> bool AsyncDestinationSocket<Executor>::cancel() {
  if (m_socket) {
    if (auto *s = boost::get<tcp::socket>(&*m_socket)) {
      s->cancel();
      return true;
    }
  }
  return false;
}

ProxyBase::ProxyBase(std::uint32_t session_id, tcp::socket &&client_socket,
                     std::size_t buffer_size)
    : m_sessionId{session_id}, m_inBuf{buffer_size}, m_outBuf{buffer_size},
      m_clientSocket{std::move(client_socket)} {}

ProxyBase::ProxyBase(std::uint32_t session_id, tcp::socket &&client_socket,
                     ContiguousStreamBuffer &&input_buffer,
                     ContiguousStreamBuffer &&output_buffer)
    : m_sessionId{session_id}, m_inBuf{std::move(input_buffer)},
      m_outBuf{std::move(output_buffer)},
      m_clientSocket{std::move(client_socket)} {}

ProxyAuth::ProxyAuth(std::uint32_t session_id, tcp::socket &&client_socket)
    : ProxyBase(session_id, std::move(client_socket), 512),
      session_buffer_size{0} {}

void ProxyAuth::start_internal() {
  BOOST_ASIO_HANDLER_LOCATION((__FILE__, __LINE__, __func__));

  async_read(m_clientSocket, +m_inBuf, transfer_at_least(2),
             boost::bind(&ProxyAuth::recv_client_greeting, shared_from_this(),
                         asio::placeholders::error,
                         asio::placeholders::bytes_transferred));
}

void ProxyAuth::recv_client_greeting(const system::error_code &ec,
                                     std::size_t length) {
  BOOST_ASIO_HANDLER_LOCATION((__FILE__, __LINE__, __func__));

  if (ec || length == 0)
    return;
  m_inBuf += length;

  if (m_inBuf[0] != 0x05 || m_inBuf[1] > 0x09 || m_inBuf[1] == 0x00)
    return;
  const std::size_t expected_size = std::size_t(2) + m_inBuf[1];
  if (m_inBuf.size() < expected_size) {
    async_read(m_clientSocket, +m_inBuf,
               transfer_at_least(expected_size - m_inBuf.size()),
               boost::bind(&ProxyAuth::recv_client_greeting, shared_from_this(),
                           asio::placeholders::error,
                           asio::placeholders::bytes_transferred));
    return;
  }

  auto found_no_auth = false; // only "No Authentication" supported
  for (auto i = std::size_t(2); i < expected_size; ++i) {
    if (m_inBuf[i] == 0x00) {
      found_no_auth = true;
      break;
    }
  }

  m_inBuf -= expected_size;
  send_server_greeting(found_no_auth);
}

void ProxyAuth::send_server_greeting(bool auth_supported) {
  BOOST_ASIO_HANDLER_LOCATION((__FILE__, __LINE__, __func__));

  if (!auth_supported) {
    m_outBuf += {0x05, 0xFF};
    m_clientSocket.async_send(
        -m_outBuf, boost::bind(&ProxyAuth::handle_write, shared_from_this(),
                               asio::placeholders::error,
                               asio::placeholders::bytes_transferred));
    return;
  }

  m_outBuf += {0x05, 0x00};
  m_clientSocket.async_send(
      -m_outBuf, boost::bind(&ProxyAuth::handle_write, shared_from_this(),
                             asio::placeholders::error,
                             asio::placeholders::bytes_transferred));
  process_connection_request();
}

void ProxyAuth::recv_connection_request(const system::error_code &ec,
                                        std::size_t length) {
  BOOST_ASIO_HANDLER_LOCATION((__FILE__, __LINE__, __func__));

  if (ec || length == 0)
    return;
  m_inBuf += length;
  process_connection_request();
}

void ProxyAuth::process_connection_request() {
  BOOST_ASIO_HANDLER_LOCATION((__FILE__, __LINE__, __func__));

  if (m_inBuf.size() < 6) {
    async_read(m_clientSocket, +m_inBuf, transfer_at_least(6 - m_inBuf.size()),
               boost::bind(&ProxyAuth::recv_connection_request,
                           shared_from_this(), asio::placeholders::error,
                           asio::placeholders::bytes_transferred));
    return;
  }

  if (m_inBuf[0] != 0x05 || m_inBuf[1] > 0x03 || m_inBuf[2] != 0x00)
    return;

  size_t expected_size = 0;
  uint8_t address_size;
  switch (m_inBuf[3]) {
  // IPv4 Address
  case 0x01:
    address_size = 4;
    break;
  // DNS FQDN
  case 0x03:
    address_size = m_inBuf[4];
    expected_size++;
    break;
  // IPv6 Address
  case 0x04:
    address_size = 16;
    break;
  default:
    return;
  }

  expected_size += std::size_t(6) + address_size;
  if (m_inBuf.size() < expected_size) {
    async_read(m_clientSocket, +m_inBuf,
               transfer_at_least(expected_size - m_inBuf.size()),
               boost::bind(&ProxyAuth::recv_connection_request,
                           shared_from_this(), asio::placeholders::error,
                           asio::placeholders::bytes_transferred));
    return;
  }

  const uint8_t proxy_cmd = m_inBuf[1];
  switch (m_inBuf[3]) {
  case 0x01: {
    auto ip4_bytes = ::ntohl(*reinterpret_cast<const uint32_t *>(m_inBuf(4)));
    auto host = ip::make_address_v4(ip4_bytes);
    auto port =
        ntohs(*reinterpret_cast<const uint16_t *>(m_inBuf(4 + address_size)));
    tcp::endpoint direct_endpoint(std::move(host), port);
    m_tcp_resolver_results =
        tcp::resolver::results_type::create(std::move(direct_endpoint), "", "");
    m_tcp_resolver_iter = m_tcp_resolver_results.cbegin();
    connect_to_destination(proxy_cmd);
    break;
  }
  case 0x03: {
    auto host = std::string_view(reinterpret_cast<const char *>(m_inBuf(5)),
                                 address_size);
    auto port = ntohs(
        (*reinterpret_cast<const uint8_t *>(m_inBuf(5 + address_size)) << 0) |
        (*reinterpret_cast<const uint8_t *>(m_inBuf(6 + address_size)) << 8));
    tcp::endpoint direct_endpoint(ip::address_v4(), port);
    m_tcp_resolver_results = tcp::resolver::results_type::create(
        std::move(direct_endpoint), std::string(host), "");
    m_tcp_resolver_iter = m_tcp_resolver_results.cbegin();
    resolve_tcp_destination_host(proxy_cmd, host, port);
    break;
  }
  case 0x04: {
    auto ip6_array =
        *reinterpret_cast<const std::array<std::uint8_t, 16> *>(m_inBuf(4));
    auto host = ip::make_address_v6(ip6_array);
    auto port =
        ntohs(*reinterpret_cast<const uint16_t *>(m_inBuf(4 + address_size)));
    tcp::endpoint direct_endpoint(std::move(host), port);
    m_tcp_resolver_results =
        tcp::resolver::results_type::create(std::move(direct_endpoint), "", "");
    m_tcp_resolver_iter = m_tcp_resolver_results.cbegin();
    connect_to_destination(proxy_cmd);
    break;
  }
  default:
    break;
  }

  m_inBuf -= expected_size;
}

void ProxyAuth::send_server_response(std::uint8_t proxy_cmd,
                                     std::uint8_t status_code) {
  BOOST_ASIO_HANDLER_LOCATION((__FILE__, __LINE__, __func__));

  m_outBuf += {0x05, status_code, 0x00};

  auto tcp_endpoint = m_tcp_resolver_iter->endpoint();
  auto tcp_address = tcp_endpoint.address();
  if (m_tcp_resolver.has_value()) {
    const auto tcp_hostname = m_tcp_resolver_iter->host_name();
    m_outBuf += {0x03, static_cast<uint8_t>(tcp_hostname.length())};
    m_outBuf += tcp_hostname;
  } else if (tcp_address.is_v4()) {
    const uint32_t addr = ::htonl(tcp_address.to_v4().to_uint());
    m_outBuf += {0x01, static_cast<uint8_t>(addr & 0x000000FF),
                 static_cast<uint8_t>((addr & 0x0000FF00) >> 8),
                 static_cast<uint8_t>((addr & 0x00FF0000) >> 16),
                 static_cast<uint8_t>((addr & 0xFF000000) >> 24)};
  } else {
    m_outBuf += {0x04};
    const auto addr = tcp_address.to_v6().to_bytes();
    for (const auto byte : addr)
      m_outBuf += {byte};
  }
  const auto port = htons(tcp_endpoint.port());
  m_outBuf += std::initializer_list<unsigned char>{
      static_cast<uint8_t>(port & 0x00FF),
      static_cast<uint8_t>((port & 0xFF00) >> 8)};

  m_clientSocket.async_send(-m_outBuf,
                            boost::bind(&ProxyAuth::handle_response_write,
                                        shared_from_this(), proxy_cmd,
                                        status_code, asio::placeholders::error,
                                        asio::placeholders::bytes_transferred));
}

void ProxyAuth::resolve_tcp_destination_host(std::uint8_t proxy_cmd,
                                             const std::string_view &host,
                                             std::uint16_t port) {
  BOOST_ASIO_HANDLER_LOCATION((__FILE__, __LINE__, __func__));

  m_tcp_resolver.emplace(m_clientSocket.get_executor());
  m_tcp_resolver->async_resolve(
      host, std::to_string(port),
      [this, self = shared_from_this(),
       proxy_cmd](const system::error_code &ec,
                  boost::asio::ip::tcp::resolver::results_type res) {
        if (ec) {
          send_server_response(proxy_cmd, 0x04);
          return;
        }
        m_tcp_resolver_results = std::move(res);
        m_tcp_resolver_iter = m_tcp_resolver_results.cbegin();
        connect_to_destination(proxy_cmd);
      });
}

void ProxyAuth::connect_to_destination(std::uint8_t proxy_cmd) {
  BOOST_ASIO_HANDLER_LOCATION((__FILE__, __LINE__, __func__));

  const auto check_error = [this, proxy_cmd](const system::error_code &ec) {
    if (ec) {
      auto tmp_iter = m_tcp_resolver_iter;
      if (++tmp_iter != m_tcp_resolver_results.cend()) {
        m_tcp_resolver_iter = tmp_iter;
        return connect_to_destination(proxy_cmd);
      }

      if (ec == system::errc::connection_refused)
        send_server_response(proxy_cmd, 0x05);
      else if (ec == system::errc::network_unreachable)
        send_server_response(proxy_cmd, 0x03);
      else if (ec == system::errc::host_unreachable)
        send_server_response(proxy_cmd, 0x04);
      else
        send_server_response(proxy_cmd, 0x01);
      return;
    }
    send_server_response(proxy_cmd, 0x00);
  };

  if (!m_destinationSocket) {
    m_destinationSocket = m_getDestinationSocket(m_clientSocket.get_executor());
    if (!m_destinationSocket)
      return send_server_response(proxy_cmd, 0x01);
  }

  switch (proxy_cmd) {
  case 0x01: // TCP client connection
  {

    m_destinationSocket->connect_tcp(
        m_tcp_resolver_iter,
        [self = shared_from_this(), check_error](const system::error_code &ec) {
          check_error(ec);
        });
    return;
  }
  case 0x02: // TCP port bind (not implemented)
  {
    return send_server_response(proxy_cmd, 0x07);
  }
  case 0x03: // UDP port bind (not implemented)
  {
    return send_server_response(proxy_cmd, 0x07);
  }
  default:
    return send_server_response(proxy_cmd, 0x07);
  }
}

void ProxyAuth::handle_write(const system::error_code &ec, std::size_t length) {
  BOOST_ASIO_HANDLER_LOCATION((__FILE__, __LINE__, __func__));

  if (ec || length == 0)
    m_clientSocket.cancel();
  m_outBuf -= length;

  if (m_outBuf.size() > 0)
    m_clientSocket.async_send(
        -m_outBuf, boost::bind(&ProxyAuth::handle_write, shared_from_this(),
                               asio::placeholders::error,
                               asio::placeholders::bytes_transferred));
}

void ProxyAuth::handle_response_write(std::uint8_t proxy_cmd,
                                      std::uint8_t status_code,
                                      const system::error_code &ec,
                                      std::size_t length) {
  BOOST_ASIO_HANDLER_LOCATION((__FILE__, __LINE__, __func__));

  if (ec || length == 0)
    m_clientSocket.cancel();
  m_outBuf -= length;

  if (m_outBuf.size() > 0) {
    m_clientSocket.async_send(
        -m_outBuf,
        boost::bind(&ProxyAuth::handle_response_write, shared_from_this(),
                    proxy_cmd, status_code, asio::placeholders::error,
                    asio::placeholders::bytes_transferred));
    return;
  }

  if (status_code == 0x00) {
    std::shared_ptr<ProxySession> session = nullptr;
    if (session_buffer_size)
      session = std::make_shared<ProxySession>(
          m_sessionId, std::move(m_clientSocket),
          std::move(m_destinationSocket), session_buffer_size);
    else
      session = std::make_shared<ProxySession>(
          m_sessionId, std::move(m_clientSocket),
          std::move(m_destinationSocket), std::move(m_inBuf),
          std::move(m_outBuf));
    if (!session) {
      m_clientSocket.cancel();
      return;
    }
    session->start();
  }
}

ProxySession::ProxySession(std::uint32_t session_id,
                           tcp::socket &&client_socket,
                           std::shared_ptr<DestinationSocketBase> &&dest_socket,
                           std::size_t buffer_size)
    : ProxyBase(session_id, std::move(client_socket), buffer_size),
      m_destinationSocket(std::move(dest_socket)) {}

ProxySession::ProxySession(std::uint32_t session_id,
                           tcp::socket &&client_socket,
                           std::shared_ptr<DestinationSocketBase> &&dest_socket,
                           ContiguousStreamBuffer &&input_buffer,
                           ContiguousStreamBuffer &&output_buffer)
    : ProxyBase(session_id, std::move(client_socket), std::move(input_buffer),
                std::move(output_buffer)),
      m_destinationSocket(std::move(dest_socket)) {}

void ProxySession::start() { recv_from_both(); }

void ProxySession::recv_from_both() {
  BOOST_ASIO_HANDLER_LOCATION((__FILE__, __LINE__, __func__));

  m_clientSocket.async_read_some(
      +m_inBuf, boost::bind(&ProxySession::recv_from_client, shared_from_this(),
                            asio::placeholders::error,
                            asio::placeholders::bytes_transferred));
  m_destinationSocket->read(
      m_outBuf, boost::bind(&ProxySession::recv_from_destination,
                            shared_from_this(), asio::placeholders::error,
                            asio::placeholders::bytes_transferred));
}

void ProxySession::recv_from_destination(const system::error_code &ec,
                                         std::size_t length) {
  BOOST_ASIO_HANDLER_LOCATION((__FILE__, __LINE__, __func__));

  if (ec || length == 0) {
    m_destinationSocket->cancel();
    return;
  }

  m_outBuf += length;
  async_write(m_clientSocket, -m_outBuf, transfer_all(),
              boost::bind(&ProxySession::handle_client_write,
                          shared_from_this(), asio::placeholders::error,
                          asio::placeholders::bytes_transferred));
}

void ProxySession::recv_from_client(const system::error_code &ec,
                                    std::size_t length) {
  BOOST_ASIO_HANDLER_LOCATION((__FILE__, __LINE__, __func__));

  if (ec || length == 0) {
    m_destinationSocket->cancel();
    return;
  }

  m_inBuf += length;
  m_destinationSocket->write(
      m_inBuf, length,
      boost::bind(&ProxySession::handle_destination_write, shared_from_this(),
                  asio::placeholders::error,
                  asio::placeholders::bytes_transferred));
}

void ProxySession::handle_client_write(const system::error_code &ec,
                                       std::size_t length) {
  BOOST_ASIO_HANDLER_LOCATION((__FILE__, __LINE__, __func__));

  if (ec || length == 0) {
    m_clientSocket.cancel();
    return;
  }

  m_outBuf -= length;
  m_destinationSocket->read(
      m_outBuf, boost::bind(&ProxySession::recv_from_destination,
                            shared_from_this(), asio::placeholders::error,
                            asio::placeholders::bytes_transferred));
}

void ProxySession::handle_destination_write(const system::error_code &ec,
                                            std::size_t length) {
  BOOST_ASIO_HANDLER_LOCATION((__FILE__, __LINE__, __func__));

  if (ec || length == 0) {
    m_destinationSocket->cancel();
    return;
  }

  m_inBuf -= length;
  m_clientSocket.async_read_some(
      +m_inBuf, boost::bind(&ProxySession::recv_from_client, shared_from_this(),
                            asio::placeholders::error,
                            asio::placeholders::bytes_transferred));
}

ProxyServer::ProxyServer(io_context &ioc, const tcp::endpoint &local_endpoint)
    : m_nextSessionId{1}, m_acceptor(ioc, local_endpoint) {}

ProxyServer::ProxyServer(io_context &ioc, const std::string &listen_addr,
                         std::uint16_t listen_port)
    : ProxyServer(ioc,
                  tcp::endpoint(ip::make_address(listen_addr), listen_port)) {}

void ProxyServer::start() { async_accept(); }

void ProxyServer::stop() { m_acceptor.cancel(); }

void ProxyServer::async_accept() {
  m_acceptor.async_accept(
      make_strand(m_acceptor.get_executor()),
      [this](const system::error_code &ec, tcp::socket client_socket) {
        if (!ec) {
          auto auth_session = std::make_shared<ProxyAuth>(
              m_nextSessionId.fetch_add(1, std::memory_order_relaxed),
              std::move(client_socket));

          if (auth_session) {
            auth_session->set_session_buffer_size(BUFSIZ);
            auth_session->start([](any_io_executor exec) {
              auto aptr = new AsyncDestinationSocket<any_io_executor>(exec);
              return std::shared_ptr<DestinationSocketBase>(std::move(aptr));
            });
          }
        }
        async_accept();
      });
}

template <typename Executor>
void LoggingAsyncDestinationSocket<Executor>::do_connect_tcp(
    boost::asio::ip::tcp::resolver::results_type::const_iterator &it,
    std::function<void(system::error_code)> handler) {
  const auto endpoint = it->endpoint();
  {
    std::lock_guard log_mtx{g_loggingMutex};
    std::cout << "LoggingProxyServer::do_connect_tcp(): "
              << endpoint.address().to_string() << ":" << endpoint.port()
              << "\n";
  }
  AsyncDestinationSocket<Executor>::do_connect_tcp(it, handler);
}

template <typename Executor>
bool LoggingAsyncDestinationSocket<Executor>::do_read(
    BufferBase &buffer,
    std::function<void(system::error_code, std::size_t)> handler) {
  return AsyncDestinationSocket<Executor>::do_read(
      buffer, [this, handler](system::error_code ec, std::size_t length) {
        m_bytesRead.fetch_add(length, std::memory_order_relaxed);
        handler(ec, length);
      });
}

template <typename Executor>
bool LoggingAsyncDestinationSocket<Executor>::do_write(
    BufferBase &buffer, std::size_t length,
    std::function<void(system::error_code, std::size_t)> handler) {
  return AsyncDestinationSocket<Executor>::do_write(
      buffer, length,
      [this, handler](system::error_code ec, std::size_t length) {
        m_bytesWritten.fetch_add(length, std::memory_order_relaxed);
        handler(ec, length);
      });
}

LoggingProxyServer::LoggingProxyServer(io_context &ioc,
                                       const std::string &listen_addr,
                                       std::uint16_t listen_port)
    : ProxyServer(ioc, listen_addr, listen_port), m_statusLogger(ioc),
      m_bytesRead{0}, m_bytesWritten{0} {}

void LoggingProxyServer::start() {
  {
    std::lock_guard log_mtx{g_loggingMutex};
    std::cout << "LoggingProxyServer::start()\n";
  }
  ProxyServer::start();
  async_timer();
}

void LoggingProxyServer::stop() {
  {
    std::lock_guard log_mtx{g_loggingMutex};
    std::cout << "LoggingProxyServer::stop()\n";
  }
  ProxyServer::stop();
  m_statusLogger.cancel();
}

void LoggingProxyServer::async_timer() {
  m_statusLogger.expires_from_now(boost::posix_time::seconds(1));
  m_statusLogger.async_wait([this](const system::error_code &ec) {
    if (ec) {
      {
        std::lock_guard log_mtx{g_loggingMutex};
        std::cout << "LoggingProxyServer::async_timer() ERROR: " << ec << "\n";
      }
      return;
    }

    std::size_t total_ds = 0;
    for (const auto &weak_ds : m_weakDestinationSockets) {
      auto shared_ds = weak_ds.lock();
      if (!shared_ds)
        continue;
      total_ds++;
      m_bytesRead += shared_ds->get_bytes_read();
      m_bytesWritten += shared_ds->get_bytes_written();
    }
    m_weakDestinationSockets.erase(
        std::remove_if(m_weakDestinationSockets.begin(),
                       m_weakDestinationSockets.end(),
                       [](const std::weak_ptr<
                           LoggingAsyncDestinationSocket<any_io_executor>> &w) {
                         return w.expired();
                       }),
        m_weakDestinationSockets.end());
    {
      std::lock_guard log_mtx{g_loggingMutex};
      std::cout << "LoggingProxyServer::async_timer(): served "
                << m_nextSessionId.load(std::memory_order_relaxed) - 1
                << " sessions, " << total_ds << " active sessions, "
                << m_bytesRead << " bytes read, " << m_bytesWritten
                << " bytes written\n";
    }
    async_timer();
  });
}

void LoggingProxyServer::async_accept() {
  m_acceptor.async_accept(
      make_strand(m_acceptor.get_executor()),
      [this](const system::error_code &ec, tcp::socket client_socket) {
        if (!ec) {
          auto const client_endpoint = client_socket.remote_endpoint();
          {
            std::lock_guard log_mtx{g_loggingMutex};
            std::cout << "LoggingProxyServer::async_accept() ACCEPT: id "
                      << m_nextSessionId.load(std::memory_order_relaxed)
                      << " from " << client_endpoint.address().to_string()
                      << ":" << client_endpoint.port() << "\n";
          }

          auto auth_session = std::make_shared<ProxyAuth>(
              m_nextSessionId.fetch_add(1, std::memory_order_relaxed),
              std::move(client_socket));

          if (auth_session) {
            auth_session->set_session_buffer_size(BUFSIZ);
            auth_session->start([this](any_io_executor exec) {
              auto shared_ptr = std::make_shared<
                  LoggingAsyncDestinationSocket<any_io_executor>>(exec);
              std::weak_ptr<LoggingAsyncDestinationSocket<any_io_executor>>
                  weak_ptr(shared_ptr);
              m_weakDestinationSockets.push_back(weak_ptr);
              return shared_ptr;
            });
          }
        } else {
          {
            std::lock_guard log_mtx{g_loggingMutex};
            std::cout << "LoggingProxyServer::async_accept() ERROR: " << ec
                      << "\n";
          }
          return;
        }
        async_accept();
      });
}

template <typename Executor>
bool CustomProtocolAsyncDestinationSocket<Executor>::do_read(
    BufferBase &buffer,
    std::function<void(system::error_code, std::size_t)> handler) {
  buffer += {'C', 'U', 'S', 'T', 'O', 'M'};
  return AsyncDestinationSocket<Executor>::do_read(buffer, handler);
}

template <typename Executor>
bool CustomProtocolAsyncDestinationSocket<Executor>::do_write(
    BufferBase &buffer, std::size_t length,
    std::function<void(system::error_code, std::size_t)> handler) {
  buffer += {'P', 'R', 'O', 'T', 'O', 'C', 'O', 'L'};
  return AsyncDestinationSocket<Executor>::do_write(buffer, length + 8,
                                                    handler);
}

CustomProtocolProxyServer::CustomProtocolProxyServer(
    io_context &ioc, const std::string &listen_addr, std::uint16_t listen_port)
    : ProxyServer(ioc, listen_addr, listen_port) {}

void CustomProtocolProxyServer::start() { ProxyServer::start(); }

void CustomProtocolProxyServer::stop() { ProxyServer::stop(); }

void CustomProtocolProxyServer::async_accept() {
  m_acceptor.async_accept(
      make_strand(m_acceptor.get_executor()),
      [this](const system::error_code &ec, tcp::socket client_socket) {
        if (!ec) {
          auto auth_session = std::make_shared<ProxyAuth>(
              m_nextSessionId.fetch_add(1, std::memory_order_relaxed),
              std::move(client_socket));

          if (auth_session) {
            auth_session->set_session_buffer_size(BUFSIZ);
            auth_session->start([](any_io_executor exec) {
              auto aptr =
                  new CustomProtocolAsyncDestinationSocket<any_io_executor>(
                      exec);
              return std::shared_ptr<DestinationSocketBase>(std::move(aptr));
            });
          }
        }
        async_accept();
      });
}
