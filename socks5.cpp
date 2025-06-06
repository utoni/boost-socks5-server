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
#include <string>

using namespace SOCKS5;
using boost::asio::io_context;
using boost::asio::ip::tcp;
using boost::asio::ip::udp;

template <typename Executor>
void AsyncDestinationSocket<Executor>::do_connect_tcp(
    boost::asio::ip::address &address, uint16_t port,
    std::function<void(boost::system::error_code)> handler) {
  m_socket.emplace(boost::asio::ip::tcp::socket(m_strand));
  auto &tcp_socket = boost::get<boost::asio::ip::tcp::socket>(*m_socket);
  boost::asio::ip::tcp::endpoint endpoint(address, port);
  tcp_socket.async_connect(endpoint, std::move(handler));
}

template <typename Executor>
void AsyncDestinationSocket<Executor>::do_bind_tcp(
    boost::asio::ip::address &, uint16_t,
    std::function<void(boost::system::error_code)>) {
  throw std::runtime_error("TCP Bind not implemented");
}

template <typename Executor>
void AsyncDestinationSocket<Executor>::do_bind_udp(
    boost::asio::ip::address &, uint16_t,
    std::function<void(boost::system::error_code)>) {
  throw std::runtime_error("UDP Bind not implemented");
}

template <typename Executor>
bool AsyncDestinationSocket<Executor>::do_read(
    boost::asio::mutable_buffer buffer,
    std::function<void(boost::system::error_code, std::size_t)> handler) {
  if (m_socket) {
    if (auto *s = boost::get<boost::asio::ip::tcp::socket>(&*m_socket)) {
      s->async_read_some(buffer, std::move(handler));
      return true;
    }
  }
  return false;
};

template <typename Executor>
bool AsyncDestinationSocket<Executor>::do_write(
    boost::asio::mutable_buffer buffer, std::size_t length,
    std::function<void(boost::system::error_code, std::size_t)> handler) {
  if (m_socket) {
    if (auto *s = boost::get<boost::asio::ip::tcp::socket>(&*m_socket)) {
      boost::asio::async_write(*s, buffer,
                               boost::asio::transfer_exactly(length),
                               std::move(handler));
      return true;
    }
  }
  return false;
};

template <typename Executor> bool AsyncDestinationSocket<Executor>::cancel() {
  if (m_socket) {
    if (auto *s = boost::get<boost::asio::ip::tcp::socket>(&*m_socket)) {
      s->cancel();
      return true;
    } else if (auto *s = boost::get<boost::asio::ip::udp::socket>(&*m_socket)) {
      s->cancel();
      return true;
    } else if (auto *s =
                   boost::get<boost::asio::ip::tcp::acceptor>(&*m_socket)) {
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

ProxyBase::ProxyBase(std::uint32_t session_id,
                     boost::asio::ip::tcp::socket &&client_socket,
                     ContiguousStreamBuffer &&input_buffer,
                     ContiguousStreamBuffer &&output_buffer)
    : m_sessionId{session_id}, m_inBuf{std::move(input_buffer)},
      m_outBuf{std::move(output_buffer)},
      m_clientSocket{std::move(client_socket)} {}

ProxyAuth::ProxyAuth(std::uint32_t session_id, tcp::socket &&client_socket)
    : ProxyBase(session_id, std::move(client_socket), 512),
      m_resolver{m_clientSocket.get_executor()} {}

void ProxyAuth::start_internal() {
  BOOST_ASIO_HANDLER_LOCATION((__FILE__, __LINE__, __func__));

  boost::asio::async_read(
      m_clientSocket, +m_inBuf, boost::asio::transfer_at_least(2),
      boost::bind(&ProxyAuth::recv_client_greeting, shared_from_this(),
                  boost::asio::placeholders::error,
                  boost::asio::placeholders::bytes_transferred));
}

void ProxyAuth::recv_client_greeting(const boost::system::error_code &ec,
                                     std::size_t length) {
  BOOST_ASIO_HANDLER_LOCATION((__FILE__, __LINE__, __func__));

  if (ec || length == 0)
    return;
  m_inBuf += length;

  if (m_inBuf[0] != 0x05 || m_inBuf[1] > 0x09 || m_inBuf[1] == 0x00)
    return;
  const std::size_t expected_size = std::size_t(2) + m_inBuf[1];
  if (m_inBuf.size() < expected_size) {
    boost::asio::async_read(
        m_clientSocket, +m_inBuf,
        boost::asio::transfer_at_least(expected_size - m_inBuf.size()),
        boost::bind(&ProxyAuth::recv_client_greeting, shared_from_this(),
                    boost::asio::placeholders::error,
                    boost::asio::placeholders::bytes_transferred));
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
                               boost::asio::placeholders::error,
                               boost::asio::placeholders::bytes_transferred));
    return;
  }

  m_outBuf += {0x05, 0x00};
  m_clientSocket.async_send(
      -m_outBuf, boost::bind(&ProxyAuth::handle_write, shared_from_this(),
                             boost::asio::placeholders::error,
                             boost::asio::placeholders::bytes_transferred));
  process_connection_request();
}

void ProxyAuth::recv_connection_request(const boost::system::error_code &ec,
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
    boost::asio::async_read(
        m_clientSocket, +m_inBuf,
        boost::asio::transfer_at_least(6 - m_inBuf.size()),
        boost::bind(&ProxyAuth::recv_connection_request, shared_from_this(),
                    boost::asio::placeholders::error,
                    boost::asio::placeholders::bytes_transferred));
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
    boost::asio::async_read(
        m_clientSocket, +m_inBuf,
        boost::asio::transfer_at_least(expected_size - m_inBuf.size()),
        boost::bind(&ProxyAuth::recv_connection_request, shared_from_this(),
                    boost::asio::placeholders::error,
                    boost::asio::placeholders::bytes_transferred));
    return;
  }

  const uint8_t proxy_cmd = m_inBuf[1];
  switch (m_inBuf[3]) {
  case 0x01: {
    auto ip4_bytes = ::ntohl(*reinterpret_cast<const uint32_t *>(m_inBuf(4)));
    m_destinationAddress = boost::asio::ip::make_address_v4(ip4_bytes);
    m_destinationPort =
        ::ntohs(*reinterpret_cast<const uint16_t *>(m_inBuf(4 + address_size)));
    connect_to_destination(proxy_cmd);
    break;
  }
  case 0x03: {
    auto host = std::string_view(reinterpret_cast<const char *>(m_inBuf(5)),
                                 address_size);
    auto port =
        ::ntohs(*reinterpret_cast<const uint16_t *>(m_inBuf(5 + address_size)));
    resolve_destination_host(proxy_cmd, host, port);
    break;
  }
  case 0x04: {
    auto ip6_array =
        *reinterpret_cast<const std::array<std::uint8_t, 16> *>(m_inBuf(4));
    m_destinationAddress = boost::asio::ip::make_address_v6(ip6_array);
    m_destinationPort =
        ::ntohs(*reinterpret_cast<const uint16_t *>(m_inBuf(4 + address_size)));
    connect_to_destination(proxy_cmd);
    break;
  }
  default:
    return;
  }

  m_inBuf -= expected_size;
}

void ProxyAuth::send_server_response(std::uint8_t proxy_cmd,
                                     std::uint8_t status_code) {
  BOOST_ASIO_HANDLER_LOCATION((__FILE__, __LINE__, __func__));

  m_outBuf += {0x05, status_code, 0x00};
  // TODO: Set DNS domain if available
  if (m_destinationAddress.is_v4()) {
    const uint32_t addr = ::htonl(m_destinationAddress.to_v4().to_uint());
    m_outBuf += {0x01, static_cast<uint8_t>(addr & 0x000000FF),
                 static_cast<uint8_t>((addr & 0x0000FF00) >> 8),
                 static_cast<uint8_t>((addr & 0x00FF0000) >> 16),
                 static_cast<uint8_t>((addr & 0xFF000000) >> 24)};
  } else {
    m_outBuf += {0x04};
    const auto addr = m_destinationAddress.to_v6().to_bytes();
    for (const auto byte : addr)
      m_outBuf += {byte};
  }
  const auto port = ::htons(m_destinationPort);
  m_outBuf += {static_cast<uint8_t>(port & 0x00FF),
               static_cast<uint8_t>((port & 0xFF00) >> 8)};
  m_clientSocket.async_send(
      -m_outBuf,
      boost::bind(&ProxyAuth::handle_response_write, shared_from_this(),
                  proxy_cmd, status_code, boost::asio::placeholders::error,
                  boost::asio::placeholders::bytes_transferred));
}

void ProxyAuth::resolve_destination_host(std::uint8_t proxy_cmd,
                                         const std::string_view &host,
                                         std::uint16_t port) {
  BOOST_ASIO_HANDLER_LOCATION((__FILE__, __LINE__, __func__));

  m_resolver.async_resolve(host, std::to_string(port),
                           [this, self = shared_from_this(),
                            proxy_cmd](const boost::system::error_code &ec,
                                       const tcp::resolver::iterator &it) {
                             if (ec) {
                               send_server_response(proxy_cmd, 0x04);
                               return;
                             }
                             /* TODO: Support iterating and connecting to
                              * multiple resolved hosts on failure. */
                             auto endpoint = it->endpoint();
                             m_destinationAddress = endpoint.address();
                             m_destinationPort = endpoint.port();
                             connect_to_destination(proxy_cmd);
                           });
}

void ProxyAuth::connect_to_destination(std::uint8_t proxy_cmd) {
  BOOST_ASIO_HANDLER_LOCATION((__FILE__, __LINE__, __func__));

  const auto check_error = [this,
                            proxy_cmd](const boost::system::error_code &ec) {
    if (ec) {
      if (ec == boost::system::errc::connection_refused)
        send_server_response(proxy_cmd, 0x05);
      else if (ec == boost::system::errc::network_unreachable)
        send_server_response(proxy_cmd, 0x03);
      else if (ec == boost::system::errc::host_unreachable)
        send_server_response(proxy_cmd, 0x04);
      else
        send_server_response(proxy_cmd, 0x01);
      return;
    }
    send_server_response(proxy_cmd, 0x00);
  };

  auto ds_result = m_getDestinationSocket(m_clientSocket.get_executor());
  if (!ds_result) {
    send_server_response(proxy_cmd, 0x01);
    return;
  }
  m_destinationSocket = std::move(ds_result);

  switch (proxy_cmd) {
  case 0x01: // TCP client connection
  {
    m_destinationSocket->connect_tcp(
        m_destinationAddress, m_destinationPort,
        [this, self = shared_from_this(), check_error,
         proxy_cmd](const boost::system::error_code &ec) { check_error(ec); });
    return;
  }
  case 0x02: // TCP port bind
  {
    m_destinationSocket->tcp_bind(
        m_destinationAddress, m_destinationPort,
        [this, self = shared_from_this(), check_error,
         proxy_cmd](const boost::system::error_code &ec) { check_error(ec); });
    return;
  }
  case 0x03: // UDP port bind
  {
    m_destinationSocket->udp_bind(
        m_destinationAddress, m_destinationPort,
        [this, self = shared_from_this(), check_error,
         proxy_cmd](const boost::system::error_code &ec) { check_error(ec); });
    return;
  }
  default:
    send_server_response(proxy_cmd, 0x01);
    return;
  }
}

void ProxyAuth::handle_write(const boost::system::error_code &ec,
                             std::size_t length) {
  BOOST_ASIO_HANDLER_LOCATION((__FILE__, __LINE__, __func__));

  if (ec || length == 0)
    m_clientSocket.cancel();
  m_outBuf -= length;

  if (m_outBuf.size() > 0)
    m_clientSocket.async_send(
        -m_outBuf, boost::bind(&ProxyAuth::handle_write, shared_from_this(),
                               boost::asio::placeholders::error,
                               boost::asio::placeholders::bytes_transferred));
}

void ProxyAuth::handle_response_write(std::uint8_t proxy_cmd,
                                      std::uint8_t status_code,
                                      const boost::system::error_code &ec,
                                      std::size_t length) {
  BOOST_ASIO_HANDLER_LOCATION((__FILE__, __LINE__, __func__));

  if (ec || length == 0)
    m_clientSocket.cancel();
  m_outBuf -= length;

  if (m_outBuf.size() > 0) {
    m_clientSocket.async_send(
        -m_outBuf,
        boost::bind(&ProxyAuth::handle_response_write, shared_from_this(),
                    proxy_cmd, status_code, boost::asio::placeholders::error,
                    boost::asio::placeholders::bytes_transferred));
    return;
  }

  if (status_code == 0x00) {
    auto session = std::make_shared<ProxySession>(
        m_sessionId, std::move(m_clientSocket), std::move(m_destinationSocket),
        std::move(m_inBuf), std::move(m_outBuf));
    if (!session) {
      m_clientSocket.cancel();
      return;
    }
    session->start();
  }
}

ProxySession::ProxySession(std::uint32_t session_id,
                           boost::asio::ip::tcp::socket &&client_socket,
                           std::shared_ptr<DestinationSocketBase> &&dest_socket,
                           std::size_t buffer_size)
    : ProxyBase(session_id, std::move(client_socket), buffer_size),
      m_destinationSocket(std::move(dest_socket)) {}

ProxySession::ProxySession(std::uint32_t session_id,
                           boost::asio::ip::tcp::socket &&client_socket,
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
                            boost::asio::placeholders::error,
                            boost::asio::placeholders::bytes_transferred));
  m_destinationSocket->read(
      +m_outBuf,
      boost::bind(&ProxySession::recv_from_destination, shared_from_this(),
                  boost::asio::placeholders::error,
                  boost::asio::placeholders::bytes_transferred));
}

void ProxySession::recv_from_destination(const boost::system::error_code &ec,
                                         std::size_t length) {
  BOOST_ASIO_HANDLER_LOCATION((__FILE__, __LINE__, __func__));

  if (ec || length == 0) {
    m_destinationSocket->cancel();
    return;
  }

  m_outBuf += length;
  boost::asio::async_write(
      m_clientSocket, -m_outBuf, boost::asio::transfer_all(),
      boost::bind(&ProxySession::handle_client_write, shared_from_this(),
                  boost::asio::placeholders::error,
                  boost::asio::placeholders::bytes_transferred));
}

void ProxySession::recv_from_client(const boost::system::error_code &ec,
                                    std::size_t length) {
  BOOST_ASIO_HANDLER_LOCATION((__FILE__, __LINE__, __func__));

  if (ec || length == 0) {
    m_destinationSocket->cancel();
    return;
  }

  m_inBuf += length;
  m_destinationSocket->write(
      -m_inBuf, length,
      boost::bind(&ProxySession::handle_destination_write, shared_from_this(),
                  boost::asio::placeholders::error,
                  boost::asio::placeholders::bytes_transferred));
}

void ProxySession::handle_client_write(const boost::system::error_code &ec,
                                       std::size_t length) {
  BOOST_ASIO_HANDLER_LOCATION((__FILE__, __LINE__, __func__));

  if (ec || length == 0) {
    m_clientSocket.cancel();
    return;
  }

  m_outBuf -= length;
  m_destinationSocket->read(
      +m_outBuf,
      boost::bind(&ProxySession::recv_from_destination, shared_from_this(),
                  boost::asio::placeholders::error,
                  boost::asio::placeholders::bytes_transferred));
}

void ProxySession::handle_destination_write(const boost::system::error_code &ec,
                                            std::size_t length) {
  BOOST_ASIO_HANDLER_LOCATION((__FILE__, __LINE__, __func__));

  if (ec || length == 0) {
    m_destinationSocket->cancel();
    return;
  }

  m_inBuf -= length;
  m_clientSocket.async_read_some(
      +m_inBuf, boost::bind(&ProxySession::recv_from_client, shared_from_this(),
                            boost::asio::placeholders::error,
                            boost::asio::placeholders::bytes_transferred));
}

ProxyServer::ProxyServer(io_context &ioc, const tcp::endpoint &local_endpoint)
    : m_nextSessionId{1}, m_acceptor(ioc, local_endpoint) {}

ProxyServer::ProxyServer(io_context &ioc, const std::string &listen_addr,
                         std::uint16_t listen_port)
    : ProxyServer(ioc, tcp::endpoint(boost::asio::ip::make_address(listen_addr),
                                     listen_port)) {}

void ProxyServer::start() { async_accept(); }

void ProxyServer::stop() { m_acceptor.cancel(); }

void ProxyServer::async_accept() {
  m_acceptor.async_accept(
      boost::asio::make_strand(m_acceptor.get_executor()),
      [this](const boost::system::error_code &ec, tcp::socket client_socket) {
        if (!ec) {
          auto auth_session = std::make_shared<ProxyAuth>(
              m_nextSessionId.fetch_add(1, std::memory_order_relaxed),
              std::move(client_socket));

          if (auth_session) {
            auth_session->start([](boost::asio::any_io_executor exec) {
              auto aptr =
                  new AsyncDestinationSocket<boost::asio::any_io_executor>(
                      exec);
              return std::shared_ptr<DestinationSocketBase>(std::move(aptr));
            });
          }
        }
        async_accept();
      });
}

template <typename Executor>
void LoggingAsyncDestinationSocket<Executor>::do_connect_tcp(
    boost::asio::ip::address &address, uint16_t port,
    std::function<void(boost::system::error_code)> handler) {
  std::cout << "LoggingProxyServer::do_connect_tcp(): " << address.to_string()
            << ":" << port << "\n";
  AsyncDestinationSocket<Executor>::do_connect_tcp(address, port, handler);
}

template <typename Executor>
void LoggingAsyncDestinationSocket<Executor>::do_bind_tcp(
    boost::asio::ip::address &address, uint16_t port,
    std::function<void(boost::system::error_code)> handler) {
  std::cout << "LoggingProxyServer::do_bind_tcp(): " << address.to_string()
            << ":" << port << "\n";
  AsyncDestinationSocket<Executor>::do_bind_tcp(address, port, handler);
}

template <typename Executor>
void LoggingAsyncDestinationSocket<Executor>::do_bind_udp(
    boost::asio::ip::address &address, uint16_t port,
    std::function<void(boost::system::error_code)> handler) {
  std::cout << "LoggingProxyServer::do_bind_udp(): " << address.to_string()
            << ":" << port << "\n";
  AsyncDestinationSocket<Executor>::do_bind_udp(address, port, handler);
}

template <typename Executor>
bool LoggingAsyncDestinationSocket<Executor>::do_read(
    boost::asio::mutable_buffer buffer,
    std::function<void(boost::system::error_code, std::size_t)> handler) {
  return AsyncDestinationSocket<Executor>::do_read(
      buffer,
      [this, handler](boost::system::error_code ec, std::size_t length) {
        m_bytesRead.fetch_add(length, std::memory_order_relaxed);
        handler(ec, length);
      });
}

template <typename Executor>
bool LoggingAsyncDestinationSocket<Executor>::do_write(
    boost::asio::mutable_buffer buffer, std::size_t length,
    std::function<void(boost::system::error_code, std::size_t)> handler) {
  return AsyncDestinationSocket<Executor>::do_write(
      buffer, length,
      [this, handler](boost::system::error_code ec, std::size_t length) {
        m_bytesWritten.fetch_add(length, std::memory_order_relaxed);
        handler(ec, length);
      });
}

LoggingProxyServer::LoggingProxyServer(boost::asio::io_context &ioc,
                                       const std::string &listen_addr,
                                       std::uint16_t listen_port)
    : ProxyServer(ioc, listen_addr, listen_port), m_statusLogger(ioc),
      m_bytesRead{0}, m_bytesWritten{0} {}

void LoggingProxyServer::start() {
  std::cout << "LoggingProxyServer::start()\n";
  ProxyServer::start();
  async_timer();
}

void LoggingProxyServer::stop() {
  std::cout << "LoggingProxyServer::stop()\n";
  ProxyServer::stop();
  m_statusLogger.cancel();
}

void LoggingProxyServer::async_timer() {
  m_statusLogger.expires_from_now(boost::posix_time::seconds(1));
  m_statusLogger.async_wait([this](const boost::system::error_code &ec) {
    if (ec) {
      std::cout << "LoggingProxyServer::async_timer() ERROR: " << ec << "\n";
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
        std::remove_if(
            m_weakDestinationSockets.begin(), m_weakDestinationSockets.end(),
            [](const std::weak_ptr<LoggingAsyncDestinationSocket<
                   boost::asio::any_io_executor>> &w) { return w.expired(); }),
        m_weakDestinationSockets.end());
    std::cout << "LoggingProxyServer::async_timer(): served "
              << m_nextSessionId.load(std::memory_order_relaxed) - 1
              << " sessions, " << total_ds << " active sessions, "
              << m_bytesRead << " bytes read, " << m_bytesWritten
              << " bytes written\n";
    async_timer();
  });
}

void LoggingProxyServer::async_accept() {
  m_acceptor.async_accept(
      boost::asio::make_strand(m_acceptor.get_executor()),
      [this](const boost::system::error_code &ec, tcp::socket client_socket) {
        if (!ec) {
          auto const client_endpoint = client_socket.remote_endpoint();
          std::cout << "LoggingProxyServer::async_accept() ACCEPT: id "
                    << m_nextSessionId.load(std::memory_order_relaxed)
                    << " from " << client_endpoint.address().to_string() << ":"
                    << client_endpoint.port() << "\n";

          auto auth_session = std::make_shared<ProxyAuth>(
              m_nextSessionId.fetch_add(1, std::memory_order_relaxed),
              std::move(client_socket));

          if (auth_session) {
            auth_session->start([this](boost::asio::any_io_executor exec) {
              auto shared_ptr = std::make_shared<
                  LoggingAsyncDestinationSocket<boost::asio::any_io_executor>>(
                  exec);
              std::weak_ptr<
                  LoggingAsyncDestinationSocket<boost::asio::any_io_executor>>
                  weak_ptr(shared_ptr);
              m_weakDestinationSockets.push_back(weak_ptr);
              return shared_ptr;
            });
          }
        } else {
          std::cout << "LoggingProxyServer::async_accept() ERROR: " << ec
                    << "\n";
          return;
        }
        async_accept();
      });
}
