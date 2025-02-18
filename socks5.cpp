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
#include <memory>
#include <string>

using namespace SOCKS5;
using boost::asio::io_context;
using boost::asio::ip::tcp;

ProxySessionBase::ProxySessionBase(std::uint32_t session_id,
                                   tcp::socket &&client_socket,
                                   std::size_t buffer_size)
    : m_sessionId{session_id}, m_inBuf{buffer_size}, m_outBuf{buffer_size},
      m_clientSocket{std::move(client_socket)} {}

ProxySessionBase::ProxySessionBase(std::uint32_t session_id,
                                   boost::asio::ip::tcp::socket &&client_socket,
                                   StreamBuffer &&input_buffer,
                                   StreamBuffer &&output_buffer)
    : m_sessionId{session_id}, m_inBuf{std::move(input_buffer)},
      m_outBuf{std::move(output_buffer)},
      m_clientSocket{std::move(client_socket)} {}

ProxySessionAuth::ProxySessionAuth(std::uint32_t session_id,
                                   tcp::socket &&client_socket)
    : ProxySessionBase(session_id, std::move(client_socket), 32),
      m_resolver{m_clientSocket.get_executor()},
      m_destinationSocket{m_clientSocket.get_executor()} {}

void ProxySessionAuth::start() {
  boost::asio::async_read(
      m_clientSocket, +m_inBuf, boost::asio::transfer_exactly(2),
      boost::bind(&ProxySessionAuth::recv_client_greeting, shared_from_this(),
                  boost::asio::placeholders::error,
                  boost::asio::placeholders::bytes_transferred));
}

void ProxySessionAuth::recv_client_greeting(const boost::system::error_code &ec,
                                            std::size_t length) {
  if (ec || length == 0)
    return;
  m_inBuf += length;

  if (m_inBuf[0] != 0x05 || m_inBuf[1] > 0x09 || m_inBuf[1] == 0x00)
    return;
  const std::size_t expected_size = std::size_t(2) + m_inBuf[1];
  if (m_inBuf.size() < expected_size) {
    boost::asio::async_read(
        m_clientSocket, +m_inBuf, boost::asio::transfer_exactly(expected_size - m_inBuf.size()),
        boost::bind(&ProxySessionAuth::recv_client_greeting, shared_from_this(),
                    boost::asio::placeholders::error,
                    boost::asio::placeholders::bytes_transferred));
    return;
  }

  auto found_no_auth = false; // only No Authentication supported
  for (auto i = std::size_t(2); i < expected_size; ++i) {
    if (m_inBuf[i] == 0x00) {
      found_no_auth = true;
      break;
    }
  }

  m_inBuf -= expected_size;
  send_server_greeting(found_no_auth);
}

void ProxySessionAuth::send_server_greeting(bool auth_supported) {
  if (!auth_supported) {
    m_outBuf += {0x05, 0xFF};
    m_clientSocket.async_send(
        -m_outBuf,
        boost::bind(&ProxySessionAuth::handle_write, shared_from_this(),
                    boost::asio::placeholders::error,
                    boost::asio::placeholders::bytes_transferred));
    return;
  }

  m_outBuf += {0x05, 0x00};
  m_clientSocket.async_send(
      -m_outBuf,
      boost::bind(&ProxySessionAuth::handle_write, shared_from_this(),
                  boost::asio::placeholders::error,
                  boost::asio::placeholders::bytes_transferred));
  process_connection_request();
}

void ProxySessionAuth::recv_connection_request(
    const boost::system::error_code &ec, std::size_t length) {
  if (ec || length == 0)
    return;
  m_inBuf += length;

  process_connection_request();
}

void ProxySessionAuth::process_connection_request() {
  if (m_inBuf.size() < 6) {
    boost::asio::async_read(
        m_clientSocket, +m_inBuf, boost::asio::transfer_exactly(6 - m_inBuf.size()),
        boost::bind(&ProxySessionAuth::recv_connection_request,
                    shared_from_this(), boost::asio::placeholders::error,
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
        boost::asio::transfer_exactly(expected_size - m_inBuf.size()),
        boost::bind(&ProxySessionAuth::recv_connection_request,
                    shared_from_this(), boost::asio::placeholders::error,
                    boost::asio::placeholders::bytes_transferred));
    return;
  }

  const uint8_t proxy_cmd = m_inBuf[1];
  switch (m_inBuf[3]) {
  case 0x01: {
    auto ip4_bytes = ::ntohl(*reinterpret_cast<const uint32_t *>(m_inBuf(4)));
    m_endpoint = tcp::endpoint(boost::asio::ip::make_address_v4(ip4_bytes),
                               ::ntohs(*reinterpret_cast<const uint16_t *>(
                                   m_inBuf(4 + address_size))));
    connect_to_destination(proxy_cmd);
    return;
  }
  case 0x03: {
    auto host = std::string_view(reinterpret_cast<const char *>(m_inBuf(5)),
                                 address_size);
    auto port =
        ::ntohs(*reinterpret_cast<const uint16_t *>(m_inBuf(5 + address_size)));
    resolve_destination_host(proxy_cmd, host, port);
    return;
  }
  case 0x04: {
    auto ip6_array =
        *reinterpret_cast<const std::array<std::uint8_t, 16> *>(m_inBuf(4));
    m_endpoint = tcp::endpoint(boost::asio::ip::make_address_v6(ip6_array),
                               ::ntohs(*reinterpret_cast<const uint16_t *>(
                                   m_inBuf(4 + address_size))));
    connect_to_destination(proxy_cmd);
    return;
  }
  default:
    return;
  }
}

void ProxySessionAuth::send_server_response(std::uint8_t proxy_cmd,
                                            std::uint8_t status_code) {
  m_outBuf += {0x05, status_code, 0x00};
  // TODO: Set DNS domain if available
  if (m_endpoint.address().is_v4()) {
    const uint32_t addr = ::htonl(m_endpoint.address().to_v4().to_uint());
    m_outBuf += {0x01, static_cast<uint8_t>(addr & 0x000000FF),
                 static_cast<uint8_t>((addr & 0x0000FF00) >> 8),
                 static_cast<uint8_t>((addr & 0x00FF0000) >> 16),
                 static_cast<uint8_t>((addr & 0xFF000000) >> 24)};
  } else {
    m_outBuf += {0x04};
    const auto addr = m_endpoint.address().to_v6().to_bytes();
    for (const auto byte : addr)
      m_outBuf += {byte};
  }
  const auto port = ::htons(m_endpoint.port());
  m_outBuf += {static_cast<uint8_t>(port & 0x00FF),
               static_cast<uint8_t>((port & 0xFF00) >> 8)};
  m_clientSocket.async_send(
      -m_outBuf,
      boost::bind(&ProxySessionAuth::handle_response_write, shared_from_this(),
                  proxy_cmd, status_code, boost::asio::placeholders::error,
                  boost::asio::placeholders::bytes_transferred));
}

void ProxySessionAuth::resolve_destination_host(std::uint8_t proxy_cmd,
                                                const std::string_view &host,
                                                std::uint16_t port) {
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
                             m_endpoint = *it;
                             connect_to_destination(proxy_cmd);
                           });
}

void ProxySessionAuth::connect_to_destination(std::uint8_t proxy_cmd) {
  switch (proxy_cmd) {
  case 0x01: // TCP client connection
  {
    m_destinationSocket.async_connect(
        m_endpoint,
        [this, self = shared_from_this(), proxy_cmd](const boost::system::error_code &ec) {
          if (ec) {
            send_server_response(proxy_cmd, 0x04);
            return;
          }
          send_server_response(proxy_cmd, 0x00);
        });
    return;
  }
  case 0x02: // TCP port bind
  {
    send_server_response(proxy_cmd, 0x02);
    return;
  }
  case 0x03: // UDP port bind
  {
    send_server_response(proxy_cmd, 0x02);
    return;
  }
  default:
    send_server_response(proxy_cmd, 0x01);
    return;
  }
}

void ProxySessionAuth::handle_write(const boost::system::error_code &ec,
                                    std::size_t length) {
  if (ec || length == 0)
    m_clientSocket.cancel();
  m_outBuf -= length;

  if (m_outBuf.size() > 0)
    m_clientSocket.async_send(
        -m_outBuf,
        boost::bind(&ProxySessionAuth::handle_write, shared_from_this(),
                    boost::asio::placeholders::error,
                    boost::asio::placeholders::bytes_transferred));
}

void ProxySessionAuth::handle_response_write(
    std::uint8_t proxy_cmd, std::uint8_t status_code,
    const boost::system::error_code &ec, std::size_t length) {
  if (ec || length == 0)
    m_clientSocket.cancel();
  m_outBuf -= length;

  if (m_outBuf.size() > 0) {
    m_clientSocket.async_send(
        -m_outBuf, boost::bind(&ProxySessionAuth::handle_response_write,
                               shared_from_this(), proxy_cmd, status_code,
                               boost::asio::placeholders::error,
                               boost::asio::placeholders::bytes_transferred));
    return;
  }

  if (status_code == 0x00)
    switch (proxy_cmd) {
    case 0x01: // TCP client connection
    {
      auto tcp_session = std::make_shared<ProxySessionTcp>(
          m_sessionId, std::move(m_clientSocket),
          std::move(m_destinationSocket));
      tcp_session->start();
      break;
    }
    case 0x02: // TCP port bind
    {
      return;
    }
    case 0x03: // UDP port bind
    {
      return;
    }
    default:
      return;
    }
}

ProxySessionTcp::ProxySessionTcp(
    std::uint32_t session_id, boost::asio::ip::tcp::socket &&client_socket,
    boost::asio::ip::tcp::socket &&destination_socket, std::size_t buffer_size)
    : ProxySessionBase(session_id, std::move(client_socket), buffer_size),
      m_destinationSocket(std::move(destination_socket)) {}

void ProxySessionTcp::start() { recv_from_both(); }

void ProxySessionTcp::recv_from_both() {
  BOOST_ASIO_HANDLER_LOCATION((__FILE__, __LINE__, __func__));

  m_clientSocket.async_read_some(
      +m_inBuf,
      boost::bind(&ProxySessionTcp::recv_from_client, shared_from_this(),
                  boost::asio::placeholders::error,
                  boost::asio::placeholders::bytes_transferred));
  m_destinationSocket.async_read_some(
      +m_outBuf,
      boost::bind(&ProxySessionTcp::recv_from_destination, shared_from_this(),
                  boost::asio::placeholders::error,
                  boost::asio::placeholders::bytes_transferred));
}

void ProxySessionTcp::recv_from_destination(const boost::system::error_code &ec,
                                            std::size_t length) {
  BOOST_ASIO_HANDLER_LOCATION((__FILE__, __LINE__, __func__));

  if (ec || length == 0) {
    m_destinationSocket.cancel();
    return;
  }

  m_outBuf += length;
  boost::asio::async_write(
      m_clientSocket, -m_outBuf, boost::asio::transfer_all(),
      boost::bind(&ProxySessionTcp::handle_client_write, shared_from_this(),
                  boost::asio::placeholders::error,
                  boost::asio::placeholders::bytes_transferred));
}

void ProxySessionTcp::recv_from_client(const boost::system::error_code &ec,
                                       std::size_t length) {
  BOOST_ASIO_HANDLER_LOCATION((__FILE__, __LINE__, __func__));

  if (ec || length == 0) {
    m_destinationSocket.cancel();
    return;
  }

  m_inBuf += length;
  boost::asio::async_write(
      m_destinationSocket, -m_inBuf, boost::asio::transfer_exactly(length),
      boost::bind(&ProxySessionTcp::handle_destination_write,
                  shared_from_this(), boost::asio::placeholders::error,
                  boost::asio::placeholders::bytes_transferred));
}

void ProxySessionTcp::handle_client_write(const boost::system::error_code &ec,
                                          std::size_t length) {
  BOOST_ASIO_HANDLER_LOCATION((__FILE__, __LINE__, __func__));

  if (ec || length == 0) {
    m_clientSocket.cancel();
    return;
  }

  m_outBuf -= length;
  m_destinationSocket.async_read_some(
      +m_outBuf,
      boost::bind(&ProxySessionTcp::recv_from_destination, shared_from_this(),
                  boost::asio::placeholders::error,
                  boost::asio::placeholders::bytes_transferred));
}

void ProxySessionTcp::handle_destination_write(
    const boost::system::error_code &ec, std::size_t length) {
  BOOST_ASIO_HANDLER_LOCATION((__FILE__, __LINE__, __func__));

  if (ec || length == 0) {
    m_destinationSocket.cancel();
    return;
  }

  m_inBuf -= length;
  m_clientSocket.async_read_some(
      +m_inBuf,
      boost::bind(&ProxySessionTcp::recv_from_client, shared_from_this(),
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

void ProxyServer::async_accept() {
  m_acceptor.async_accept(
      boost::asio::make_strand(m_acceptor.get_executor()),
      [this](const boost::system::error_code &ec, tcp::socket client_socket) {
        if (!ec) {
          auto auth_session = std::make_shared<ProxySessionAuth>(
              m_nextSessionId.fetch_add(1, std::memory_order_relaxed),
              std::move(client_socket));
          if (auth_session)
            auth_session->start();
        }
        async_accept();
      });
}
