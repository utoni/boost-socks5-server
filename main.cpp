#include "socks5.hpp"

#include <boost/asio/io_context.hpp>
#include <iostream>
#include <thread>

int main() {
  std::cout << "SOCKS5::ProxyServer listen on 127.0.0.1:1080\n"
            << "SOCKS5::LoggingProxyServer listen on 127.0.0.1:1081\n"
            << "SOCKS5::CustomProtocolProxyServer listen on 127.0.0.1:1082\n";

  boost::asio::io_context ioc;
  auto server = SOCKS5::ProxyServer(ioc, "127.0.0.1", 1080);
  auto logging_server = SOCKS5::LoggingProxyServer(ioc, "127.0.0.1", 1081);
  auto custom_protocol_server =
      SOCKS5::CustomProtocolProxyServer(ioc, "127.0.0.1", 1082);
  auto threads = std::vector<std::thread>();

  server.start();
  logging_server.start();
  custom_protocol_server.start();

  for (size_t i = 0; i < 4; ++i) {
    threads.emplace_back([&ioc]() { ioc.run(); });
  }
  for (size_t i = 0; i < threads.size(); ++i) {
    threads[i].join();
  }
}
