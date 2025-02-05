#include "socks5.hpp"

#include <boost/asio/io_context.hpp>
#include <thread>

int main() {
  boost::asio::io_context ioc;
  auto server = SOCKS5::ProxyServer(ioc, "127.0.0.1", 1080);
  auto threads = std::vector<std::thread>();

  server.start();
  for (size_t i = 0; i < 4; ++i) {
    threads.emplace_back([&ioc]() { ioc.run(); });
  }
  for (size_t i = 0; i < threads.size(); ++i) {
    threads[i].join();
  }
}
