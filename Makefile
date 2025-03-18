CXX = g++
GIT = git
CXXFLAGS = -Wall -Wextra -Iboost-asio-fastbuffer
SERVER_HDRS = socks5.hpp
SERVER_SRCS = socks5.cpp main.cpp

ifneq ($(ENABLE_SANITIZER),)
CXXFLAGS += -fsanitize=address -fsanitize=leak -fsanitize=undefined
else
ifneq ($(ENABLE_THREAD_SANITIZER),)
CXXFLAGS += -fsanitize=thread -fsanitize=undefined
endif
endif
ifneq ($(DEBUG),)
CXXFLAGS += -g #-DBOOST_ASIO_ENABLE_HANDLER_TRACKING=1
endif

all: git server

git: boost-asio-fastbuffer/fastbuffer.hpp

boost-asio-fastbuffer/fastbuffer.hpp:
	$(GIT) submodule update --init

server: boost-asio-fastbuffer/fastbuffer.hpp $(SERVER_HDRS) $(SERVER_SRCS)
	$(CXX) $(CXXFLAGS) $(SERVER_SRCS) -o $@

clean:
	rm -f server

distclean: clean
	$(GIT) submodule deinit --all --force

.PHONY: all git clean distclean
