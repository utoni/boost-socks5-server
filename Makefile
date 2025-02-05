CXX = g++
CXXFLAGS = -Wall -Wextra
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

all: server

server: $(SERVER_HDRS) $(SERVER_SRCS)
	$(CXX) $(CXXFLAGS) $(SERVER_SRCS) -o $@

clean:
	rm -f server

.PHONY: clean
