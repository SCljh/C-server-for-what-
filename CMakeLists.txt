cmake_minimum_required(VERSION 3.15)
project(706_middle)

set(CMAKE_CXX_STANDARD 14)

ADD_EXECUTABLE(706_middle epollsrv.cpp  commen.h Epoll.cpp Epoll.h EpollException.h Socket.cpp Socket.h SocketException.h threadpool.hpp Utils.hpp Utils.cpp)

TARGET_LINK_LIBRARIES(706_middle curl)
TARGET_LINK_LIBRARIES(706_middle pthread)
TARGET_LINK_LIBRARIES(706_middle json)
TARGET_LINK_LIBRARIES(706_middle pcap)