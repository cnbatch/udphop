set(THISLIB_NAME NETCONNECTIONS)

add_library(${THISLIB_NAME} STATIC connections.cpp client.cpp server.cpp relay.cpp stun.cpp)
target_link_libraries(${THISLIB_NAME} PRIVATE SHAREDEFINES)
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(${THISLIB_NAME} PUBLIC Threads::Threads)
#target_include_directories(${THISLIB_NAME} INTERFACE networks/ PARENT_SCOPE)
