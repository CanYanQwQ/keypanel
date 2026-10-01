cmake_minimum_required(VERSION 3.21)
project(cardkey_cpp_qt LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 6.4 REQUIRED COMPONENTS Core Network)
find_package(OpenSSL 3 REQUIRED COMPONENTS Crypto)
find_package(Qt6 6.4 QUIET COMPONENTS Test)

add_library(cardkey_client
    src/cardkey_client.cpp
    src/signer.cpp
    src/transport_crypto.cpp
)
target_include_directories(cardkey_client PUBLIC include)
target_link_libraries(cardkey_client PUBLIC Qt6::Core Qt6::Network OpenSSL::Crypto)

add_executable(cardkey_example src/main.cpp)
target_link_libraries(cardkey_example PRIVATE cardkey_client)

if (TARGET Qt6::Test)
    enable_testing()
    add_executable(cardkey_protocol_test tests/protocol_vector_test.cpp)
    target_link_libraries(cardkey_protocol_test PRIVATE cardkey_client Qt6::Test)
    add_test(NAME cardkey_protocol_test COMMAND cardkey_protocol_test)
endif()
