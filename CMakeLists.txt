cmake_minimum_required(VERSION 3.16)
project(mcu_ascon_secure C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(MCU_SECURE_BUILD_TESTS "Build host-side tests" ON)
option(MCU_SECURE_BUILD_EXAMPLE "Build example" ON)
option(MCU_SECURE_BUILD_EXPERIMENTAL
       "Build unaudited Experimental-AEAD-384-v0 research code" OFF)

set(ASCON_REF_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/vendor/ascon-c/crypto_aead/asconaead128/ref")

add_library(ascon_aead128 STATIC "${ASCON_REF_DIR}/aead.c")
target_include_directories(ascon_aead128
  PUBLIC "${ASCON_REF_DIR}"
  PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/vendor/ascon-c/tests")

add_library(mcu_secure STATIC src/mcu_secure.c)
target_include_directories(mcu_secure PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(mcu_secure PUBLIC ascon_aead128)

if(MCU_SECURE_BUILD_EXAMPLE)
  add_executable(mcu_secure_example example/example.c)
  target_link_libraries(mcu_secure_example PRIVATE mcu_secure)
endif()

if(MCU_SECURE_BUILD_TESTS)
  enable_testing()
  add_executable(mcu_secure_tests tests/test_mcu_secure.c)
  target_link_libraries(mcu_secure_tests PRIVATE mcu_secure)
  add_test(NAME mcu_secure_tests COMMAND mcu_secure_tests)
endif()

if(MCU_SECURE_BUILD_EXPERIMENTAL)
  add_library(experimental_aead_384 STATIC
              experimental/experimental_aead_384/experimental_aead_384.c)
  target_include_directories(experimental_aead_384
                             PUBLIC experimental/experimental_aead_384)

  if(MCU_SECURE_BUILD_TESTS)
    add_executable(experimental_aead_384_tests
                   experimental/experimental_aead_384/test_experimental_aead_384.c)
    target_link_libraries(experimental_aead_384_tests
                          PRIVATE experimental_aead_384)
    add_test(NAME experimental_aead_384_tests
             COMMAND experimental_aead_384_tests)
  endif()
endif()
