cmake_minimum_required(VERSION 3.16)
project(eshop_linux_port LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

option(ESHOP_SANITIZE "Build with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)
option(ESHOP_WITH_SDL "Build the windowed frontend (requires SDL2 or SDL3)" ON)

add_compile_options(-Wall -Wextra)
if(ESHOP_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address,undefined)
endif()

# Layer 1: recovered / reconstructed original eShop code (no platform dependencies).
add_library(eshop_original STATIC src/original/eshop_runtime.cpp)
target_include_directories(eshop_original PUBLIC include)

# Layer 2: platform-neutral port code (3DS compatibility layer, screens, input).
add_library(eshop_port STATIC
  src/compatibility/ctr_compat.cpp
  src/graphics/dual_screen.cpp
  src/input/input_map.cpp
  src/application/app.cpp)
target_include_directories(eshop_port PUBLIC include)
target_link_libraries(eshop_port PUBLIC eshop_original)

# Layer 3: executable + SDL frontend.
add_executable(eshop src/main.cpp)
target_link_libraries(eshop PRIVATE eshop_port)
if(ESHOP_WITH_SDL)
  find_package(SDL3 QUIET CONFIG)
  if(TARGET SDL3::SDL3)
    message(STATUS "Using SDL3")
    target_compile_definitions(eshop PRIVATE ESHOP_SDL=3)
    target_link_libraries(eshop PRIVATE SDL3::SDL3)
  else()
    find_package(SDL2 QUIET CONFIG)
    if(TARGET SDL2::SDL2)
      message(STATUS "SDL3 not found; falling back to SDL2")
      target_compile_definitions(eshop PRIVATE ESHOP_SDL=2)
      target_link_libraries(eshop PRIVATE SDL2::SDL2)
    else()
      message(WARNING "No SDL found: building headless-only")
    endif()
  endif()
endif()

enable_testing()
add_executable(test_original_vectors tests/test_original_vectors.cpp)
target_link_libraries(test_original_vectors PRIVATE eshop_original)
add_test(NAME original_vs_arm_oracle
         COMMAND test_original_vectors ${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors)
add_executable(test_port tests/test_port.cpp)
target_link_libraries(test_port PRIVATE eshop_port)
add_test(NAME port_layout_input COMMAND test_port)
