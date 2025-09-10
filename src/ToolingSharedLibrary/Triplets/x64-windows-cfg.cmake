# Only used to build flatbuffer compiler with Control Flow Guard enabled
set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE dynamic)
set(VCPKG_C_FLAGS "${VCPKG_C_FLAGS} /guard:cf")
set(VCPKG_CXX_FLAGS "${VCPKG_CXX_FLAGS} /guard:cf")
set(VCPKG_LINKER_FLAGS "${VCPKG_LINKER_FLAGS} /guard:cf /DYNAMICBASE")
set(VCPKG_PLATFORM_TOOLSET v143)
