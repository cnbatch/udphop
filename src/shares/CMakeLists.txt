set(THISLIB_NAME SHAREDEFINES)

add_library(${THISLIB_NAME} STATIC share_defines.cpp configurations.cpp data_operations.cpp)

#target_include_directories(${THISLIB_NAME} PUBLIC shares/ PARENT_SCOPE)

