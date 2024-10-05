#=============================================================================
#  Copyright (c) 2022 VPROFi
#=============================================================================
# - Try load asmc (Asmc Macro Assembler) see https://documentation.help/Asmc-Macro-Assembler/
#  ASMC_ASM_TOOL - Set this variable to the location asmc64 file

if( NOT ASMC_ASM_TOOL )
    file(GLOB ASMC_ASM_TOOL "${CMAKE_CURRENT_BINARY_DIR}/tools/asmc64")
    execute_process(COMMAND sh -c "mkdir -p \"${CMAKE_CURRENT_BINARY_DIR}/tools\" && wget https://github.com/VPROFi/asmc/raw/3f6a19842cc5fdfb11b160b6e250f7b9e200fc99/bin/asmc64 -O\"${CMAKE_CURRENT_BINARY_DIR}/tools/asmc64\" 1>/dev/null 2>&1 && chmod +x \"${CMAKE_CURRENT_BINARY_DIR}/tools/asmc64\"")
    file(GLOB ASMC_ASM_TOOL "${CMAKE_CURRENT_BINARY_DIR}/tools/asmc64")
endif()

if( ASMC_ASM_TOOL )
    message(STATUS "Found Asmc: ${ASMC_ASM_TOOL}")
endif()
mark_as_advanced(ASMC_ASM_TOOL)
