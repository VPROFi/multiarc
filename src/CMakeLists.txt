cmake_minimum_required(VERSION 3.0.2)

project(multiarc)

set(PROJECT_SOURCE_DIR ${FAR_SOURCE_DIR})
get_directory_property(INSTALL_DIR DIRECTORY ${PROJECT_SOURCE_DIR} DEFINITION INSTALL_DIR)

message("multiarc PROJECT_SOURCE_DIR ${PROJECT_SOURCE_DIR} ${CMAKE_SYSTEM_NAME} INSTALL_DIR ${INSTALL_DIR}")

message(STATUS "MULTIARC plugin enabled")
# workaround for brew's/macports' libarchive
if(IS_DIRECTORY "/usr/local/opt/libarchive/include")
    set(LibArchive_INCLUDE_DIR "/usr/local/opt/libarchive/include")
    set(LibArchive_LIBRARY "/usr/local/opt/libarchive/lib/libarchive.dylib")
elseif(EXISTS "/opt/local/lib/libarchive.dylib")
    set(LibArchive_LIBRARY "/opt/local/lib/libarchive.dylib")
endif()

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/tools)

set(ColorNormal "${Esc}[m")
set(ColorRed "${Esc}[1;31m")
find_package(LibArchive)
if(NOT LibArchive_FOUND)
    message(WARNING "${ColorRed}libarchive not found, multiarc will have weaker archives support. Its recommended to install libarchive-dev and reconfigure far2l.${ColorNormal}")
endif()

find_package(PCRE)
if(NOT PCRE_FOUND)
    message(WARNING "${ColorRed}libpcre not found, multiarc will have no custom archives support. Install libpcre and reconfigure far2l if you need that functionality.${ColorNormal}")
endif()


set(SOURCES
    src/MultiArc.cpp
    src/ArcPlg.cpp
    src/arccfg.cpp
    src/arcget.cpp
    src/arcput.cpp
    src/ArcMix.cpp
    src/ArcProc.cpp
    src/global.cpp
    src/arcread.cpp
    src/arccmd.cpp
    src/formats/rar/rar.cpp
    src/formats/ha/ha.cpp
    src/formats/arj/arj.cpp
    src/formats/ace/ace.cpp
    src/formats/arc/arc.cpp
    src/formats/zip/zip.cpp
    src/formats/lzh/lzh.cpp
    src/formats/rar/unrar/scantree.cpp
    src/formats/rar/unrar/sha1.cpp
    src/formats/rar/unrar/threadpool.cpp
    src/formats/rar/unrar/crc.cpp
    src/formats/rar/unrar/hash.cpp
    src/formats/rar/unrar/strlist.cpp
    src/formats/rar/unrar/rs16.cpp
    src/formats/rar/unrar/resource.cpp
    src/formats/rar/unrar/consio.cpp
    src/formats/rar/unrar/secpassword.cpp
    src/formats/rar/unrar/qopen.cpp
    src/formats/rar/unrar/recvol.cpp
    src/formats/rar/unrar/rijndael.cpp
    src/formats/rar/unrar/timefn.cpp
    src/formats/rar/unrar/encname.cpp
    src/formats/rar/unrar/rawread.cpp
    src/formats/rar/unrar/file.cpp
    src/formats/rar/unrar/strfn.cpp
    src/formats/rar/unrar/sha256.cpp
    src/formats/rar/unrar/filefn.cpp
    src/formats/rar/unrar/filcreat.cpp
    src/formats/rar/unrar/headers.cpp
    src/formats/rar/unrar/blake2s.cpp
    src/formats/rar/unrar/options.cpp
    src/formats/rar/unrar/volume.cpp
    src/formats/rar/unrar/system.cpp
    src/formats/rar/unrar/crypt.cpp
    src/formats/rar/unrar/rar.cpp
    src/formats/rar/unrar/cmddata.cpp
    src/formats/rar/unrar/extinfo.cpp
    src/formats/rar/unrar/filestr.cpp
    src/formats/rar/unrar/ui.cpp
    src/formats/rar/unrar/list.cpp
    src/formats/rar/unrar/find.cpp
    src/formats/rar/unrar/smallfn.cpp
    src/formats/rar/unrar/unicode.cpp
    src/formats/rar/unrar/pathfn.cpp
    src/formats/rar/unrar/global.cpp
    src/formats/rar/unrar/rarvm.cpp
    src/formats/rar/unrar/getbits.cpp
    src/formats/rar/unrar/rs.cpp
    src/formats/rar/unrar/errhnd.cpp
    src/formats/rar/unrar/archive.cpp
    src/formats/rar/unrar/dll.cpp
    src/formats/rar/unrar/extract.cpp
    src/formats/rar/unrar/match.cpp
    src/formats/rar/unrar/unpack.cpp
    src/formats/rar/unrar/arcread.cpp
    src/formats/rar/unrar/rdwrfn.cpp
    src/formats/rar/unrar/rarpch.cpp

    src/formats/7z/7zcommon.cpp
    src/formats/7z/7z.cpp
    src/formats/7z/CPP/7zip/UI/Console/Main.cpp

    src/formats/7z/CPP/7zip/Common/StreamBinder.cpp
    src/formats/7z/CPP/Windows/Synchronization.cpp
    src/formats/7z/CPP/7zip/Common/VirtThread.cpp
    src/formats/7z/CPP/7zip/Common/MemBlocks.cpp
    src/formats/7z/CPP/7zip/Common/OutMemStream.cpp
    src/formats/7z/CPP/7zip/Common/ProgressMt.cpp
    src/formats/7z/CPP/Common/CRC.cpp
    src/formats/7z/CPP/Common/CrcReg.cpp
    src/formats/7z/CPP/Common/DynLimBuf.cpp
    src/formats/7z/CPP/Common/IntToString.cpp
    src/formats/7z/CPP/Common/LzFindPrepare.cpp
    src/formats/7z/CPP/Common/MyMap.cpp
    src/formats/7z/CPP/Common/MyString.cpp
    src/formats/7z/CPP/Common/MyVector.cpp
    src/formats/7z/CPP/Common/MyXml.cpp
    src/formats/7z/CPP/Common/NewHandler.cpp
    src/formats/7z/CPP/Common/Sha1Prepare.cpp
    src/formats/7z/CPP/Common/Sha1Reg.cpp
    src/formats/7z/CPP/Common/Sha256Prepare.cpp
    src/formats/7z/CPP/Common/Sha256Reg.cpp
    src/formats/7z/CPP/Common/StringConvert.cpp
    src/formats/7z/CPP/Common/StringToInt.cpp
    src/formats/7z/CPP/Common/UTFConvert.cpp
    src/formats/7z/CPP/Common/Wildcard.cpp
    src/formats/7z/CPP/Common/XzCrc64Init.cpp
    src/formats/7z/CPP/Common/XzCrc64Reg.cpp
    src/formats/7z/CPP/Windows/FileDir.cpp
    src/formats/7z/CPP/Windows/FileFind.cpp
    src/formats/7z/CPP/Windows/FileIO.cpp
    src/formats/7z/CPP/Windows/FileName.cpp
    src/formats/7z/CPP/Windows/PropVariant.cpp
    src/formats/7z/CPP/Windows/PropVariantUtils.cpp
    src/formats/7z/CPP/Windows/System.cpp
    src/formats/7z/CPP/Windows/TimeUtils.cpp
    src/formats/7z/CPP/7zip/Archive/ApfsHandler.cpp
    src/formats/7z/CPP/7zip/Archive/ApmHandler.cpp
    src/formats/7z/CPP/7zip/Archive/ArHandler.cpp
    src/formats/7z/CPP/7zip/Archive/ArjHandler.cpp
    src/formats/7z/CPP/7zip/Archive/AvbHandler.cpp
    src/formats/7z/CPP/7zip/Archive/Base64Handler.cpp
    src/formats/7z/CPP/7zip/Archive/Bz2Handler.cpp
    src/formats/7z/CPP/7zip/Archive/ComHandler.cpp
    src/formats/7z/CPP/7zip/Archive/CpioHandler.cpp
    src/formats/7z/CPP/7zip/Archive/CramfsHandler.cpp
    src/formats/7z/CPP/7zip/Archive/DeflateProps.cpp
    src/formats/7z/CPP/7zip/Archive/DmgHandler.cpp
    src/formats/7z/CPP/7zip/Archive/ElfHandler.cpp
    src/formats/7z/CPP/7zip/Archive/ExtHandler.cpp
    src/formats/7z/CPP/7zip/Archive/FatHandler.cpp
    src/formats/7z/CPP/7zip/Archive/FlvHandler.cpp
    src/formats/7z/CPP/7zip/Archive/GzHandler.cpp
    src/formats/7z/CPP/7zip/Archive/GptHandler.cpp
    src/formats/7z/CPP/7zip/Archive/HandlerCont.cpp
    src/formats/7z/CPP/7zip/Archive/HfsHandler.cpp
    src/formats/7z/CPP/7zip/Archive/IhexHandler.cpp
    src/formats/7z/CPP/7zip/Archive/LpHandler.cpp
    src/formats/7z/CPP/7zip/Archive/LvmHandler.cpp
    src/formats/7z/CPP/7zip/Archive/LzhHandler.cpp
    src/formats/7z/CPP/7zip/Archive/LzmaHandler.cpp
    src/formats/7z/CPP/7zip/Archive/MachoHandler.cpp
    src/formats/7z/CPP/7zip/Archive/MbrHandler.cpp
    src/formats/7z/CPP/7zip/Archive/MslzHandler.cpp
    src/formats/7z/CPP/7zip/Archive/MubHandler.cpp
    src/formats/7z/CPP/7zip/Archive/NtfsHandler.cpp
    src/formats/7z/CPP/7zip/Archive/PeHandler.cpp
    src/formats/7z/CPP/7zip/Archive/PpmdHandler.cpp
    src/formats/7z/CPP/7zip/Archive/QcowHandler.cpp
    src/formats/7z/CPP/7zip/Archive/RpmHandler.cpp
    src/formats/7z/CPP/7zip/Archive/SparseHandler.cpp
    src/formats/7z/CPP/7zip/Archive/SplitHandler.cpp
    src/formats/7z/CPP/7zip/Archive/SquashfsHandler.cpp
    src/formats/7z/CPP/7zip/Archive/SwfHandler.cpp
    src/formats/7z/CPP/7zip/Archive/UefiHandler.cpp
    src/formats/7z/CPP/7zip/Archive/VdiHandler.cpp
    src/formats/7z/CPP/7zip/Archive/VhdHandler.cpp
    src/formats/7z/CPP/7zip/Archive/VhdxHandler.cpp
    src/formats/7z/CPP/7zip/Archive/VmdkHandler.cpp
    src/formats/7z/CPP/7zip/Archive/XarHandler.cpp
    src/formats/7z/CPP/7zip/Archive/XzHandler.cpp
    src/formats/7z/CPP/7zip/Archive/ZHandler.cpp
    src/formats/7z/CPP/7zip/Archive/ZstdHandler.cpp
    src/formats/7z/CPP/7zip/Archive/Common/CoderMixer2.cpp
    src/formats/7z/CPP/7zip/Archive/Common/DummyOutStream.cpp
    src/formats/7z/CPP/7zip/Archive/Common/FindSignature.cpp
    src/formats/7z/CPP/7zip/Archive/Common/InStreamWithCRC.cpp
    src/formats/7z/CPP/7zip/Archive/Common/ItemNameUtils.cpp
    src/formats/7z/CPP/7zip/Archive/Common/MultiStream.cpp
    src/formats/7z/CPP/7zip/Archive/Common/OutStreamWithCRC.cpp
    src/formats/7z/CPP/7zip/Archive/Common/OutStreamWithSha1.cpp
    src/formats/7z/CPP/7zip/Archive/Common/HandlerOut.cpp
    src/formats/7z/CPP/7zip/Archive/Common/ParseProperties.cpp
    src/formats/7z/CPP/7zip/Archive/7z/7zCompressionMode.cpp
    src/formats/7z/CPP/7zip/Archive/7z/7zDecode.cpp
    src/formats/7z/CPP/7zip/Archive/7z/7zEncode.cpp
    src/formats/7z/CPP/7zip/Archive/7z/7zExtract.cpp
    src/formats/7z/CPP/7zip/Archive/7z/7zFolderInStream.cpp
    src/formats/7z/CPP/7zip/Archive/7z/7zHandler.cpp
    src/formats/7z/CPP/7zip/Archive/7z/7zHandlerOut.cpp
    src/formats/7z/CPP/7zip/Archive/7z/7zHeader.cpp
    src/formats/7z/CPP/7zip/Archive/7z/7zIn.cpp
    src/formats/7z/CPP/7zip/Archive/7z/7zOut.cpp
    src/formats/7z/CPP/7zip/Archive/7z/7zProperties.cpp
    src/formats/7z/CPP/7zip/Archive/7z/7zSpecStream.cpp
    src/formats/7z/CPP/7zip/Archive/7z/7zUpdate.cpp
    src/formats/7z/CPP/7zip/Archive/7z/7zRegister.cpp
    src/formats/7z/CPP/7zip/Archive/Cab/CabBlockInStream.cpp
    src/formats/7z/CPP/7zip/Archive/Cab/CabHandler.cpp
    src/formats/7z/CPP/7zip/Archive/Cab/CabHeader.cpp
    src/formats/7z/CPP/7zip/Archive/Cab/CabIn.cpp
    src/formats/7z/CPP/7zip/Archive/Cab/CabRegister.cpp
    src/formats/7z/CPP/7zip/Archive/Chm/ChmHandler.cpp
    src/formats/7z/CPP/7zip/Archive/Chm/ChmIn.cpp
    src/formats/7z/CPP/7zip/Archive/Iso/IsoHandler.cpp
    src/formats/7z/CPP/7zip/Archive/Iso/IsoHeader.cpp
    src/formats/7z/CPP/7zip/Archive/Iso/IsoIn.cpp
    src/formats/7z/CPP/7zip/Archive/Iso/IsoRegister.cpp
    src/formats/7z/CPP/7zip/Archive/Nsis/NsisDecode.cpp
    src/formats/7z/CPP/7zip/Archive/Nsis/NsisHandler.cpp
    src/formats/7z/CPP/7zip/Archive/Nsis/NsisIn.cpp
    src/formats/7z/CPP/7zip/Archive/Nsis/NsisRegister.cpp
    src/formats/7z/CPP/7zip/Archive/Rar/RarHandler.cpp
    src/formats/7z/CPP/7zip/Archive/Rar/Rar5Handler.cpp
    src/formats/7z/CPP/7zip/Archive/Tar/TarHandler.cpp
    src/formats/7z/CPP/7zip/Archive/Tar/TarHandlerOut.cpp
    src/formats/7z/CPP/7zip/Archive/Tar/TarHeader.cpp
    src/formats/7z/CPP/7zip/Archive/Tar/TarIn.cpp
    src/formats/7z/CPP/7zip/Archive/Tar/TarOut.cpp
    src/formats/7z/CPP/7zip/Archive/Tar/TarUpdate.cpp
    src/formats/7z/CPP/7zip/Archive/Tar/TarRegister.cpp
    src/formats/7z/CPP/7zip/Archive/Udf/UdfHandler.cpp
    src/formats/7z/CPP/7zip/Archive/Udf/UdfIn.cpp
    src/formats/7z/CPP/7zip/Archive/Wim/WimHandler.cpp
    src/formats/7z/CPP/7zip/Archive/Wim/WimHandlerOut.cpp
    src/formats/7z/CPP/7zip/Archive/Wim/WimIn.cpp
    src/formats/7z/CPP/7zip/Archive/Wim/WimRegister.cpp
    src/formats/7z/CPP/7zip/Archive/Zip/ZipAddCommon.cpp
    src/formats/7z/CPP/7zip/Archive/Zip/ZipHandler.cpp
    src/formats/7z/CPP/7zip/Archive/Zip/ZipHandlerOut.cpp
    src/formats/7z/CPP/7zip/Archive/Zip/ZipIn.cpp
    src/formats/7z/CPP/7zip/Archive/Zip/ZipItem.cpp
    src/formats/7z/CPP/7zip/Archive/Zip/ZipOut.cpp
    src/formats/7z/CPP/7zip/Archive/Zip/ZipUpdate.cpp
    src/formats/7z/CPP/7zip/Archive/Zip/ZipRegister.cpp
    src/formats/7z/CPP/7zip/Compress/Bcj2Coder.cpp
    src/formats/7z/CPP/7zip/Compress/Bcj2Register.cpp
    src/formats/7z/CPP/7zip/Compress/BcjCoder.cpp
    src/formats/7z/CPP/7zip/Compress/BcjRegister.cpp
    src/formats/7z/CPP/7zip/Compress/BitlDecoder.cpp
    src/formats/7z/CPP/7zip/Compress/BranchMisc.cpp
    src/formats/7z/CPP/7zip/Compress/BranchRegister.cpp
    src/formats/7z/CPP/7zip/Compress/ByteSwap.cpp
    src/formats/7z/CPP/7zip/Compress/BZip2Crc.cpp
    src/formats/7z/CPP/7zip/Compress/BZip2Decoder.cpp
    src/formats/7z/CPP/7zip/Compress/BZip2Encoder.cpp
    src/formats/7z/CPP/7zip/Compress/BZip2Register.cpp
    src/formats/7z/CPP/7zip/Compress/CopyCoder.cpp
    src/formats/7z/CPP/7zip/Compress/CopyRegister.cpp
    src/formats/7z/CPP/7zip/Compress/Deflate64Register.cpp
    src/formats/7z/CPP/7zip/Compress/DeflateDecoder.cpp
    src/formats/7z/CPP/7zip/Compress/DeflateEncoder.cpp
    src/formats/7z/CPP/7zip/Compress/DeflateRegister.cpp
    src/formats/7z/CPP/7zip/Compress/DeltaFilter.cpp
    src/formats/7z/CPP/7zip/Compress/ImplodeDecoder.cpp
    src/formats/7z/CPP/7zip/Compress/LzfseDecoder.cpp
    src/formats/7z/CPP/7zip/Compress/LzhDecoder.cpp
    src/formats/7z/CPP/7zip/Compress/Lzma2Decoder.cpp
    src/formats/7z/CPP/7zip/Compress/Lzma2Encoder.cpp
    src/formats/7z/CPP/7zip/Compress/Lzma2Register.cpp
    src/formats/7z/CPP/7zip/Compress/LzmaDecoder.cpp
    src/formats/7z/CPP/7zip/Compress/LzmaEncoder.cpp
    src/formats/7z/CPP/7zip/Compress/LzmaRegister.cpp
    src/formats/7z/CPP/7zip/Compress/LzmsDecoder.cpp
    src/formats/7z/CPP/7zip/Compress/LzOutWindow.cpp
    src/formats/7z/CPP/7zip/Compress/LzxDecoder.cpp
    src/formats/7z/CPP/7zip/Compress/PpmdDecoder.cpp
    src/formats/7z/CPP/7zip/Compress/PpmdEncoder.cpp
    src/formats/7z/CPP/7zip/Compress/PpmdRegister.cpp
    src/formats/7z/CPP/7zip/Compress/PpmdZip.cpp
    src/formats/7z/CPP/7zip/Compress/QuantumDecoder.cpp
    src/formats/7z/CPP/7zip/Compress/ShrinkDecoder.cpp
    src/formats/7z/CPP/7zip/Compress/XpressDecoder.cpp
    src/formats/7z/CPP/7zip/Compress/XzDecoder.cpp
    src/formats/7z/CPP/7zip/Compress/XzEncoder.cpp
    src/formats/7z/CPP/7zip/Compress/ZlibDecoder.cpp
    src/formats/7z/CPP/7zip/Compress/ZlibEncoder.cpp
    src/formats/7z/CPP/7zip/Compress/ZDecoder.cpp
    src/formats/7z/CPP/7zip/Compress/Rar1Decoder.cpp
    src/formats/7z/CPP/7zip/Compress/Rar2Decoder.cpp
    src/formats/7z/CPP/7zip/Compress/Rar3Decoder.cpp
    src/formats/7z/CPP/7zip/Compress/Rar3Vm.cpp
    src/formats/7z/CPP/7zip/Compress/Rar5Decoder.cpp
    src/formats/7z/CPP/7zip/Compress/RarCodecsRegister.cpp
    src/formats/7z/CPP/7zip/Compress/ZstdDecoder.cpp
    src/formats/7z/CPP/7zip/Crypto/7zAes.cpp
    src/formats/7z/CPP/7zip/Crypto/7zAesRegister.cpp
    src/formats/7z/CPP/7zip/Crypto/HmacSha1.cpp
    src/formats/7z/CPP/7zip/Crypto/HmacSha256.cpp
    src/formats/7z/CPP/7zip/Crypto/MyAes.cpp
    src/formats/7z/CPP/7zip/Crypto/MyAesReg.cpp
    src/formats/7z/CPP/7zip/Crypto/Pbkdf2HmacSha1.cpp
    src/formats/7z/CPP/7zip/Crypto/RandGen.cpp
    src/formats/7z/CPP/7zip/Crypto/WzAes.cpp
    src/formats/7z/CPP/7zip/Crypto/ZipCrypto.cpp
    src/formats/7z/CPP/7zip/Crypto/ZipStrong.cpp
    src/formats/7z/CPP/7zip/Crypto/Rar20Crypto.cpp
    src/formats/7z/CPP/7zip/Crypto/Rar5Aes.cpp
    src/formats/7z/CPP/7zip/Crypto/RarAes.cpp
    src/formats/7z/CPP/7zip/Common/CreateCoder.cpp
    src/formats/7z/CPP/7zip/Common/CWrappers.cpp
    src/formats/7z/CPP/7zip/Common/InBuffer.cpp
    src/formats/7z/CPP/7zip/Common/InOutTempBuffer.cpp
    src/formats/7z/CPP/7zip/Common/FilterCoder.cpp
    src/formats/7z/CPP/7zip/Common/LimitedStreams.cpp
    src/formats/7z/CPP/7zip/Common/LockedStream.cpp
    src/formats/7z/CPP/7zip/Common/MethodId.cpp
    src/formats/7z/CPP/7zip/Common/MethodProps.cpp
    src/formats/7z/CPP/7zip/Common/MultiOutStream.cpp
    src/formats/7z/CPP/7zip/Common/OffsetStream.cpp
    src/formats/7z/CPP/7zip/Common/OutBuffer.cpp
    src/formats/7z/CPP/7zip/Common/ProgressUtils.cpp
    src/formats/7z/CPP/7zip/Common/PropId.cpp
    src/formats/7z/CPP/7zip/Common/StreamObjects.cpp
    src/formats/7z/CPP/7zip/Common/StreamUtils.cpp
    src/formats/7z/CPP/7zip/Common/UniqBlocks.cpp
    src/formats/7z/CPP/Common/MyWindows.cpp
    src/formats/7z/CPP/Common/CommandLineParser.cpp
    src/formats/7z/CPP/Common/ListFileUtils.cpp
    src/formats/7z/CPP/Common/StdInStream.cpp
    src/formats/7z/CPP/Common/StdOutStream.cpp
    src/formats/7z/CPP/Common/Xxh64Reg.cpp
    src/formats/7z/CPP/Windows/ErrorMsg.cpp
    src/formats/7z/CPP/Windows/FileLink.cpp
    src/formats/7z/CPP/Windows/PropVariantConv.cpp
    src/formats/7z/CPP/Windows/SystemInfo.cpp
    src/formats/7z/CPP/7zip/Common/FilePathAutoRename.cpp
    src/formats/7z/CPP/7zip/Common/FileStreams.cpp
    src/formats/7z/CPP/7zip/UI/Common/ArchiveCommandLine.cpp
    src/formats/7z/CPP/7zip/UI/Common/ArchiveExtractCallback.cpp
    src/formats/7z/CPP/7zip/UI/Common/ArchiveOpenCallback.cpp
    src/formats/7z/CPP/7zip/UI/Common/Bench.cpp
    src/formats/7z/CPP/7zip/UI/Common/DefaultName.cpp
    src/formats/7z/CPP/7zip/UI/Common/EnumDirItems.cpp
    src/formats/7z/CPP/7zip/UI/Common/Extract.cpp
    src/formats/7z/CPP/7zip/UI/Common/ExtractingFilePath.cpp
    src/formats/7z/CPP/7zip/UI/Common/HashCalc.cpp
    src/formats/7z/CPP/7zip/UI/Common/LoadCodecs.cpp
    src/formats/7z/CPP/7zip/UI/Common/OpenArchive.cpp
    src/formats/7z/CPP/7zip/UI/Common/PropIDUtils.cpp
    src/formats/7z/CPP/7zip/UI/Common/SetProperties.cpp
    src/formats/7z/CPP/7zip/UI/Common/SortUtils.cpp
    src/formats/7z/CPP/7zip/UI/Common/TempFiles.cpp
    src/formats/7z/CPP/7zip/UI/Common/Update.cpp
    src/formats/7z/CPP/7zip/UI/Common/UpdateAction.cpp
    src/formats/7z/CPP/7zip/UI/Common/UpdateCallback.cpp
    src/formats/7z/CPP/7zip/UI/Common/UpdatePair.cpp
    src/formats/7z/CPP/7zip/UI/Common/UpdateProduce.cpp
    src/formats/7z/CPP/7zip/UI/Console/BenchCon.cpp
    src/formats/7z/CPP/7zip/UI/Console/ConsoleClose.cpp
    src/formats/7z/CPP/7zip/UI/Console/ExtractCallbackConsole.cpp
    src/formats/7z/CPP/7zip/UI/Console/HashCon.cpp
    src/formats/7z/CPP/7zip/UI/Console/List.cpp

    src/formats/7z/CPP/7zip/UI/Console/OpenCallbackConsole.cpp
    src/formats/7z/CPP/7zip/UI/Console/PercentPrinter.cpp
    src/formats/7z/CPP/7zip/UI/Console/UpdateCallbackConsole.cpp
    src/formats/7z/CPP/7zip/UI/Console/UserInputUtils.cpp


    src/formats/7z/C/7zBuf2.c    
    src/formats/7z/C/7zStream.c  
    src/formats/7z/C/Alloc.c     
    src/formats/7z/C/Bcj2.c      
    src/formats/7z/C/Bcj2Enc.c   
    src/formats/7z/C/Blake2s.c   
    src/formats/7z/C/Bra.c       
    src/formats/7z/C/Bra86.c     
    src/formats/7z/C/BraIA64.c   
    src/formats/7z/C/BwtSort.c   
    src/formats/7z/C/CpuArch.c   
    src/formats/7z/C/Delta.c     
    src/formats/7z/C/HuffEnc.c   
    src/formats/7z/C/LzFind.c    
    src/formats/7z/C/Lzma2Dec.c  
    src/formats/7z/C/Lzma2DecMt.c
    src/formats/7z/C/Lzma2Enc.c  
    src/formats/7z/C/LzmaDec.c   
    src/formats/7z/C/LzmaEnc.c   
    src/formats/7z/C/MtCoder.c   
    src/formats/7z/C/MtDec.c     
    src/formats/7z/C/Ppmd7.c     
    src/formats/7z/C/Ppmd7Dec.c  
    src/formats/7z/C/Ppmd7aDec.c 
    src/formats/7z/C/Ppmd7Enc.c  
    src/formats/7z/C/Ppmd8.c     
    src/formats/7z/C/Ppmd8Dec.c  
    src/formats/7z/C/Ppmd8Enc.c  
    src/formats/7z/C/Sort.c      
    src/formats/7z/C/Xz.c        
    src/formats/7z/C/XzDec.c     
    src/formats/7z/C/XzEnc.c     
    src/formats/7z/C/XzIn.c      
    src/formats/7z/C/XzCrc64.c   
    src/formats/7z/C/7zCrc.c     
    src/formats/7z/C/Aes.c       
    src/formats/7z/C/Sha256.c    
    src/formats/7z/C/Sha1.c      
    src/formats/7z/C/LzFindMt.c  
    src/formats/7z/C/Threads.c   
    src/formats/7z/C/Xxh64.c
    src/formats/7z/C/SwapBytes.c
    src/formats/7z/C/ZstdDec.c
    
    src/formats/ha/ha/acoder.c
    src/formats/ha/ha/archive.c
    src/formats/ha/ha/asc.c
    src/formats/ha/ha/cpy.c
    src/formats/ha/ha/error.c
    src/formats/ha/ha/ha.c
    src/formats/ha/ha/haio.c
    src/formats/ha/ha/hsc.c
    src/formats/ha/ha/info.c
    src/formats/ha/ha/machine.c
    src/formats/ha/ha/misc.c
    src/formats/ha/ha/swdict.c
)
    
if(PCRE_FOUND)
    set(SOURCES
        ${SOURCES}
        src/formats/custom/custom.cpp
    )
endif()

if(LibArchive_FOUND)
    set(SOURCES
        ${SOURCES}
        src/formats/libarch/libarch_utils.cpp
        src/formats/libarch/libarch_crutches.cpp
        src/formats/libarch/libarch_cmd_read.cpp
        src/formats/libarch/libarch_cmd_write.cpp
        src/formats/libarch/libarch.cpp
    )
else()
    set(SOURCES
        ${SOURCES}
        src/formats/targz/targz.cpp
        src/formats/cab/cab.cpp

    )
endif()

find_package(Asmc)
if( ASMC_ASM_TOOL AND CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64" )

    message(STATUS "Asmc used for compile portion of 7z code")

    set(ASM_OPTIONS " -nologo -elf64 -DABI_LINUX ")

    set(ASM_SOURCES
        src/formats/7z/Asm/x86/7zCrcOpt.asm
        src/formats/7z/Asm/x86/XzCrc64Opt.asm
        src/formats/7z/Asm/x86/Sha1Opt.asm
        src/formats/7z/Asm/x86/Sha256Opt.asm
        src/formats/7z/Asm/x86/AesOpt.asm
        src/formats/7z/Asm/x86/LzFindOpt.asm
        src/formats/7z/Asm/x86/LzmaDecOpt.asm
    )

    #This bit of code loops through the assembly files and calls asmc64.
    foreach(src ${ASM_SOURCES})
        get_filename_component(FILE_BASE ${src} NAME_WE)
        set(src ${CMAKE_CURRENT_SOURCE_DIR}/${src})
        set(obj ${CMAKE_CURRENT_BINARY_DIR}/${FILE_BASE}.o)
        add_custom_command(OUTPUT ${obj}
                  MAIN_DEPENDENCY ${src}
                  COMMAND "${ASMC_ASM_TOOL}"
                  ARGS "${ASM_OPTIONS}" -Fo"${obj}" "${src}")
        set(ASM_OBJS ${ASM_OBJS} ${obj})
    endforeach(src)

else()

    # This portion of code used if can't compile asm
    set(SOURCES
        ${SOURCES}
        src/formats/7z/C/7zCrcOpt.c
        src/formats/7z/C/XzCrc64Opt.c
        src/formats/7z/C/Sha1Opt.c
        src/formats/7z/C/Sha256Opt.c
        src/formats/7z/C/AesOpt.c
        src/formats/7z/C/LzFindOpt.c
    )

endif()

add_library (multiarc MODULE ${SOURCES} ${ASM_SOURCES})

target_compile_definitions(multiarc PRIVATE -DRARDLL -D_7ZIP_ST -D_7ZIP_PPMD_SUPPPORT -DST_MODE)

target_link_libraries(multiarc utils far2l ${ASM_OBJS})

target_include_directories(multiarc PRIVATE src/formats/rar/unrar)
target_include_directories(multiarc PRIVATE src)
target_include_directories(multiarc PRIVATE src/libpcre)

target_compile_definitions(multiarc PRIVATE -DUSEUCD=OFF -DWINPORT_DIRECT -DUNICODE -DFAR_DONT_USE_INTERNALS)

target_include_directories(multiarc PRIVATE .)
target_include_directories(multiarc PRIVATE ./multiarc)
target_include_directories(multiarc PRIVATE ${PROJECT_SOURCE_DIR}/utils/include)
target_include_directories(multiarc PRIVATE ${PROJECT_SOURCE_DIR}/far2l/far2sdk)
target_include_directories(multiarc PRIVATE ${PROJECT_SOURCE_DIR}/far2l/Include)
target_include_directories(multiarc PRIVATE ${PROJECT_SOURCE_DIR}/WinPort)

if(PCRE_FOUND)
    target_compile_definitions(multiarc PRIVATE -DHAVE_PCRE)
    target_link_libraries(multiarc ${PCRE_LIBRARIES})
    target_include_directories(multiarc PRIVATE ${PCRE_INCLUDE_DIRS})
endif()

if(LibArchive_FOUND)
    target_compile_definitions(multiarc PRIVATE -DHAVE_LIBARCHIVE)
    target_link_libraries(multiarc ${LibArchive_LIBRARIES})
    target_include_directories(multiarc PRIVATE ${LibArchive_INCLUDE_DIRS})
endif()

set_target_properties(multiarc
  PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${INSTALL_DIR}/Plugins/multiarc/plug"
    PREFIX ""
    SUFFIX ".far-plug-mb")

add_custom_command(TARGET multiarc POST_BUILD
   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/configs
   COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/configs "${INSTALL_DIR}/Plugins/multiarc")
