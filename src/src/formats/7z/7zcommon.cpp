/*
  7zcommon.cpp
  Common plugin module for FAR Manager and MultiArc plugin
  Copyrigth (c) 2022 VPROFi
*/

#include "7zcommon.h"
#include "./CPP/Common/MyWindows.h"
#include "./CPP/Common/Common.h"

#ifdef _WIN32
#include <Psapi.h>
#else
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/times.h>
#endif

#include "./CPP/../C/CpuArch.h"

#include "./CPP/Common/CommandLineParser.h"
#include "./CPP/Common/IntToString.h"
#include "./CPP/Common/MyException.h"
#include "./CPP/Common/StdInStream.h"
#include "./CPP/Common/StdOutStream.h"
#include "./CPP/Common/StringConvert.h"
#include "./CPP/Common/StringToInt.h"
#include "./CPP/Common/UTFConvert.h"
#include "./CPP/Common/MyLinux.h"

#include "./CPP/Windows/ErrorMsg.h"
#include "./CPP/Windows/TimeUtils.h"

#include "./CPP/7zip/Common/RegisterCodec.h"

#ifdef PROG_VARIANT_R
#include "./CPP/../C/7zVersion.h"
#else
#include "./CPP/7zip/MyVersion.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#define PYPLUGIN_DEBUGLOG "/tmp/far2.7zcommon.cpp.log"
#if !defined(__APPLE__) && !defined(__FreeBSD__)
# include <alloca.h>
#endif

static void z_log(const char *function, unsigned int line, const char *format, ...)
{
    va_list args;
    char *xformat = (char *)alloca(strlen(format) + strlen(function) + 64);
    sprintf(xformat, "[7ZCOMMON]: %s@%u%s%s",
        function, line, (*format != '\n') ? " - " : "", format);

    FILE *stream = nullptr;
    if (PYPLUGIN_DEBUGLOG[0]) {
        stream = fopen(PYPLUGIN_DEBUGLOG, "at");
    }
    if (!stream) {
        stream = stderr;
    }
    va_start(args, format);
    vfprintf(stream, xformat, args);
    va_end(args);

    if (stream != stderr) {
        fclose(stream);
    }
}

#define Z_LOG(args...) z_log(__FUNCTION__, __LINE__, args)

#include "./CPP/7zip/UI/Common/LoadCodecs.h"
#include "./CPP/7zip/UI/Common/HashCalc.h"
#include "./CPP/7zip/UI/Console/OpenCallbackConsole.h"
#include "./CPP/Common/StdOutStream.h"
#include "./CPP/7zip/PropID.h"
#include "./CPP/Windows/PropVariantConv.h"

#include <time.h>

static time_t FileTime_to_POSIX(FILETIME ft)
{
    FILETIME localFileTime;
    FileTimeToLocalFileTime(&ft,&localFileTime);
    SYSTEMTIME sysTime;
    FileTimeToSystemTime(&localFileTime,&sysTime);
    struct tm tmtime = {0};
    tmtime.tm_year = sysTime.wYear - 1900;
    tmtime.tm_mon = sysTime.wMonth - 1;
    tmtime.tm_mday = sysTime.wDay;
    tmtime.tm_hour = sysTime.wHour;
    tmtime.tm_min = sysTime.wMinute;
    tmtime.tm_sec = sysTime.wSecond;
    tmtime.tm_wday = 0;
    tmtime.tm_yday = 0;
    tmtime.tm_isdst = -1;
    time_t ret = mktime(&tmtime);
    return ret;
}

class COpenCallbackFar2l: public IOpenCallbackUI
{
protected:

public:

  bool PasswordIsDefined;
  UString Password;
  UString Archive;

  bool MultiArcMode;

  void ClosePercents();

  COpenCallbackFar2l():
      PasswordIsDefined(false)
  {
    Password.Empty();
  }

  virtual ~COpenCallbackFar2l() {};
  
  void Init(const wchar_t * archive)
  {
	Archive = archive;
  }

  //INTERFACE_IOpenCallbackUI(;)
  Z7_IFACE_IMP(IOpenCallbackUI)

};

//#include "showpassdialog.h"
std::wstring CryptoGetTextPassword(const wchar_t * archive);

HRESULT COpenCallbackFar2l::Open_CryptoGetTextPassword(BSTR *password)
{
  *password = NULL;
  if (!PasswordIsDefined)
  {
    std::wstring pass = CryptoGetTextPassword(Archive.Ptr(Archive.ReverseFind_PathSepar()+1));
    Password = pass.c_str();
    PasswordIsDefined = true;
  }
  return StringToBstr(Password, password);
}

HRESULT COpenCallbackFar2l::Open_Finished()
{
  return S_OK;
}

HRESULT COpenCallbackFar2l::Open_CheckBreak()
{
  return S_OK;
}

HRESULT COpenCallbackFar2l::Open_SetTotal(const UInt64 *files, const UInt64 *bytes)
{
  return S_OK;
}

HRESULT COpenCallbackFar2l::Open_SetCompleted(const UInt64 *files, const UInt64 *bytes)
{
  return S_OK;
}

extern
CStdOutStream *g_StdStream;
CStdOutStream *g_StdStream = &g_StdOut;
extern
CStdOutStream *g_ErrStream;
CStdOutStream *g_ErrStream = &g_StdErr;

static CCodecs *g_Codecs = nullptr;

static bool Init7z(void)
{
	CCodecs *codecs = new CCodecs; \
	codecs->CaseSensitive_Change = false;
	codecs->CaseSensitive = false;
	HRESULT res = codecs->Load();
	if( res != S_OK) {
		Z_LOG("... codecs->Load() error %u\n", res);
		delete codecs;
		return false;
	}
	Codecs_AddHashArcHandler(codecs);
	g_Codecs = codecs;
	return true;
}

void * OpenFile7z(const wchar_t *path, bool & passwordIsDefined)
{
	if( !g_Codecs && !Init7z())
		return nullptr;

	CArchiveLink * arcLink = new CArchiveLink();

	COpenOptions options;
	options.codecs = g_Codecs;
	CObjectVector<COpenType> types;
	options.types = &types;
	CIntVector excludedFormats;
	options.excludedFormats = &excludedFormats;
	options.stdInMode = false;
	options.stream = NULL;
	options.filePath = UString(path);
	CObjectVector<CProperty> Properties;
	options.props = &Properties;

	COpenCallbackFar2l openCallbackFar2l;
	openCallbackFar2l.Init(path);
	HRESULT res = arcLink->Open_Strict(options, &openCallbackFar2l);
	if( res != S_OK) {
		Z_LOG("... arcLink->Open_Strict(%S) result 0x%08X PasswordIsDefined %d\n", options.filePath.Ptr(), res, openCallbackFar2l.PasswordIsDefined);
		if( openCallbackFar2l.PasswordIsDefined )
			PasswordError(options.filePath.Ptr());
		return nullptr;
	}

	passwordIsDefined = openCallbackFar2l.PasswordIsDefined;
	return arcLink;
}
void CloseFile7z(void * _context)
{
	CArchiveLink * arcLink = (CArchiveLink*)_context;
	delete arcLink;
}

unsigned int GetNumFiles7z(void * _context)
{
	CArchiveLink * arcLink = (CArchiveLink*)_context;
	const CArc &arc = arcLink->Arcs.Back();
	IInArchive *archive = arc.Archive;
	UInt32 numItems;
	archive->GetNumberOfItems(&numItems);
	return (unsigned int)numItems;
}

static bool GetCPropVariant(void * _context, unsigned int _index, PROPID propID, NWindows::NCOM::CPropVariant & prop)
{
	CArchiveLink * arcLink = (CArchiveLink*)_context;
	const CArc &arc = arcLink->Arcs.Back();
	IInArchive *archive = arc.Archive;
	archive->GetProperty(_index, propID, &prop);
	if( prop.vt == VT_EMPTY )
		return false;
	return true;
}

static bool GetBool(void * _context, unsigned int _index, PROPID propID)
{
	NWindows::NCOM::CPropVariant prop;
	if(GetCPropVariant(_context, _index, propID, prop) && prop.vt == VT_BOOL)
		return (bool)VARIANT_BOOLToBool(prop.boolVal);
	return false;
}

static uint32_t GetUint32(void * _context, unsigned int _index, PROPID propID)
{
	NWindows::NCOM::CPropVariant prop;
	if(GetCPropVariant(_context, _index, propID, prop) && (prop.vt == VT_UI4 || prop.vt == VT_I4))
		return prop.ulVal;
	return 0;
}

static uint64_t GetUint64(void * _context, unsigned int _index, PROPID propID)
{
	NWindows::NCOM::CPropVariant prop;
	if(GetCPropVariant(_context, _index, propID, prop)) {
		switch (prop.vt) {
			case VT_UI8:
				return (uint64_t)prop.hVal.QuadPart;
			case VT_I8:
				return (uint64_t)prop.uhVal.QuadPart;
			case VT_UI4:
				return (uint64_t)prop.ulVal;
			case VT_I4:
				return (uint64_t)prop.lVal;
			case VT_UI2:
				return (uint64_t)prop.uiVal;
			case VT_I2:
				return (uint64_t)prop.iVal;
			case VT_UI1:
				return (uint64_t)prop.bVal;
			case VT_I1:
				return (uint64_t)prop.cVal;
			default:
				break;
		}
	}
	return (uint64_t)0;
}

uint32_t GetAttrib7z(void * _context, unsigned int _index)
{
	return GetUint32(_context, _index, kpidAttrib);
}

// The 7-zip archive format does not store standard Unix file permissions such as owner/group or extended file attributes.
// But we support many others formats.
uint32_t GetPosixAttrib7z(void * _context, unsigned int _index)
{
	uint32_t attr = GetUint32(_context, _index, kpidPosixAttrib);
	if(attr)
		return attr;
	attr = GetUint32(_context, _index, kpidAttrib);
	if( attr & FILE_ATTRIBUTE_UNIX_EXTENSION )
		return attr >> 16;
	return 0;
}

uint32_t GetCRC7z(void * _context, unsigned int _index)
{
	return GetUint32(_context, _index, kpidCRC);
}

uint64_t GetSize7z(void * _context, unsigned int _index)
{
	return GetUint64(_context, _index, kpidSize);
}

uint64_t GetPackSize7z(void * _context, unsigned int _index)
{
	return GetUint64(_context, _index, kpidPackSize);
}

bool IsDir7z(void * _context, unsigned int _index)
{
	return GetBool(_context, _index, kpidIsDir);
}

bool IsEncrypted7z(void * _context, unsigned int _index)
{
	return GetBool(_context, _index, kpidEncrypted);
}

bool IsSymlink7z(void * _context, unsigned int _index)
{
	if( GetBool(_context, _index, kpidSymLink) )
		return true;
	return MY_LIN_S_ISLNK(GetPosixAttrib7z(_context, _index));
}

bool GetName7z(void * _context, unsigned int _index, std::wstring & _tmp_str)
{
	CArchiveLink * arcLink = (CArchiveLink*)_context;
	const CArc &arc = arcLink->Arcs.Back();
	UString FilePath;
	HRESULT res = arc.GetItem_Path2(_index, FilePath);
	if( res != S_OK) {
		Z_LOG("... arc.GetItem_Path2() error %u\n", res);
		return false;
	}
	_tmp_str = std::wstring(FilePath.Ptr());
	return true;
}

void GetCTime7z(void * _context, unsigned int _index, void * ftc)
{
	NWindows::NCOM::CPropVariant prop;
	if(GetCPropVariant(_context, _index, kpidCTime, prop) && prop.vt == VT_FILETIME)
		*(FILETIME *)ftc = prop.filetime;
	return;
}

void GetMTime7z(void * _context, unsigned int _index, void * ftm)
{
	NWindows::NCOM::CPropVariant prop;
	if(GetCPropVariant(_context, _index, kpidMTime, prop) && prop.vt == VT_FILETIME)
		*(FILETIME *)ftm = prop.filetime;
	return;
}
