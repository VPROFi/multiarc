/*
  7z.cpp

  Second-level plugin module for FAR Manager and MultiArc plugin

  Copyright (c) 1996 Eugene Roshal
  Copyrigth (c) 2000 FAR group
  Copyrigth (c) 2016 elfmz
  Copyrigth (c) 2022 VPROFi
*/
#define _UNICODE
#include <windows.h>
#include <utils.h>
#include <string.h>
#if !defined(__APPLE__) && !defined(__FreeBSD__)
# include <malloc.h>
#endif
#include <stddef.h>
#include <memory.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <vector>
#include <exception>
#include <stdexcept>
#include <farplug-mb.h>
using namespace oldfar;
#include "MultiArc.hpp"

#include "7zcommon.h"

#if defined(__BORLANDC__)
  #pragma option -a1
#elif defined(__GNUC__) || (defined(__WATCOMC__) && (__WATCOMC__ < 1100)) || defined(__LCC__)
  #pragma pack(1)
#else
  #pragma pack(push,1)
  #if _MSC_VER
    #define _export
  #endif
#endif

struct PluginStartupInfo   gInfo;

/////////////////////////////

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include "../../marclng.hpp"

class Traverser
{
	unsigned int _index;
	bool _valid, _passwordIsDefined;
	void * _context;
	struct stat _archStat;

	bool GetFileStat(const char *path, struct stat * fileStat)
	{
		int filedes = open(path, O_RDONLY);
		if( filedes > 0 ) {
			int res = fstat(filedes, fileStat);
			close(filedes);
			if( res == 0 )
				return true;
		}
		return false;
	}
public:
	Traverser(const char *path) : _index(0), _valid(false), _passwordIsDefined(false), _context(nullptr)
	{
		if( !GetFileStat(path, &_archStat) )
			return;
        std::wstring dst;
        MB2Wide(path, dst);
		_context = OpenFile7z(dst.c_str(), _passwordIsDefined);
		if ( _context != nullptr )
			_valid = true;
		else if (_passwordIsDefined) {
			const char *NamePtr = path;
			while(*path) {
				if(*path=='/')
				NamePtr=path+1;
				path++;
			}
			std::string title = "MultiArc: ";
			title += NamePtr;
			const char *MsgItems[] = { title.c_str(), (const char*)gInfo.GetMsg(gInfo.ModuleNumber, MAddPswNotMatch)};
			gInfo.Message(gInfo.ModuleNumber, FMSG_WARNING | FMSG_MB_OK, NULL, MsgItems, ARRAYSIZE(MsgItems), 0);
		}
	}

	friend std::wstring CryptoGetTextPassword(const wchar_t * archive);
	
	~Traverser()
	{
		if (_context) {
			CloseFile7z(_context);
			_context = nullptr;
		}
	}
	
	bool Valid() const
	{
		return _valid;
	}

	bool IsSameFile(const char *path) {
		if( !Valid() )
			return false;
		struct stat fileStat;
		if( !GetFileStat(path, &fileStat) )
			return false;
		return ( fileStat.st_dev == _archStat.st_dev && fileStat.st_ino == _archStat.st_ino
#ifdef __APPLE__
			  && memcmp(&fileStat.st_mtimespec, &_archStat.st_mtimespec, sizeof(fileStat.st_mtimespec)) == 0
			  && memcmp(&fileStat.st_ctimespec, &_archStat.st_ctimespec, sizeof(fileStat.st_ctimespec)) == 0
#else
			  && memcmp(&fileStat.st_mtim, &_archStat.st_mtim, sizeof(fileStat.st_mtim)) == 0
			  && memcmp(&fileStat.st_ctim, &_archStat.st_ctim, sizeof(fileStat.st_ctim)) == 0
#endif
			);
	}
	
	int Next(struct PluginPanelItem *Item, struct ArcItemInfo *Info)
	{
		if (!_valid || _context == nullptr)
			return GETARC_READERROR;

		if (_index >= GetNumFiles7z(_context))
			return GETARC_EOF;

		unsigned is_dir = 0;
		DWORD attribs = 0;
		uint64_t file_size = 0;
		uint64_t packed_size = 0;
		DWORD crc32 = 0;
		FILETIME ftm = {}, ftc = {};
		std::wstring _tmp_str;

		is_dir = IsDir7z(_context, _index);
		if ( !GetName7z(_context, _index, _tmp_str) )
			return GETARC_READERROR;
		attribs = (DWORD)GetAttrib7z(_context, _index);
		if( IsEncrypted7z(_context, _index) )
			Item->Flags |= F_ENCRYPTED;
		file_size = GetSize7z(_context, _index);
		packed_size = GetPackSize7z(_context, _index);
		crc32 = (DWORD)GetCRC7z(_context,_index);
		GetCTime7z(_context, _index, &ftc);
		GetMTime7z(_context, _index, &ftm);

		const std::string &name = StrWide2MB(_tmp_str);

		strncpy(Item->FindData.cFileName, name.c_str(), ARRAYSIZE(Item->FindData.cFileName)-1);

		Item->FindData.dwUnixMode = GetPosixAttrib7z(_context, _index);

		if( Item->FindData.dwUnixMode ) {
			if ((Item->FindData.dwUnixMode & S_IFMT) == 0)
				Item->FindData.dwUnixMode|= S_IFREG;
			Item->FindData.dwFileAttributes = WINPORT(EvaluateAttributesA)(Item->FindData.dwUnixMode, Item->FindData.cFileName);
		} else {
			Item->FindData.dwUnixMode = is_dir ? 0755 : 0644;
			attribs&=~ (FILE_ATTRIBUTE_BROKEN | FILE_ATTRIBUTE_EXECUTABLE);
			Item->FindData.dwFileAttributes = attribs;
		}

		Item->FindData.nFileSize = file_size;
		Item->FindData.nPhysicalSize = packed_size;
		Item->CRC32 = crc32;
		
		Item->FindData.ftLastWriteTime = ftm;
		Item->FindData.ftCreationTime = ftc;

		Info->Solid = 0;
		Info->Comment = 0;
		Info->Encrypted = _passwordIsDefined;
		Info->DictSize = 0;
		Info->UnpVer = 0;

		++_index;
		
		return GETARC_SUCCESS;
	}
};

///////////////////////////////////
int WINAPI GetPassword(char *Password,const char *FileName);
std::wstring CryptoGetTextPassword(const wchar_t * archive)
{
	std::wstring pass;
	char password[512];
	const std::string &title = StrWide2MB(std::wstring(archive));
	if( !GetPassword(password,title.c_str()) )
		return pass;
	pass = MB2Wide(password);
	return pass;
}

void PasswordError(const wchar_t * info)
{
	const std::string &path = StrWide2MB(std::wstring(info));
	const char *msgItems[] = {GetMsg(MAddPswNotMatch), path.c_str()};
	gInfo.Message(gInfo.ModuleNumber, FMSG_WARNING|FMSG_MB_OK, NULL, msgItems, ARRAYSIZE(msgItems), 0);
	return;
}

///////////////////////////////////
struct posix_header
{                               /* byte offset */
  char name[100];               /*   0 = 0x000 */
  char mode[8];                 /* 100 = 0x064 */
  char uid[8];                  /* 108 = 0x06C */
  char gid[8];                  /* 116 = 0x074 */
  char size[12];                /* 124 = 0x07C */
  char mtime[12];               /* 136 = 0x088 */
  char chksum[8];               /* 148 = 0x094 */
  char typeflag;                /* 156 = 0x09C */
  char linkname[100];           /* 157 = 0x09D */
  char magic[6];                /* 257 = 0x101 */
  char version[2];              /* 263 = 0x107 */
  char uname[32];               /* 265 = 0x109 */
  char gname[32];               /* 297 = 0x129 */
  char devmajor[8];             /* 329 = 0x149 */
  char devminor[8];             /* 337 = 0x151 */
  char prefix[155];             /* 345 = 0x159 */
                                /* 500 = 0x1F4 */
};
#define TMAGIC   "ustar"    // ustar and a null
#define OLDGNU_MAGIC "ustar  "  /* 7 chars and a null */
static int IsTarHeader(const BYTE *Data,int DataSize)
{
    struct posix_header *Header;
    if (DataSize<(int)sizeof(struct posix_header))
        return(FALSE);
    Header=(struct posix_header *)Data;
    if(!strcmp (Header->magic, TMAGIC) || !strcmp (Header->magic, OLDGNU_MAGIC))
        return(TRUE);
    if (Data[0]==0x1f && (Data[1]==0x8b || Data[1]==0x9d))
        return(TRUE);
    if (Data[0]=='B' && Data[1]=='Z')
        return(TRUE);
    if (DataSize>=6 && memcmp(Data, "\xFD\x37\x7A\x58\x5A\x00", 6) == 0)
        return(TRUE);
    return FALSE;
}

///////////////////////////////////
static Traverser *s_selected_traverser = NULL;

BOOL WINAPI _export SEVENZ_IsArchive(const char *Name,const unsigned char *Data,int DataSize)
{
	if( s_selected_traverser && s_selected_traverser->IsSameFile(Name) )
			return TRUE;

	// linux tar format more powerfull
	if( IsTarHeader(Data, DataSize) )
		return FALSE;

	// linux tar.gz tar.z tar.bz tar.xz format more powerfull
	if( DataSize >= 2 ) {
		if (Data[0]==0x1f && Data[1]==0x8b)
			return FALSE; // GZ_FORMAT
		else if (Data[0]==0x1f && Data[1]==0x9d)
			return FALSE; // Z_FORMAT;
		else if (Data[0]=='B' && Data[1]=='Z')
			return FALSE; // BZ_FORMAT;
		else if (DataSize>=6 && memcmp(Data, "\xFD\x37\x7A\x58\x5A\x00", 6) == 0)
			return FALSE; // XZ_FORMAT;
	}

	// deb not fully supported 
	const char *dot=(const char *)strrchr((char*)Name,'.');
	if( dot!=NULL && (strcasecmp(dot,".deb")==0) )
		return FALSE;

	Traverser *t = new Traverser(Name);
	if (!t->Valid()) {
		delete t;
		return FALSE;
	}

	if(s_selected_traverser ) {
		delete s_selected_traverser;
		s_selected_traverser = NULL;
	}

	s_selected_traverser = t;
	return TRUE;
}

BOOL WINAPI _export SEVENZ_OpenArchive(const char *Name,int *Type,bool Silent)
{
	if (!s_selected_traverser)
		return FALSE;
	return TRUE;
}

int WINAPI _export SEVENZ_GetArcItem(struct PluginPanelItem *Item, struct ArcItemInfo *Info)
{
	if (!s_selected_traverser)
		return GETARC_READERROR;
		
	return s_selected_traverser->Next(Item, Info);
}


BOOL WINAPI _export SEVENZ_CloseArchive(struct ArcInfo *Info)
{
	if (!s_selected_traverser)
		return FALSE;
		
	delete s_selected_traverser;
	s_selected_traverser = NULL;
	return TRUE;
}

void  WINAPI _export SEVENZ_SetFarInfo(const struct PluginStartupInfo *Info)
{
   gInfo = *Info;
}

BOOL WINAPI _export SEVENZ_GetFormatName(int Type,char *FormatName,char *DefaultExt)
{
  if (Type==0)
  {
    strcpy(FormatName,"7Z");
    strcpy(DefaultExt,"7z");
    return TRUE;
  }
  return FALSE;
}

BOOL WINAPI _export SEVENZ_GetDefaultCommands(int Type,int Command,char *Dest)
{
  if (Type==0)
  {
    static const char *Commands[]={
    /*Extract               */"^7z x -snld {-p%%P} %%A %%FMq*4096",
    /*Extract without paths */"^7z e -snld {-p%%P} %%A %%FMq*4096",
    /*Test                  */"^7z t %%A",
    /*Delete                */"^7z d {-p%%P} %%A @%%LN",
    /*Comment archive       */"",
    /*Comment files         */"",
    /*Convert to SFX        */"",
    /*Lock archive          */"",
    /*Protect archive       */"",
    /*Recover archive       */"",
    /*Add files             */"^7z a -y {-p%%P} -snh -snl %%A @%%LN",
    /*Move files            */"^7z a -y -sdel {-p%%P} -snh -snl %%A @%%LN",
    /*Add files and folders */"^7z a -y -r {-p%%P} -snh -snl %%A @%%LN",
    /*Move files and folders*/"^7z a -y -r -sdel {-p%%P} -snh -snl %%A @%%LN",
    /*"All files" mask      */"*"
    };
    if (Command<(int)(ARRAYSIZE(Commands)))
    {
      strcpy(Dest,Commands[Command]);
      return(TRUE);
    }
  }
  return(FALSE);
}

extern "C" int sevenz_main(int numargs, char *args[])
{
	return Main2(numargs, args);
}
