#include "MultiArc.hpp"
#include "marclng.hpp"
#include <errno.h>

BOOL PluginClass::GetFormatName(char *FormatName, char *DefExt)
{
  *FormatName=0;
  if(DefExt)
    *DefExt=0;
  char TempDefExt[NM];
  return ArcPlugin->GetFormatName(ArcPluginNumber,ArcPluginType,FormatName,DefExt?DefExt:TempDefExt);
}

void PluginClass::GetCommandFormat(int Command,char *Format,int FormatSize)
{
  //*Format=0;
  char ArcFormat[100]/*,DefExt[NM]*/;
  /*if (!ArcPlugin->GetFormatName(ArcPluginNumber,ArcPluginType,ArcFormat,DefExt))
    return;*/
  if(!GetFormatName(ArcFormat))
    return;
  ArcPlugin->GetDefaultCommands(ArcPluginNumber,ArcPluginType,Command,Format);
  KeyFileReadSection(INI_LOCATION,ArcFormat).GetChars(Format, FormatSize, CmdNames[Command],Format);
}


int PluginClass::DeleteFiles(struct PluginPanelItem *PanelItem,int ItemsNumber,int OpMode)
{
  char Command[MA_MAX_SIZE_COMMAND_NAME],AllFilesMask[MA_MAX_SIZE_COMMAND_NAME];
  if (ItemsNumber==0)
    return FALSE;
  if ((OpMode & OPM_SILENT)==0)
  {
    const char *MsgItems[]={GetMsg(MDeleteTitle),GetMsg(MDeleteFiles),
                      GetMsg(MDeleteDelete),GetMsg(MDeleteCancel)};
    char Msg[512];
    if (ItemsNumber==1)
    {
      char NameMsg[NM];
      FSF.TruncPathStr(strncpy(NameMsg,PanelItem[0].FindData.cFileName,sizeof(NameMsg)-1),MAX_WIDTH_MESSAGE);
      FSF.sprintf(Msg,GetMsg(MDeleteFile),NameMsg);
      MsgItems[1]=Msg;
    }
    if (Info.Message(Info.ModuleNumber,0,NULL,MsgItems,ARRAYSIZE(MsgItems),2)!=0)
      return FALSE;
    if (ItemsNumber>1)
    {
      char Msg[100];
      FSF.sprintf(Msg,GetMsg(MDeleteNumberOfFiles),ItemsNumber);
      MsgItems[1]=Msg;
      if (Info.Message(Info.ModuleNumber,FMSG_WARNING,NULL,MsgItems,ARRAYSIZE(MsgItems),2)!=0)
        return FALSE;
    }
  }
  GetCommandFormat(CMD_DELETE,Command,sizeof(Command));
  GetCommandFormat(CMD_ALLFILESMASK,AllFilesMask,sizeof(AllFilesMask));
  int IgnoreErrors=(CurArcInfo.Flags & AF_IGNOREERRORS);
  ArcCommand ArcCmd(PanelItem,ItemsNumber,Command,ArcName,CurDir,"",AllFilesMask,IgnoreErrors,0,0,CurDir,ItemsInfo.Codepage);
  if (!IgnoreErrors && ArcCmd.GetExecCode()!=0)
    return FALSE;
  if (Opt.UpdateDescriptions)
    for (int I=0;I<ItemsNumber;I++)
      PanelItem[I].Flags|=PPIF_PROCESSDESCR;
  return TRUE;
}


int PluginClass::ProcessHostFile(struct PluginPanelItem *PanelItem,int ItemsNumber,int OpMode)
{
  struct ArcCmdMenuData{ int Msg, Cmd; };
  static const ArcCmdMenuData MenuData[]=
  {
    {MArcCmdTest,         CMD_TEST        },
    {MArcCmdComment,      CMD_COMMENT     },
    {MArcCmdCommentFiles, CMD_COMMENTFILES},
    {MArcCmdSFX,          CMD_SFX         },
    {MArcCmdRecover,      CMD_RECOVER     },
    {MArcCmdProtect,      CMD_PROTECT     },
    {MArcCmdLock,         CMD_LOCK        },
  };

  char Command[MA_MAX_SIZE_COMMAND_NAME],AllFilesMask[MA_MAX_SIZE_COMMAND_NAME];
  int CommandType;
  int ExitCode=0;

  while(1)
  {
    struct FarMenuItemEx MenuItems[ARRAYSIZE(MenuData)];

    memset(MenuItems,0,sizeof(MenuItems));
    MenuItems[ExitCode].Flags=MIF_SELECTED;

    int Count=0;
    for(size_t i=0; i<ARRAYSIZE(MenuData); i++)
    {
      GetCommandFormat(MenuData[i].Cmd, Command, sizeof(Command));
      if(*Command)
      {
        MenuItems[Count].Text.TextPtr=GetMsg(MenuData[i].Msg);
        MenuItems[Count].Flags|=MIF_USETEXTPTR;
        MenuItems[Count++].UserData=MenuData[i].Cmd;
      }
    }

    if(!Count)
    {
      Count=1;
      MenuItems[0].UserData=0xFFFFFFFF;
    }

    int BreakCode;
    int BreakKeys[2]={VK_F4,0};
    ExitCode=Info.Menu(Info.ModuleNumber,-1,-1,0,FMENU_USEEXT|FMENU_WRAPMODE,
         GetMsg(MArcCmdTitle),GetMsg(MSelectF4),"ArcCmd",BreakKeys,&BreakCode,
         (FarMenuItem *)MenuItems,Count);
    if(ExitCode>=0)
    {
      if(BreakCode == 0)  // F4 pressed
      {
        MenuItems[0].Flags&=~MIF_USETEXTPTR;
        GetFormatName(MenuItems[0].Text.Text);
        ConfigCommands(MenuItems[0].Text.Text,2+MenuData[ExitCode].Cmd*2);
        continue;
      }
      CommandType=(int)MenuItems[ExitCode].UserData;
      if(MenuItems[ExitCode].UserData==0xFFFFFFFF)
        return FALSE;
    }
    else
      return FALSE;
    break;
  }

  WINPORT(FlushConsoleInputBuffer)(NULL);//GetStdHandle(STD_INPUT_HANDLE));

  GetCommandFormat(CommandType,Command,sizeof(Command));
  GetCommandFormat(CMD_ALLFILESMASK,AllFilesMask,sizeof(AllFilesMask));
  int IgnoreErrors=(CurArcInfo.Flags & AF_IGNOREERRORS);
  char Password[512];
  *Password=0;

  int AskVolume=(OpMode & (OPM_FIND|OPM_VIEW|OPM_EDIT|OPM_QUICKVIEW))==0 &&
                CurArcInfo.Volume && *CurDir==0 && ExitCode==0;
  struct PluginPanelItem MaskPanelItem;

  if (AskVolume)
  {
    char VolMsg[300];
    char NameMsg[NM];
    FSF.TruncPathStr(strncpy(NameMsg,FSF.PointToName(ArcName),sizeof(NameMsg)-1),MAX_WIDTH_MESSAGE);
    FSF.sprintf(VolMsg,GetMsg(MExtrVolume),NameMsg);
    const char *MsgItems[]={"",VolMsg,GetMsg(MExtrVolumeAsk1),
                      GetMsg(MExtrVolumeAsk2),GetMsg(MExtrVolumeSelFiles),
                      GetMsg(MExtrAllVolumes)};
    int MsgCode=Info.Message(Info.ModuleNumber,0,NULL,MsgItems,ARRAYSIZE(MsgItems),2);
    if (MsgCode<0)
      return -1;
    if (MsgCode==1)
    {
      memset(&MaskPanelItem,0,sizeof(MaskPanelItem));
      strncpy(MaskPanelItem.FindData.cFileName,AllFilesMask,ARRAYSIZE(MaskPanelItem.FindData.cFileName)-1);
      if (ItemsInfo.Encrypted)
        MaskPanelItem.Flags=F_ENCRYPTED;
      PanelItem=&MaskPanelItem;
      ItemsNumber=1;
    }
  }

  if (strstr(Command,"%%P")!=NULL)
    for (int I=0;I<ItemsNumber;I++)
      if ((PanelItem[I].Flags & F_ENCRYPTED) || (ItemsInfo.Encrypted &&
          (PanelItem[I].FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)))
      {
        if (!GetPassword(Password,FSF.PointToName(ArcName)))
          return FALSE;
        break;
      }

  ArcCommand ArcCmd(PanelItem,ItemsNumber,Command,ArcName,CurDir,Password,AllFilesMask,
                    IgnoreErrors,CommandType==CMD_COMMENT || CommandType==CMD_COMMENTFILES ? 2:0,0,
                    CurDir,ItemsInfo.Codepage);
  return IgnoreErrors || ArcCmd.GetExecCode()==0;
}


int __cdecl FormatSort(struct FarMenuItemEx *Item1,struct FarMenuItemEx *Item2)
{
  #ifdef _NEW_ARC_SORT_
  int Temp=(int)Item2->UserData-(int)Item1->UserData;
  return Temp?Temp:(int)Item1->UserData==-1?0:FSF.LStricmp(Item1->Text.Text,Item2->Text.Text);
  #else
  return strcasecmp(Item1->Text.Text,Item2->Text.Text);
  #endif
}

int PluginClass::SelectFormat(char *ArcFormat,int AddOnly)
{
  typedef int (__cdecl *FCmp)(const void *, const void *);
  struct FarMenuItemEx *MenuItems=NULL, *NewMenuItems;
  int MenuItemsNumber=0;
  char Format[100],DefExt[NM];
  int BreakCode;
  int BreakKeys[]={VK_F4,VK_RETURN,0};
  int ExitCode;

  #ifdef _NEW_ARC_SORT_
  int SortModeIndex=GetPrivateProfileInt("MultiArc", "SortMode", 1, IniFile);
  char *SortMode;
  if(SortModeIndex<=1 || SortModeIndex>=ARRAYSIZE(SortModes))
    SortMode=NULL;
  else
    SortMode=SortModes[SortModeIndex];
  #endif

  BreakKeys[1]=(AddOnly)?0:VK_RETURN;

  while(1)
  {
    for(int i=0; i<ArcPlugin->FmtCount(); i++)
    {
      for(int j=0; ; j++)
      {
        if(!ArcPlugin->GetFormatName(i, j, Format, DefExt))
          break;

        if(AddOnly) // Only add to archive?
        {
          char Buffer[MA_MAX_SIZE_COMMAND_NAME];
          ArcPlugin->GetDefaultCommands(i, j, CMD_ADD, Buffer);
          KeyFileReadSection(INI_LOCATION, Format).GetChars(Buffer,sizeof(Buffer),CmdNames[CMD_ADD],Buffer);
          if(*Buffer==0)
            continue;
        }

        NewMenuItems=(struct FarMenuItemEx *)realloc(MenuItems,
                             (MenuItemsNumber+1)*sizeof(struct FarMenuItemEx));
        if (NewMenuItems==NULL)
        {
          free(MenuItems);
          return FALSE;
        }
        MenuItems=NewMenuItems;
        memset(MenuItems+MenuItemsNumber,0,sizeof(struct FarMenuItemEx));
        MenuItems[MenuItemsNumber].UserData = MAKEWPARAM((WORD)i,(WORD)j);
        strncpy(MenuItems[MenuItemsNumber].Text.Text,Format,sizeof(MenuItems[MenuItemsNumber].Text.Text)-1);
        MenuItems[MenuItemsNumber].Flags=((MenuItemsNumber==0 &&
                                          *ArcFormat==0) ||
                                          !strcasecmp(ArcFormat,Format))?
                                          MIF_SELECTED:0;
        #ifdef _NEW_ARC_SORT_
        if(SortMode)
          MenuItems[MenuItemsNumber].UserData=GetPrivateProfileInt(SortMode, Format, 0, IniFile);
        else
          MenuItems[MenuItemsNumber].UserData=SortModeIndex?0:-1;
        #endif

        MenuItemsNumber++;
      }
    }
    if (MenuItemsNumber==0)
      return FALSE;

    FSF.qsort(MenuItems,MenuItemsNumber,sizeof(struct FarMenuItemEx),(FCmp)FormatSort);

    DWORD Flags=FMENU_AUTOHIGHLIGHT|FMENU_USEEXT;
    if(!Opt.AdvFlags.MenuWrapMode)
      Flags|=FMENU_WRAPMODE;
    else if(Opt.AdvFlags.MenuWrapMode==2)
    {
      CONSOLE_SCREEN_BUFFER_INFO csbi;
      WINPORT(GetConsoleScreenBufferInfo)(NULL, &csbi);//GetStdHandle(STD_OUTPUT_HANDLE)
      if(csbi.dwSize.Y-6>=MenuItemsNumber)
        Flags|=FMENU_WRAPMODE;
    }
    ExitCode=Info.Menu(Info.ModuleNumber,-1,-1,0,Flags,
                       GetMsg(MSelectArchiver),GetMsg(MSelectF4),NULL,
                       BreakKeys,&BreakCode,
                       (struct FarMenuItem*)MenuItems,MenuItemsNumber);
    if (ExitCode>=0)
    {
      strcpy(ArcFormat,MenuItems[ExitCode].Text.Text);
      if((BreakCode >=0 && BreakCode <= 1) || !AddOnly)  // F4 or Enter pressed
        ConfigCommands(ArcFormat,2,TRUE,LOWORD(MenuItems[ExitCode].UserData),HIWORD(MenuItems[ExitCode].UserData));
      else
        break;
    }
    else
      break;
    free(MenuItems);
    MenuItems=NULL;
    MenuItemsNumber=0;
  }
  if(MenuItems)
    free(MenuItems);
  return ExitCode >= 0;
}


int PluginClass::FormatToPlugin(char *Format, int &PluginNumber, int &PluginType)
{
  char PluginFormat[100], DefExt[NM];
  for(int i=0; i<ArcPlugin->FmtCount(); i++)
  {
    for(int j=0; ; j++)
    {
      if(!ArcPlugin->GetFormatName(i, j, PluginFormat, DefExt))
        break;
      if(!strcasecmp(PluginFormat,Format))
      {
        PluginNumber=i;
        PluginType=j;
        return TRUE;
      }
    }
  }
  return FALSE;
}

SHAREDSYMBOL int WINAPI _export Configure(int ItemNumber);

int PluginClass::ProcessKey(int Key,unsigned int ControlState)
{
  if ((ControlState & PKF_ALT) && Key==VK_F6)
  {
//    HANDLE hScreen=Info.SaveScreen(0,0,-1,-1);
    if(strstr(ArcName,/*"FarTmp"*/"FTMP")==NULL)//$AA какая-то бяка баловалась
    {
      char CurDir[NM];
      strcpy(CurDir,ArcName);
      char *Slash=strrchr(CurDir, GOOD_SLASH);
      if (Slash!=NULL)
      {
		  if (Slash!=CurDir)
			  *Slash = 0;
        //if (Slash!=CurDir && *(Slash-1)==':')
         // Slash[1]=0;
        //else
         // *Slash=0;
        if (sdc_chdir(CurDir)) fprintf(stderr, "sdc_chdir('%s') - %u\n", CurDir, errno);
      }
    }
    struct PanelInfo PInfo;
    Info.Control(this,FCTL_GETPANELINFO,&PInfo);
    GetFiles(PInfo.SelectedItems,PInfo.SelectedItemsNumber,FALSE,PInfo.CurDir,OPM_SILENT);
//    Info.RestoreScreen(hScreen);
    Info.Control(this,FCTL_UPDATEPANEL,(void*)1);
    Info.Control(this,FCTL_REDRAWPANEL,NULL);
    Info.Control(this,FCTL_UPDATEANOTHERPANEL,(void*)1);
    Info.Control(this,FCTL_REDRAWANOTHERPANEL,NULL);
    return TRUE;
  }
  else if (ControlState==(PKF_ALT|PKF_SHIFT) && Key==VK_F9)
  {
    Configure(0);
    return TRUE;
  }
  return FALSE;
}