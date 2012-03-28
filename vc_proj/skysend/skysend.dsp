# Microsoft Developer Studio Project File - Name="skysend" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

CFG=skysend - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "skysend.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "skysend.mak" CFG="skysend - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "skysend - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "skysend - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "skysend - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /Yu"stdafx.h" /FD /c
# ADD CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /Yu"stdafx.h" /FD /c
# ADD BASE RSC /l 0x809 /d "NDEBUG"
# ADD RSC /l 0x809 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /machine:I386

!ELSEIF  "$(CFG)" == "skysend - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /Yu"stdafx.h" /FD /GZ /c
# ADD CPP /nologo /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /FD /GZ /c
# SUBTRACT CPP /YX /Yc /Yu
# ADD BASE RSC /l 0x809 /d "_DEBUG"
# ADD RSC /l 0x809 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib ws2_32.lib ms32.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept

!ENDIF 

# Begin Target

# Name "skysend - Win32 Release"
# Name "skysend - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Group "crypto_c"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\crypto\crypto.c
# End Source File
# Begin Source File

SOURCE=.\crypto\miramax.c
# End Source File
# Begin Source File

SOURCE=.\crypto\rijndael.c
# End Source File
# Begin Source File

SOURCE=.\crypto\sha.c
# End Source File
# End Group
# Begin Group "blobs_c"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\blobs\blob1.c
# End Source File
# Begin Source File

SOURCE=.\blobs\blob1s.c
# End Source File
# Begin Source File

SOURCE=.\blobs\blob2.c
# End Source File
# Begin Source File

SOURCE=.\blobs\blob2s.c
# End Source File
# Begin Source File

SOURCE=.\blobs\blob3s.c
# End Source File
# Begin Source File

SOURCE=.\blobs\blob4s.c
# End Source File
# Begin Source File

SOURCE=.\blobs\blob_enc.c
# End Source File
# Begin Source File

SOURCE=.\blobs\blob_newblk.c
# End Source File
# End Group
# Begin Group "rc4_c"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\rc4\Expand_IV.c
# End Source File
# End Group
# Begin Source File

SOURCE=.\decode41.c
# End Source File
# Begin Source File

SOURCE=.\process_cmd.c
# End Source File
# Begin Source File

SOURCE=.\skysend.c
# End Source File
# Begin Source File

SOURCE=.\sock_comm.c
# End Source File
# Begin Source File

SOURCE=.\tcp_sess1.c
# End Source File
# Begin Source File

SOURCE=.\tcp_setup.c
# End Source File
# Begin Source File

SOURCE=.\util.c
# End Source File
# Begin Source File

SOURCE=.\util_crc32.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Group "crypto"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\crypto\aes.h
# End Source File
# Begin Source File

SOURCE=.\crypto\crypto.h
# End Source File
# Begin Source File

SOURCE=.\crypto\miracl.h
# End Source File
# Begin Source File

SOURCE=.\crypto\mirdef.h
# End Source File
# Begin Source File

SOURCE=.\crypto\rijndael.h
# End Source File
# Begin Source File

SOURCE=.\crypto\sha.h
# End Source File
# End Group
# Begin Group "blobs"

# PROP Default_Filter ""
# End Group
# Begin Group "rc4"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\rc4\Expand_IV.h
# End Source File
# Begin Source File

SOURCE=.\rc4\Process_IV.h
# End Source File
# End Group
# Begin Source File

SOURCE=.\decode41.h
# End Source File
# Begin Source File

SOURCE=.\defs.h
# End Source File
# Begin Source File

SOURCE=.\global_vars.h
# End Source File
# Begin Source File

SOURCE=.\short_types.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# End Group
# Begin Source File

SOURCE=.\ReadMe.txt
# End Source File
# End Target
# End Project
