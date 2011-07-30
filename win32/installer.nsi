; Script based on the Facebook Plugin for Pidgin NSI files

SetCompress auto
SetCompressor lzma

; todo: SetBrandingImage
; HM NIS Edit Wizard helper defines
!define PRODUCT_NAME "msn-pecan"
!define PRODUCT_VERSION "0.1.3"
!define PRODUCT_PUBLISHER "Felipe Contreras"
!define PRODUCT_WEB_SITE "http://msn-pecan.googlecode.com/"
!define PRODUCT_UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
!define PRODUCT_UNINST_ROOT_KEY "HKLM"

!include "MUI2.nsh"

; MUI Settings
!define MUI_ABORTWARNING
!define MUI_ICON "${NSISDIR}\Contrib\Graphics\Icons\orange-install.ico"
!define MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\orange-uninstall.ico"

; Welcome page
!insertmacro MUI_PAGE_WELCOME
; License page
!insertmacro MUI_PAGE_LICENSE "libmsn-pecan/COPYING"
; Directory page
!define MUI_PAGE_CUSTOMFUNCTION_PRE dir_pre
!insertmacro MUI_PAGE_DIRECTORY
; Instfiles page
!insertmacro MUI_PAGE_INSTFILES
; Finish page
!define MUI_FINISHPAGE_SHOWREADME "http://code.google.com/p/msn-pecan/wiki/HowToUse"
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_TEXT "Run Pidgin"
!define MUI_FINISHPAGE_RUN_FUNCTION "RunPidgin"
!insertmacro MUI_PAGE_FINISH

; Uninstaller pages
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

; Language files
!insertmacro MUI_LANGUAGE "English"

; MUI end ------

Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "${PRODUCT_NAME}-${PRODUCT_VERSION}.exe"
InstallDir "$PROGRAMFILES\pidgin"

ShowInstDetails show
ShowUnInstDetails show

Function dir_pre
    readregstr $0 HKLM "Software\pidgin" ""
    iffileexists "$0\pidgin.exe" found
    readregstr $0 HKCU "Software\pidgin" ""
    iffileexists "$0\pidgin.exe" found
    goto done
found:
    strcpy $INSTDIR $0
    abort
done:
Functionend


Section "Install"
    iffileexists "$INSTDIR\pidgin.exe" cont
    messagebox MB_OK|MB_ICONINFORMATION "Failed to find Pidgin installation."
    abort "Failed to find Pidgin installation. Please install Pidgin first."
    cont:

    SetOverwrite try
	start:
		ClearErrors
		Delete "$INSTDIR\plugins\libmsn-pecan.dll"
		IfErrors busy
		SetOutPath "$INSTDIR"
		File /r libmsn-pecan\*.*
		Goto after
	busy:
		MessageBox MB_RETRYCANCEL "libmsn-pecan.dll is busy. Please close Pidgin (including tray icon) and try again" IDCANCEL cancel
		Goto start
	cancel:
		Abort "Installation of msn-pecan aborted"
	after:
		WriteUninstaller "$INSTDIR\msn-pecan-uninstall.exe"
		WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\msn-pecan" \
				 "DisplayName" "MSN (pecan) protocol plug-in"
		WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\msn-pecan" \
				 "UninstallString" "$\"$INSTDIR\msn-pecan-uninstall.exe$\""
		WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\msn-pecan" \
				 "QuietUninstallString" "$\"$INSTDIR\msn-pecan-uninstall.exe$\" /S"

SectionEnd

Section "Uninstall"
    SetOverwrite try
	start:
		ClearErrors
		Delete "$INSTDIR\plugins\libmsn-pecan.dll"
		IfErrors busy
		Goto after
	busy:
		MessageBox MB_RETRYCANCEL "libmsn-pecan.dll is busy. Please close Pidgin (including tray icon) and try again" IDCANCEL cancel
		Goto start
	cancel:
		Abort "Uninstallation of msn-pecan aborted"
	after:
		Delete "$INSTDIR\locale\ar\LC_MESSAGES\libmsn-pecan.mo"
		Delete "$INSTDIR\locale\da\LC_MESSAGES\libmsn-pecan.mo"
		Delete "$INSTDIR\locale\de\LC_MESSAGES\libmsn-pecan.mo"
		Delete "$INSTDIR\locale\eo\LC_MESSAGES\libmsn-pecan.mo"
		Delete "$INSTDIR\locale\es\LC_MESSAGES\libmsn-pecan.mo"
		Delete "$INSTDIR\locale\fi\LC_MESSAGES\libmsn-pecan.mo"
		Delete "$INSTDIR\locale\fr\LC_MESSAGES\libmsn-pecan.mo"
		Delete "$INSTDIR\locale\tr\LC_MESSAGES\libmsn-pecan.mo"
		Delete "$INSTDIR\locale\hu\LC_MESSAGES\libmsn-pecan.mo"
		Delete "$INSTDIR\locale\it\LC_MESSAGES\libmsn-pecan.mo"
		Delete "$INSTDIR\locale\nb\LC_MESSAGES\libmsn-pecan.mo"
		Delete "$INSTDIR\locale\nl\LC_MESSAGES\libmsn-pecan.mo"
		Delete "$INSTDIR\locale\pt_BR\LC_MESSAGES\libmsn-pecan.mo"
		Delete "$INSTDIR\locale\pt\LC_MESSAGES\libmsn-pecan.mo"
		Delete "$INSTDIR\locale\sr\LC_MESSAGES\libmsn-pecan.mo"
		Delete "$INSTDIR\locale\sv\LC_MESSAGES\libmsn-pecan.mo"
		Delete "$INSTDIR\locale\tr\LC_MESSAGES\libmsn-pecan.mo"
		Delete "$INSTDIR\locale\zh_CN\LC_MESSAGES\libmsn-pecan.mo"
		Delete "$INSTDIR\locale\zh_TW\LC_MESSAGES\libmsn-pecan.mo"
		Delete "$INSTDIR\msn-pecan-uninstall.exe"
		DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\msn-pecan"

SectionEnd

Function RunPidgin
	ExecShell "" "$INSTDIR\pidgin.exe"
FunctionEnd
