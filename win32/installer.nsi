; Script based on the Facebook Plugin for Pidgin NSI files

SetCompress auto
SetCompressor lzma

; todo: SetBrandingImage
; HM NIS Edit Wizard helper defines
!define PRODUCT_NAME "msn-pecan"
!define PRODUCT_VERSION "0.0.19"
!define PRODUCT_PUBLISHER "Felipe Contreras"
!define PRODUCT_WEB_SITE "http://msn-pecan.googlecode.com/"
!define PRODUCT_UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
!define PRODUCT_UNINST_ROOT_KEY "HKLM"

; MUI 1.67 compatible ------
!include "MUI.nsh"

; MUI Settings
!define MUI_ABORTWARNING
!define MUI_ICON "${NSISDIR}\Contrib\Graphics\Icons\modern-install.ico"
!define MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\modern-uninstall.ico"

; Welcome page
!insertmacro MUI_PAGE_WELCOME
; License page
!insertmacro MUI_PAGE_LICENSE "COPYING"
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

ShowInstDetails show
ShowUnInstDetails show

Section "Install"
    ;Check for pidgin installation
    Call GetPidginInstPath

    SetOverwrite try
	start:
		ClearErrors
		Delete "$INSTDIR\plugins\libmsn-pecan.dll"
		IfErrors busy
		SetOutPath "$INSTDIR\plugins"
		File "libmsn-pecan.dll"
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
		Delete "$INSTDIR\msn-pecan-uninstall.exe"
		DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\msn-pecan"

SectionEnd

Function GetPidginInstPath
  Push $0
  ReadRegStr $0 HKLM "Software\pidgin" ""
	IfFileExists "$0\pidgin.exe" cont
	ReadRegStr $0 HKCU "Software\pidgin" ""
	IfFileExists "$0\pidgin.exe" cont
		MessageBox MB_OK|MB_ICONINFORMATION "Failed to find Pidgin installation."
		Abort "Failed to find Pidgin installation. Please install Pidgin first."
  cont:
	StrCpy $INSTDIR $0
FunctionEnd

Function RunPidgin
	ExecShell "" "$INSTDIR\pidgin.exe"
FunctionEnd
