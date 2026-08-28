; Inno Setup Script for IDE Viewer
; 
; Requirements:
;   - Inno Setup 6.x (https://jrsoftware.org/isinfo.php)
;
; Build:
;   Run build_windows.bat or compile this script directly with Inno Setup
;

#define MyAppName "IDE Viewer"
#ifndef APP_VERSION
  #define MyAppVersion "0.1.0"
#else
  #define MyAppVersion APP_VERSION
#endif
#define MyAppPublisher "Securient"
#define MyAppURL "https://github.com/securient/ideviewer-oss"
#define MyAppExeName "ideviewer.exe"

[Setup]
; Application info
AppId={{8F5A3B2C-1D4E-5F6A-7B8C-9D0E1F2A3B4C}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}

; Installation settings
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
DisableProgramGroupPage=yes

; Output settings
OutputDir=..\dist
OutputBaseFilename=IDEViewer-Setup-{#MyAppVersion}
UninstallDisplayIcon={app}\{#MyAppExeName}

; Compression
Compression=lzma2
SolidCompression=yes

; Privileges (admin required for PATH modification)
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog

; Windows version requirements
MinVersion=10.0

; Wizard settings
WizardStyle=modern
WizardSizePercent=100

; License
LicenseFile=..\LICENSE

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "addtopath"; Description: "Add IDE Viewer to system PATH"; GroupDescription: "Additional options:"; Flags: checkedonce
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; Main executable
Source: "..\dist\ideviewer.exe"; DestDir: "{app}"; Flags: ignoreversion

; Include any additional DLLs if needed
; Source: "..\dist\*.dll"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
; Start Menu
Name: "{group}\IDE Viewer (Command Prompt)"; Filename: "{cmd}"; Parameters: "/k ""{app}\{#MyAppExeName}"""; WorkingDir: "{app}"
Name: "{group}\IDE Viewer - Scan"; Filename: "{cmd}"; Parameters: "/k ""{app}\{#MyAppExeName}"" scan"; WorkingDir: "{app}"
Name: "{group}\Uninstall IDE Viewer"; Filename: "{uninstallexe}"

; Desktop (optional)
Name: "{autodesktop}\IDE Viewer"; Filename: "{cmd}"; Parameters: "/k ""{app}\{#MyAppExeName}"""; WorkingDir: "{app}"; Tasks: desktopicon

[Registry]
; Add to PATH if selected
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Tasks: addtopath; Check: NeedsAddPath('{app}')

[Run]
; Show quick help after install
Filename: "{cmd}"; Parameters: "/k echo. && echo ============================================ && echo   IDE Viewer installed successfully! && echo ============================================ && echo. && echo IMPORTANT: You need a Customer Key to use this daemon. && echo. && echo Step 1: Get your customer key from the IDE Viewer Portal && echo Step 2: Register this machine: && echo. && echo   ideviewer register --customer-key YOUR_KEY --portal-url https://portal.example.com && echo. && echo Step 3: Start the daemon: && echo   ideviewer daemon --foreground && echo. && echo Press any key to close... && pause >nul"; Description: "Show setup instructions"; Flags: postinstall nowait skipifsilent

[UninstallRun]
; Ask the daemon to shut down cleanly first so it can post its "daemon_stopping"
; alert to the portal, then remove the logon task, then force-kill any straggler.
Filename: "{app}\{#MyAppExeName}"; Parameters: "stop"; Flags: runhidden; RunOnceId: "StopDaemon"
Filename: "schtasks"; Parameters: "/Delete /F /TN ""IDEViewer Daemon"""; Flags: runhidden; RunOnceId: "RemoveLogonTask"
Filename: "taskkill"; Parameters: "/F /IM ideviewer.exe"; Flags: runhidden; RunOnceId: "KillDaemon"

[UninstallDelete]
; Every directory IDEViewer can load a config from. Removing only
; {localappdata} left {commonappdata}\IDEViewer and {%USERPROFILE}\.ideviewer
; behind, and because those outrank the user config at load time, the *next*
; install silently ran on the previous install's portal URL, customer key and
; host token -- which looked like registration having no effect.
Type: filesandordirs; Name: "{localappdata}\IDEViewer"
Type: filesandordirs; Name: "{commonappdata}\IDEViewer"
Type: filesandordirs; Name: "{%USERPROFILE}\.ideviewer"

[Code]
// Check if the path already contains the app directory
function NeedsAddPath(Param: string): boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKEY_LOCAL_MACHINE,
    'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
    'Path', OrigPath)
  then begin
    Result := True;
    exit;
  end;
  // Look for the path with leading and trailing semicolon
  Result := Pos(';' + Param + ';', ';' + OrigPath + ';') = 0;
end;

// Send uninstall notification to portal
procedure NotifyPortalOfUninstall();
var
  ConfigPath: string;
  ResultCode: Integer;
begin
  // Must match internal/config.configCandidates() priority order. This used to
  // look only at {%USERPROFILE}\.ideviewer, the legacy path -- but 'ideviewer
  // register' writes {localappdata}\IDEViewer, so on a normal install the file
  // was never found and the uninstall alert never reached the portal.
  ConfigPath := ExpandConstant('{commonappdata}') + '\IDEViewer\config.json';
  if not FileExists(ConfigPath) then
    ConfigPath := ExpandConstant('{localappdata}') + '\IDEViewer\config.json';
  if not FileExists(ConfigPath) then
    ConfigPath := ExpandConstant('{%USERPROFILE}') + '\.ideviewer\config.json';
  if FileExists(ConfigPath) then
  begin
    Exec('powershell.exe',
      '-NoProfile -ExecutionPolicy Bypass -File NUL -Command "' +
      'try { $c = Get-Content ''' + ConfigPath + ''' | ConvertFrom-Json; ' +
      '$h = @{''X-Customer-Key'' = $c.customer_key; ''Content-Type'' = ''application/json''}; ' +
      '$b = ''{\"hostname\":\"'' + $env:COMPUTERNAME + ''\",\"alert_type\":\"uninstall_attempt\",\"details\":\"IDE Viewer uninstalled on Windows\"}''; ' +
      'Invoke-RestMethod -Uri ($c.portal_url + ''/api/alert'') -Method POST -Body $b -Headers $h -TimeoutSec 10 } catch {}"',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;

// Remove from PATH on uninstall and notify portal
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Path: string;
  AppDir: string;
  P: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    NotifyPortalOfUninstall();
  end;
  
  if CurUninstallStep = usPostUninstall then
  begin
    if RegQueryStringValue(HKEY_LOCAL_MACHINE,
      'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
      'Path', Path) then
    begin
      AppDir := ExpandConstant('{app}');
      P := Pos(';' + AppDir, Path);
      if P > 0 then
      begin
        Delete(Path, P, Length(';' + AppDir));
        RegWriteStringValue(HKEY_LOCAL_MACHINE,
          'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
          'Path', Path);
      end;
    end;
  end;
end;

// Show a welcome message
procedure InitializeWizard();
begin
  WizardForm.WelcomeLabel2.Caption := 
    'IDE Viewer is a cross-platform daemon that detects installed IDEs and scans their extensions for security analysis.' + #13#10 + #13#10 +
    'Features:' + #13#10 +
    '• Detects VS Code, Cursor, JetBrains IDEs, Sublime Text, Vim/Neovim' + #13#10 +
    '• Analyzes extension permissions and capabilities' + #13#10 +
    '• Identifies potentially dangerous extensions' + #13#10 +
    '• Runs as a daemon for continuous monitoring' + #13#10 + #13#10 +
    'Click Next to continue.';
end;
