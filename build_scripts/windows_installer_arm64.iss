; Inno Setup Script for IDE Viewer (ARM64)
; 
; Note: Inno Setup 6.3+ supports ARM64
; https://jrsoftware.org/isinfo.php
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
AppId={{8F5A3B2C-1D4E-5F6A-7B8C-9D0E1F2A3B4D}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
DisableProgramGroupPage=yes
OutputDir=..\dist
OutputBaseFilename=IDEViewer-Setup-{#MyAppVersion}-arm64
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=admin
MinVersion=10.0
WizardStyle=modern
ArchitecturesAllowed=arm64
ArchitecturesInstallIn64BitMode=arm64
LicenseFile=..\LICENSE

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "addtopath"; Description: "Add IDE Viewer to system PATH"; GroupDescription: "Additional options:"; Flags: checkedonce

[Files]
Source: "..\dist\ideviewer.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\IDE Viewer"; Filename: "{cmd}"; Parameters: "/k ""{app}\{#MyAppExeName}"""; WorkingDir: "{app}"
Name: "{group}\Uninstall IDE Viewer"; Filename: "{uninstallexe}"

[Registry]
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Tasks: addtopath; Check: NeedsAddPath('{app}')

[Run]
Filename: "{cmd}"; Parameters: "/k echo IDE Viewer installed! && echo. && echo Run: ideviewer register --customer-key KEY --portal-url URL && pause"; Flags: postinstall nowait skipifsilent

[UninstallRun]
; Stop daemon if running
Filename: "taskkill"; Parameters: "/F /IM ideviewer.exe"; Flags: runhidden; RunOnceId: "StopDaemon"

[Code]
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
  Result := Pos(';' + Param + ';', ';' + OrigPath + ';') = 0;
end;

procedure NotifyPortalOfUninstall();
var
  ConfigPath: string;
  ResultCode: Integer;
begin
  ConfigPath := ExpandConstant('{userprofile}') + '\.ideviewer\config.json';
  if FileExists(ConfigPath) then
  begin
    Exec('powershell.exe',
      '-NoProfile -ExecutionPolicy Bypass -File NUL -Command "' +
      'try { $c = Get-Content ''' + ConfigPath + ''' | ConvertFrom-Json; ' +
      '$h = @{''X-Customer-Key'' = $c.customer_key; ''Content-Type'' = ''application/json''}; ' +
      '$b = ''{\"hostname\":\"'' + $env:COMPUTERNAME + ''\",\"alert_type\":\"uninstall_attempt\",\"details\":\"IDE Viewer uninstalled on Windows ARM64\"}''; ' +
      'Invoke-RestMethod -Uri ($c.portal_url + ''/api/alert'') -Method POST -Body $b -Headers $h -TimeoutSec 10 } catch {}"',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;

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
