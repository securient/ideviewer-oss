; Inno Setup Script for IDE Viewer (ARM64)
; 
; Note: Inno Setup 6.3+ supports ARM64
; https://jrsoftware.org/isinfo.php
;

#define MyAppName "IDE Viewer"
#define MyAppVersion "0.1.0"
#define MyAppPublisher "IDE Viewer Team"
#define MyAppURL "https://github.com/ideviewer/ideviewer"
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
; Send uninstall notification to the portal before removing
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""try {{ $cfg = Get-Content \"$env:USERPROFILE\.ideviewer\config.json\" | ConvertFrom-Json; $body = @{{ hostname = $env:COMPUTERNAME; alert_type = 'uninstall_attempt'; details = 'IDE Viewer is being uninstalled on Windows (ARM64).' }} | ConvertTo-Json; Invoke-RestMethod -Uri \"$($cfg.portal_url)/api/alert\" -Method POST -Body $body -ContentType 'application/json' -Headers @{{ 'X-Customer-Key' = $cfg.customer_key }} -TimeoutSec 10 }} catch {{}}"""; Flags: runhidden; RunOnceId: "NotifyPortal"
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
