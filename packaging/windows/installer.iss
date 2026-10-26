; Inno Setup script for Proxmox Controller (run by build.py, which gives AppVersion and AppIdName).
; Saved as UTF-8 with a BOM: that is how Inno Setup knows it is not in the computer's code page (the · below).
; Installs for the current user without asking for an administrator (the user may choose all users instead).

#define AppName "Proxmox Controller"
#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef AppIdName
  #define AppIdName "store.themechanic.ProxmoxController"
#endif
#define AppExe "Proxmox Controller.exe"
#define BridgeExe "proxmox-controller-mcp.exe"
; virt-viewer, the SPICE console the app opens (sound, clipboard, USB): downloaded while installing when it is not
; on the computer yet, checked against this SHA-256 (measured 26/10 on virt-manager's official 11.0 release, 84 MB)
#define ViewerUrl "https://gitlab.com/virt-viewer/virt-viewer/-/releases/v11.0/downloads/virt-viewer-x64-11.0-1.0.msi"
#define ViewerSha256 "b7de0474e97fe1e81101f2406fcf603fe08666bcb3816c3c465c8d64330be610"

[Setup]
; The same AppId for every version: an install replaces the one before it.
AppId={{CD154B40-5EEA-477B-B826-A0F95650C4E8}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher=the mechanic
VersionInfoVersion={#AppVersion}
VersionInfoCompany=the mechanic
VersionInfoProductName={#AppName}
DefaultDirName={autopf}\{#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Windows 10 1809 or later, as Qt 6 needs
MinVersion=10.0.17763
OutputBaseFilename=ProxmoxController-{#AppVersion}-setup
SetupIconFile=build\app.ico
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
WizardStyle=modern
Compression=lzma2/max
SolidCompression=yes
; the app and its bridges are stopped by the code below, not by Windows' Restart Manager
CloseApplications=no

[Messages]
; the signature, low on the left of every page of the wizard
BeveledLabel=HOME LAB · by the mechanic

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "virtviewer"; Description: "Install virt-viewer, the SPICE console — sound, clipboard and USB (downloads 84 MB from virt-manager's site; Windows asks for an administrator)"; GroupDescription: "SPICE console:"; Check: not ViewerInstalled

[Files]
Source: "..\..\dist\pyinstaller\{#AppName}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
; The app's own AppUserModelID, as the app sets it: a pinned taskbar button is the app's
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"; AppUserModelID: "{#AppIdName}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; AppUserModelID: "{#AppIdName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExe}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent

[Code]
var
  DownloadPage: TDownloadWizardPage;

function ViewerInstalled(): Boolean;
var
  Found: TFindRec;
begin
  { where its installer puts it: C:\Program Files\VirtViewer v11.0-256\ (the app looks there too) }
  Result := FindFirst(ExpandConstant('{commonpf64}\VirtViewer*'), Found);
  if Result then
    FindClose(Found);
end;

function OnDownloadProgress(const Url, FileName: String; const Progress, ProgressMax: Int64): Boolean;
begin
  Result := True;
end;

procedure InitializeWizard;
begin
  DownloadPage := CreateDownloadPage('Downloading virt-viewer', 'The SPICE console, from virt-manager''s site.', @OnDownloadProgress);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if (CurPageID = wpReady) and WizardIsTaskSelected('virtviewer') and not ViewerInstalled() then
  begin
    DownloadPage.Clear;
    DownloadPage.Add('{#ViewerUrl}', 'virt-viewer.msi', '{#ViewerSha256}');
    DownloadPage.Show;
    try
      try
        DownloadPage.Download;  { the checksum is checked as it comes: a cut or altered file is refused }
      except
        if not DownloadPage.AbortedByUser then
          SuppressibleMsgBox('virt-viewer could not be downloaded (' + GetExceptionMessage + ').' + #13#10 +
                             'Proxmox Controller installs anyway; its built-in console works without it.',
                             mbInformation, MB_OK, IDOK);
      end;
    finally
      DownloadPage.Hide;
    end;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Code: Integer;
  Msi: String;
begin
  Msi := ExpandConstant('{tmp}\virt-viewer.msi');
  if (CurStep = ssPostInstall) and FileExists(Msi) then
    { its own installer, for all users: Windows asks for an administrator }
    ShellExec('runas', 'msiexec.exe', '/i "' + Msi + '" /passive /norestart', '', SW_SHOW, ewWaitUntilTerminated, Code);
end;

procedure StopRunning();
var
  Code: Integer;
begin
  { the app (it would keep its files) and the bridges Claude started }
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM "{#AppExe}"', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM "{#BridgeExe}"', '', SW_HIDE, ewWaitUntilTerminated, Code);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  StopRunning();
  Result := '';
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Code: Integer;
  Args: String;
begin
  if CurUninstallStep = usUninstall then
  begin
    StopRunning();
    Args := '--uninstall';
    if not UninstallSilent() and
       (MsgBox('Also remove your hosts, their API token secrets and the settings?' + #13#10#13#10 +
               'Choose No to keep them for a later install.', mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES) then
      Args := Args + ' --all';
    { before the files go: the start-at-login entry and the connector's entries in the Claude apps }
    Exec(ExpandConstant('{app}\{#BridgeExe}'), Args, '', SW_HIDE, ewWaitUntilTerminated, Code);
  end;
end;
