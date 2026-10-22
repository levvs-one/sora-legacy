#define MyAppName "Sora"
#define MyAppVersion "0.2.3"
#ifndef WindowsTarget
  #define WindowsTarget "win7"
#endif
#ifndef WindowsDisplayName
  #define WindowsDisplayName "Windows 7 SP1"
#endif
#ifndef MinimumWindowsVersion
  #define MinimumWindowsVersion "6.1sp1"
#endif
#define MyAppExeName "sora_" + WindowsTarget + ".exe"

#ifndef StageDir
  #define StageDir "stage"
#endif
#ifndef NdpInstaller
  #define NdpInstaller "NDP48-x86-x64-AllOS-ENU.exe"
#endif
#ifndef KbInstaller
  #define KbInstaller "Windows6.1-KB3033929-x86.msu"
#endif
#ifndef BuildOutputDir
  #define BuildOutputDir "."
#endif

[Setup]
AppId={{8D33A351-982B-4E71-8216-4B7E4B75EBA8}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher=Sora
AppPublisherURL=https://github.com/levvs-one/sora-legacy
VersionInfoVersion={#MyAppVersion}.0
VersionInfoCompany=Sora
VersionInfoDescription=Sora — клиент подключений для {#WindowsDisplayName}
DefaultDirName={localappdata}\Programs\Sora
DefaultGroupName=Sora
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
MinVersion={#MinimumWindowsVersion}
ArchitecturesAllowed=x86compatible
OutputDir={#BuildOutputDir}
OutputBaseFilename=Sora-{#MyAppVersion}-{#WindowsTarget}-Setup
SetupIconFile={#StageDir}\sora.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
WizardBackImageFile=art\back-light.png,art\back-light@2x.png
WizardImageFile=
WizardSmallImageFile=
CloseApplications=yes
RestartApplications=no
SetupLogging=yes
LicenseFile={#StageDir}\LICENSE

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
russian.DesktopIconTask=Создать ярлык на рабочем столе
english.DesktopIconTask=Create a desktop shortcut
russian.AutorunTask=Запускать в фоне при входе в Windows
english.AutorunTask=Start in the background at Windows sign-in
russian.ShortcutsGroup=Ярлыки:
english.ShortcutsGroup=Shortcuts:
russian.AutorunGroup=Автозапуск:
english.AutorunGroup=Startup:
russian.LaunchApp=Запустить Sora
english.LaunchApp=Launch Sora

[Tasks]
Name: "desktopicon"; Description: "{cm:DesktopIconTask}"; GroupDescription: "{cm:ShortcutsGroup}"; Flags: unchecked
Name: "autorun"; Description: "{cm:AutorunTask}"; GroupDescription: "{cm:AutorunGroup}"; Flags: unchecked

[Files]
Source: "{#StageDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#NdpInstaller}"; DestName: "NDP48-x86-x64-AllOS-ENU.exe"; Flags: dontcopy
Source: "{#KbInstaller}"; DestName: "Windows6.1-KB3033929-x86.msu"; Flags: dontcopy

[Icons]
Name: "{group}\Sora"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"
Name: "{autodesktop}\Sora"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Tasks: desktopicon
Name: "{userstartup}\Sora"; Filename: "{app}\{#MyAppExeName}"; Parameters: "--silent"; WorkingDir: "{app}"; Tasks: autorun

[Registry]
; sora:// registration, made ahead of time: the shell passes the
; whole link as "%1" (sora://add/…) to the named executable. Today
; that executable is built from v2rayN, whose command line does not
; handle a sora:// argument, so a click on a link is silently
; dropped for now. The handler is the new client's Program.cs, which
; imports what the link carries; this registration takes effect
; unchanged when the delivery stage switches the shipped executable
; to that client. uninsdeletekey removes the whole protocol key at
; uninstall.
Root: HKA; Subkey: "Software\Classes\sora"; ValueType: string; ValueData: "URL:Sora"; Flags: uninsdeletekey
Root: HKA; Subkey: "Software\Classes\sora"; ValueType: string; ValueName: "URL Protocol"; ValueData: ""
Root: HKA; Subkey: "Software\Classes\sora\DefaultIcon"; ValueType: string; ValueData: """{app}\{#MyAppExeName}"",0"
Root: HKA; Subkey: "Software\Classes\sora\shell\open\command"; ValueType: string; ValueData: """{app}\{#MyAppExeName}"" ""%1"""

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchApp}"; WorkingDir: "{app}"; Flags: nowait postinstall skipifsilent; Check: not WizardNoIcons

[UninstallRun]
Filename: "{app}\{#MyAppExeName}"; Parameters: "--restore-proxy --silent"; WorkingDir: "{app}"; Flags: runhidden waituntilterminated skipifdoesntexist; RunOnceId: "RestoreSystemProxy"

[UninstallDelete]
Type: files; Name: "{app}\guiNConfig.json"
Type: files; Name: "{app}\statistics.json"
Type: filesandordirs; Name: "{app}\guiLogs"
Type: filesandordirs; Name: "{app}\guiTemps"
Type: filesandordirs; Name: "{app}\guiBackups"
Type: filesandordirs; Name: "{app}\guiConfigs"

[Code]
function IsWindows7: Boolean;
var
  Version: TWindowsVersion;
begin
  GetWindowsVersionEx(Version);
  Result := (Version.Major = 6) and (Version.Minor = 1);
end;

function IsDotNet48Installed: Boolean;
var
  Release: Cardinal;
begin
  Result := False;
  if RegQueryDWordValue(HKLM32, 'SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full', 'Release', Release) then
    Result := Release >= 528040;
  if IsWin64 and RegQueryDWordValue(HKLM64, 'SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full', 'Release', Release) then
    Result := Result or (Release >= 528040);
end;

// A hotfix counts as installed when a CBS package for it is in the
// installed state (CurrentState 112). Package subkey names come in
// two shapes - "Package_for_KB<...>~..." and the numbered variants
// "Package_<n>_for_KB<...>~..." - so the match looks for the
// "for_KB<...>~" segment anywhere in the name; the trailing "~"
// keeps a longer KB number from matching as a prefix. The scan sees
// the package that delivered the hotfix; a hotfix that arrived
// inside a monthly rollup is recorded under the rollup's own
// number, so "not found" must be reported to the user as "not
// detected", never as a proven absence.
function IsKbInstalled(const KbNumber: String): Boolean;
var
  PackageNames: TArrayOfString;
  PackagePath: String;
  CurrentState: Cardinal;
  Index: Integer;
begin
  Result := False;
  PackagePath := 'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages';
  if not RegGetSubkeyNames(HKLM32, PackagePath, PackageNames) then
    Exit;
  for Index := 0 to GetArrayLength(PackageNames) - 1 do
  begin
    if Pos('for_' + KbNumber + '~', PackageNames[Index]) > 0 then
    begin
      if RegQueryDWordValue(HKLM32, PackagePath + '\' + PackageNames[Index], 'CurrentState', CurrentState) and (CurrentState = 112) then
      begin
        Result := True;
        Exit;
      end;
    end;
  end;
end;

function IsKb3033929Installed: Boolean;
begin
  Result := IsKbInstalled('KB3033929');
end;

// Windows 7 SP1 prerequisites this installer cannot provide itself
// (checked on Windows 7 only, both architectures):
//   KB4490628 - the servicing stack update Microsoft requires before
//     .NET Framework updates install on Windows 7 SP1;
//   KB4474419 - SHA-2 code-signing support; without it those updates
//     cannot be validated. The bundled KB3033929 step below covers
//     the SHA-2 gap only on 32-bit Windows 7, because only the x86
//     .msu is bundled; on x64 this check is the SHA-2 coverage.
//   KB3140245 - enables TLS 1.2 in the system SChannel stack. The
//     shipped client enables TLS 1.2 in code (v2rayN Utils.
//     SetSecurityProtocol), and without this update HTTPS
//     subscription downloads can fail on a bare Windows 7 SP1.
// A missing update is no longer a silent runtime failure: the user
// sees exactly what was not detected and what it affects, and
// chooses to stop and update Windows first or to continue anyway.
function ConfirmWindows7Prerequisites: Boolean;
var
  Missing: String;
begin
  Result := True;
  if not IsWindows7 then
    Exit;
  Missing := '';
  if not IsKbInstalled('KB4490628') then
    Missing := Missing + #13#10 + '- KB4490628: стек обслуживания, нужен для установки обновлений .NET Framework.';
  if not IsKbInstalled('KB4474419') then
    Missing := Missing + #13#10 + '- KB4474419: поддержка подписей SHA-2, нужна для обновлений .NET Framework.';
  if not IsKbInstalled('KB3140245') then
    Missing := Missing + #13#10 + '- KB3140245: включает TLS 1.2 в системном стеке, без него загрузка подписок по HTTPS может не работать.';
  if Missing = '' then
    Exit;
  Log('Windows 7 prerequisites not detected:' + Missing);
  Result := MsgBox('В системе не обнаружены обновления Windows 7 SP1:' + Missing + #13#10#13#10 +
    'Обновление могло прийти в составе накопительного пакета под другим номером - тогда это предупреждение ложное и можно продолжать.' + #13#10#13#10 +
    'Если система давно не обновлялась, сначала поставьте обновления через Центр обновления Windows. Продолжить установку?',
    mbConfirmation, MB_YESNO) = IDYES;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
  InstallerPath: String;
begin
  Result := '';

  if not ConfirmWindows7Prerequisites then
  begin
    Result := 'Установка отменена: сначала установите обновления Windows 7 SP1 (KB4490628, KB4474419, KB3140245) через Центр обновления Windows и запустите установщик снова.';
    Exit;
  end;

  if IsWindows7 and not IsWin64 and not IsKb3033929Installed then
  begin
    ExtractTemporaryFile('Windows6.1-KB3033929-x86.msu');
    InstallerPath := ExpandConstant('{tmp}\Windows6.1-KB3033929-x86.msu');
    if CompareText(GetSHA256OfFile(InstallerPath), '246C300A6AE6DCA99453F6839745AC0015953528A7065BED1B015F91B80CF64D') <> 0 then
    begin
      Result := 'Проверка целостности KB3033929 не пройдена.';
      Exit;
    end;
    if ShellExec('runas', ExpandConstant('{sys}\wusa.exe'), '"' + InstallerPath + '" /quiet /norestart', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    begin
      Log(Format('KB3033929 завершился с кодом %d', [ResultCode]));
      if (ResultCode = 3010) or (ResultCode = 1641) then
        NeedsRestart := True;
      if (ResultCode <> 0) and (ResultCode <> 3010) and (ResultCode <> 1641) and (ResultCode <> 2359302) then
      begin
        Result := Format('Проверка или установка KB3033929 завершилась с кодом %d.', [ResultCode]);
        Exit;
      end;
    end
    else
    begin
      Result := Format('Не удалось запустить проверку или установку KB3033929. Код: %d', [ResultCode]);
      Exit;
    end;
  end;

  if not IsDotNet48Installed then
  begin
    ExtractTemporaryFile('NDP48-x86-x64-AllOS-ENU.exe');
    InstallerPath := ExpandConstant('{tmp}\NDP48-x86-x64-AllOS-ENU.exe');
    if CompareText(GetSHA256OfFile(InstallerPath), '0A3A390C47E639D0F7FC65B21195FEE6B7F65B066F80F70C60FAB191D14B7E40') <> 0 then
    begin
      Result := 'Проверка целостности .NET Framework 4.8 не пройдена.';
      Exit;
    end;
    if not ShellExec('runas', InstallerPath, '/q /norestart', '', SW_SHOW, ewWaitUntilTerminated, ResultCode) then
    begin
      Result := Format('Не удалось запустить установку .NET Framework 4.8. Код: %d', [ResultCode]);
      Exit;
    end;
    if (ResultCode <> 0) and (ResultCode <> 3010) and (ResultCode <> 1641) then
    begin
      Result := Format('Установка .NET Framework 4.8 завершилась с кодом %d.', [ResultCode]);
      Exit;
    end;
    if (ResultCode = 3010) or (ResultCode = 1641) then
      NeedsRestart := True;
  end;
end;

// The app writes its own autostart value when the in-app "launch at sign-in"
// option is on (v2rayN Tool/Utils.cs): the value name is
// SoraAutoRun_<MD5 of the install directory>, so this script cannot name it
// in a [Registry] entry. Scan the Run key at uninstall and remove only values
// whose command line points at this installation's executable; anything else
// (another copy of Sora elsewhere, another program) is left alone.
procedure RemoveOrphanedAutoRun();
var
  Names: TArrayOfString;
  I: Integer;
  Value: String;
  ExePath: String;
begin
  ExePath := Lowercase(ExpandConstant('{app}\{#MyAppExeName}'));
  if RegGetValueNames(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Run', Names) then
  begin
    for I := 0 to GetArrayLength(Names) - 1 do
    begin
      if (Pos('soraautorun_', Lowercase(Names[I])) = 1) and
         RegQueryStringValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Run', Names[I], Value) and
         (Pos(ExePath, Lowercase(Value)) > 0) then
        RegDeleteValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Run', Names[I]);
    end;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    RemoveOrphanedAutoRun();
end;
