; WIF Bunker Inno Setup Script
; Version must be provided via command line: /DVersion=x.y.z

#ifndef Version
  #define Version "0.0.0" ; Default fallback version
#endif

[Setup]
AppName=WIF Bunker
AppVersion={#Version}
AppPublisher=Jay Lee
AppPublisherURL=https://github.com/jay0lee/wif-bunker
DefaultDirName={autopf}\WIF Bunker
DefaultGroupName=WIF Bunker
DisableProgramGroupPage=yes
OutputBaseFilename=wif-bunker-{#Version}-windows-x86_64-setup
Compression=lzma2
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired=lowest
ChangesEnvironment=yes
DirExistsWarning=no

[Files]
Source: "dist\wif-bunker\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Registry]
; Add {app} to user PATH
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Check: NeedsAddPath(ExpandConstant('{app}'))

[Code]
// Function to check if the app path is already in the user's PATH environment variable
function NeedsAddPath(Param: string): boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', OrigPath) then
  begin
    Result := True;
    exit;
  end;
  
  // Look for the path with leading and trailing semicolon
  // Also check if it's exactly the path, or at the start/end
  Result := Pos(';' + Param + ';', ';' + OrigPath + ';') = 0;
end;
