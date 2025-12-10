; 黑名单车辆筛选系统安装脚本
; 由 Inno Setup 生成

[Setup]
; 基本设置
AppId={{8A4E1A4F-1C8C-4F5A-9E4A-1B2C3D4E5F6G}}
AppName=黑名单车辆筛选系统
AppVersion=3.0
AppPublisher=杨一旭
AppCopyright=© 2025 杨一旭. 保留所有权利.
AppPublisherURL=https://www.example.com/
AppSupportURL=https://www.example.com/support
AppUpdatesURL=https://www.example.com/updates
DefaultDirName={pf}\黑名单车辆筛选系统
DefaultGroupName=黑名单车辆筛选系统
AllowNoIcons=yes
LicenseFile=license.txt
OutputDir=d:\Py_Black_Backstage3.0\installer_output
OutputBaseFilename=黑名单车辆筛选系统安装包
Compression=lzma
SolidCompression=yes

; 安装图标
SetupIconFile=d:\Py_Black_Backstage3.0\app_icon.ico

[Languages]
Name: "chinese"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "quicklaunchicon"; Description: "{cm:CreateQuickLaunchIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked; OnlyBelowVersion: 6.1; Check: IsTaskSelected('desktopicon')

[Files]
; 主程序文件
Source: "d:\Py_Black_Backstage3.0\dist\Compares_Excel_PySide6.exe"; DestDir: "{app}"; Flags: ignoreversion
; 后台管理服务器
Source: "d:\Py_Black_Backstage3.0\admin_server.py"; DestDir: "{app}"; Flags: ignoreversion
; 图标文件
Source: "d:\Py_Black_Backstage3.0\app_icon.ico"; DestDir: "{app}"; Flags: ignoreversion
; 许可证文件
Source: "d:\Py_Black_Backstage3.0\license.txt"; DestDir: "{app}"; Flags: ignoreversion
; 后台管理页面目录
Source: "d:\Py_Black_Backstage3.0\admin_html\*"; DestDir: "{app}\admin_html"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\黑名单车辆筛选系统"; Filename: "{app}\Compares_Excel_PySide6.exe"
Name: "{group}\后台管理服务器"; Filename: "{app}\admin_server.py"
Name: "{commondesktop}\黑名单车辆筛选系统"; Filename: "{app}\Compares_Excel_PySide6.exe"; Tasks: desktopicon
Name: "{userappdata}\Microsoft\Internet Explorer\Quick Launch\黑名单车辆筛选系统"; Filename: "{app}\Compares_Excel_PySide6.exe"; Tasks: quicklaunchicon

[Run]
Filename: "{app}\Compares_Excel_PySide6.exe"; Description: "{cm:LaunchProgram,黑名单车辆筛选系统}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; 删除所有相关文件
Type: files; Name: "{app}\Compares_Excel_PySide6.exe"
Type: files; Name: "{app}\admin_server.py"
Type: files; Name: "{app}\app_icon.ico"
Type: files; Name: "{app}\license.txt"
Type: files; Name: "{app}\blacklist_vehicles.db"
; 删除可能生成的数据库文件（包括可能的备份）
Type: files; Name: "{app}\*.db"
; 删除后台管理页面目录
Type: files; Name: "{app}\admin_html\*.*"
Type: dirifempty; Name: "{app}\admin_html"
; 删除所有其他可能的文件
Type: files; Name: "{app}\*.*"
; 删除整个应用目录（在所有文件删除后，目录会变为空目录）
Type: dirifempty; Name: "{app}"