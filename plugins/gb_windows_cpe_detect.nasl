###############################################################################
# OpenVAS Vulnerability Test
#
# Windows Application CPE Detection
#
# Authors:
# Thomas Rotter <thomas.rotter@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96207");
  script_version("2019-05-15T09:55:33+0000");
  script_tag(name:"last_modification", value:"2019-05-15 09:55:33 +0000 (Wed, 15 May 2019)");
  script_tag(name:"creation_date", value:"2011-04-26 12:54:47 +0200 (Tue, 26 Apr 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Windows Application CPE Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Windows");
  # Don't add a dependency to os_detection.nasl. This will cause a dependency sycle.
  script_dependencies("toolcheck.nasl", "smb_login.nasl", "smb_nativelanman.nasl", "netbios_name_get.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/password", "SMB/login", "Tools/Present/wmi");
  script_exclude_keys("SMB/samba");

  script_tag(name:"summary", value:"This NVT collects information about installed applications
  from a Microsoft Windows system and stores the CPEs, making them available to other NVTs.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("wmi_os.inc");
include("wmi_file.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");
include("host_details.inc");
include("version_func.inc");
include("misc_func.inc");

SCRIPT_DESC = "Windows Application CPE Detection";
BANNER_TYPE = "Registry access via SMB";

if( kb_smb_is_samba() ) exit( 0 );

host      = get_host_ip();
usrname   = kb_smb_login();
domain    = kb_smb_domain();
transport = kb_smb_transport();
passwd    = kb_smb_password();

if( ! host || ! usrname || ! passwd || ! transport ) {
  exit( 0 );
}

if( domain ) usrname = domain + '\\' + usrname;

errorval = "none";
app = "App";

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
keyx = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
netfrm = "SOFTWARE\Microsoft\NET Framework Setup\NDP\";
officekey = "SOFTWARE\Microsoft\Office\";
officexkey = "SOFTWARE\Wow6432Node\Microsoft\Office\";
works = "SOFTWARE\Microsoft\Works\";
worksx = "SOFTWARE\Wow6432Node\Microsoft\Works\";

Office = "MSO.dll";
Access = "MSACCESS.exe";
Excel = "EXCEL.exe";
InfoPath = "INFOPATH.exe";
OneNote = "ONENOTE.exe";
PowerPoint = "POWERPNT.exe";
Project = "WINPROJ.exe";
Publisher = "MSPUB.exe";
SharePoint_Designer = "SPDESIGN.exe";
SharePoint_Workspace = "GROOVE.exe";
Word = "WINWORD.exe";
Visio = "VISLIB.dll";

#WMI Part deactivated until Mantis 52166 is fixed.
#handle = wmi_connect(host:host, username:usrname, password:passwd);
#handlereg = wmi_connect_reg(host:host, username:usrname, password:passwd);

###SMB Part starts here:
if(!handle || !handlereg){
  OSSYSDIR = smb_get_systemroot();

  cputype = registry_get_sz(key:"SYSTEM\CurrentControlSet\Control\Session Manager\Environment", item:"PROCESSOR_ARCHITECTURE");
  type = registry_get_sz(key:"SYSTEM\CurrentControlSet\Control\ProductOptions", item:"ProductType");
  version = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion", item:"CurrentVersion");
  smbosname = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion", item:"ProductName");
  build = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion", item:"CurrentBuild");
  if( isnull( build ) || ! build ) build = "unknown";

  spver = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion", item:"CSDVersion");
  if( isnull( spver ) || ! spver ) spver = "0";
  if( spver != "0" ) {
    spver = eregmatch( pattern:'(Service Pack) ([0-9]+)', string:spver );
    if( ! isnull( spver[0] ) ) {
      spver = spver[2];
    }
  }
  if (spver == "6"){
    com = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Hotfix\Q246009", item:"Comments");
    if (com) spver = "6a";
  }
  smbregentries = registry_enum_keys(key:key);
  foreach entry (smbregentries)
  {
    if (entry == "{ABEB838C-A1A7-4C5D-B7E1-8B4314600208}") MSNMess = "6.2";
    else if (entry == "{ABEB838C-A1A7-4C5D-B7E1-8B4314600820}") MSNMess = "7.0";
    else if (entry == "{CEB3A11A-03EA-11DA-BFBD-00065BBDC0B5}") MSNMess = "7.5";
    else if (entry == "{FCE50DB8-C610-4C42-BE5C-193F46C6F812}" || entry == "{7A837109-E671-470D-B489-F1EBE471D220}") MSNMess = "8.0";
    else if (entry == "{571700F0-DB9D-4B3A-B03D-35A14BB5939F}") MSNMess = "8.1";
    val = registry_get_sz(key:key + entry, item:"DisplayName");
    if (val){
      smbkeylist += val +";";
      smbkeylist += registry_get_sz(key:key + entry, item:"DisplayVersion") + "|";
    }
  }
  smbregentriesx = registry_enum_keys(key:keyx);
  if (smbregentriesx)
  {
    x64 = "1";
    foreach entryx (smbregentriesx)
    if (!MSNMess){
      if (entryx == "{ABEB838C-A1A7-4C5D-B7E1-8B4314600208}") MSNMess = "6.2";
      else if (entryx == "{ABEB838C-A1A7-4C5D-B7E1-8B4314600820}") MSNMess = "7.0";
      else if (entryx == "{CEB3A11A-03EA-11DA-BFBD-00065BBDC0B5}") MSNMess = "7.5";
      else if (entryx == "{FCE50DB8-C610-4C42-BE5C-193F46C6F812}" || entryx == "{7A837109-E671-470D-B489-F1EBE471D220}") MSNMess = "8.0";
      else if (entryx == "{571700F0-DB9D-4B3A-B03D-35A14BB5939F}") MSNMess = "8.1";
    }
    {
      val = registry_get_sz(key:keyx + entryx, item:"DisplayName");
      if (val){
        smbkeylist += val +";";
        smbkeylist += registry_get_sz(key:keyx + entryx, item:"DisplayVersion") + "|";
      }
    }
  }

  netfrmregentries = registry_enum_keys(key:netfrm);
  foreach entry (netfrmregentries)
  {
    install = registry_get_dword(key:netfrm + entry, item:"Install");
    if (install){
      netfrmkeylist += entry + ";";
      netfrmkeylist += registry_get_sz(key:netfrm + entry, item:"Version") + ";";
      netfrmkeylist += registry_get_dword(key:netfrm + entry, item:"SP") + "|";
    }
  }

  ComFilesDir = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"CommonFilesDir");
  ComFilesDirx86 = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"CommonFilesDir (x86)");

  officeregentries = registry_enum_keys(key:officekey);
  if (officeregentries){
    foreach entry (officeregentries)
    {
      val = registry_get_sz(key:officekey + entry + "\Common\InstallRoot\", item:"Path");
      if (val){
        msodll = registry_get_sz(key:officekey + entry + "\Common\FilesPaths\", item:"mso.dll");
        if (msodll) officepath  = val;
        officebakpath  += val + ";";
        OfficeVer = entry[i];
      }
      visiopath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\visio.exe", item:"Path");
      if (visiopath){
        if(!VisioCRV)VisioCRV = registry_get_sz(key:officekey + entry + "\Visio\", item:"CurrentlyRegisteredVersion");
        valv = registry_get_sz(key:officekey + entry[i] + "\Visio\", item:"InstalledVersion");
        if (valv )VisioRegVer = valv;
        if(!VisioRegVer){
          Visioregentries = registry_enum_keys(key:officekey + entry + "\Visio\");
          if(!Visioentry)Visioentry = Visioregentries;
          for(v=0; v<max_index(Visioentry); v++){
            valv = VisioRegVer = registry_get_sz(key:officekey + entry + "\Visio\" + Visioentry[v], item:"InstalledVersion");
            if (valv )VisioRegVer = valv;
          }
        }
      }
    }
  }
  worksregentries = registry_enum_keys(key:works);
  if(worksregentries){
    foreach entry (worksregentries)
    {
      val = registry_get_sz(key:works + entry, item:"Installdir");
      if (val) {
        ver = registry_get_sz(key:works + entry, item:"CurrentVersion");
        if (ver) workspath  = val;
        worksVer = ver;
      }
    }
  }

  if (x64){
    officeregentriesx = registry_enum_keys(key:officexkey);
    if(officeregentriesx){
      foreach entry (officeregentriesx)
      {
        val1 = registry_get_sz(key:officexkey + entry + "\Common\InstallRoot\", item:"Path");
        if (val1) {
          msodll1 = registry_get_sz(key:officexkey + entry + "\Common\FilesPaths\", item:"mso.dll");
          if (msodll1) officepath  = val1;
          if (msodll1) msodll  = msodll1;
          officebakpath  += val1 + ";";
          OfficeVer = entry;
        }
        if(!visiopath)visiopath = registry_get_sz(key:"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\App Paths\visio.exe", item:"Path");
        if (visiopath){
          if(!VisioCRV)VisioCRV = registry_get_sz(key:officexkey + entry + "\Visio\", item:"CurrentlyRegisteredVersion");
          if(!VisioRegVer)xvalv = registry_get_sz(key:officexkey + entry + "\Visio\", item:"InstalledVersion");
          if (xvalv )VisioRegVer = xvalv;
          if(!VisioRegVer){
            Visioregentries = registry_enum_keys(key:officexkey + entry + "\Visio\");
            #Visioentry = split(Visioregentries, sep:"|", keep:0);
            if(!Visioentry)Visioentry = Visioregentries;
            for(v=0; v<max_index(Visioentry); v++){
              xvalv = registry_get_sz(key:officexkey + entry + "\Visio\" + Visioentry[v], item:"InstalledVersion");
              if (xvalv )VisioRegVer = xvalv;
            }
          }
        }
      }
    }
    worksregentriesx = registry_enum_keys(key:works);
    if(worksregentriesx){
      foreach entry (worksregentriesx)
      {
        val1 = registry_get_sz(key:works + entry, item:"Installdir");
        if (val1) {
          ver1 = registry_get_sz(key:works + entry, item:"CurrentVersion");
          if (ver1) workspath  = val1;
          if (ver1)worksVer = ver1;
        }
      }
    }
  }

  if (OfficeVer == "10.0")Outlook = "OutLLib.dll";
  else Outlook = "OUTLOOK.exe";

  if (msodll){
    msodll = msodll - "\MSO.DLL";
    OfficeFileVer = fetch_file_version(sysPath:msodll, file_name:"mso.dll");
  }
  if (officepath){
    AccessVer = fetch_file_version(sysPath:officepath, file_name:Access);
    ExcelVer = fetch_file_version(sysPath:officepath, file_name:Excel);
    InfoPathVer = fetch_file_version(sysPath:officepath, file_name:InfoPath);
    OneNoteVer = fetch_file_version(sysPath:officepath, file_name:OneNote);
    OutlookVer = fetch_file_version(sysPath:officepath, file_name:Outlook);
    PowerPointVer = fetch_file_version(sysPath:officepath, file_name:PowerPoint);
    ProjectVer = fetch_file_version(sysPath:officepath, file_name:Project);
    PublisherVer = fetch_file_version(sysPath:officepath, file_name:Publisher);
    SharePoint_DesignerVer = fetch_file_version(sysPath:officepath, file_name:SharePoint_Designer);
    SharePoint_WorkspaceVer = fetch_file_version(sysPath:officepath, file_name:SharePoint_Workspace);
    WordVer = fetch_file_version(sysPath:officepath, file_name:Word);
    VisioVer = fetch_file_version(sysPath:officepath, file_name:Visio);
    VisioSMBVer = fetch_file_version(sysPath:officepath, file_name:Visio);
  }

  if( ! VisioRegVer && VisioSMBVer )
    VisioRegVer = VisioSMBVer;

  if( VisioRegVer && VisioSMBVer ) {
    if( version_is_less( version:VisioRegVer, test_version:VisioSMBVer ) ) {
      VisioRegVer = VisioSMBVer;
    }
  }

  if( ! VisioVer && VisioRegVer )
    VisioVer = VisioRegVer;

  directx = registry_get_sz(key:"SOFTWARE\Microsoft\DirectX", item:"Version");
  iever = registry_get_sz(key:"SOFTWARE\Microsoft\Internet Explorer", item:"Version");
  oever= registry_get_sz(key:"SOFTWARE\Microsoft\Outlook Express\Version Info", item:"Current");
  if(oever)oever = ereg_replace(pattern:",", replace:".", string:oever);

  #wmplayer = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\wmplayer.exe", item:"Path");
  #wmplayerver = fetch_file_version(sysPath:wmplayer, file_name:"wmplayer.exe");

  wmplayerver = registry_get_sz(key:"SOFTWARE\Microsoft\MediaPlayer\PlayerUpgrade",item:"PlayerVersion");
  if (wmplayerver)wmplayerver = ereg_replace(pattern:",", replace:".", string:wmplayerver);

  mdacfullver = registry_get_sz(key:"SOFTWARE\Microsoft\DataAccess", item:"FullInstallVer");
  mdacver = registry_get_sz(key:"SOFTWARE\Microsoft\DataAccess", item:"Version");

  IISMinorVersion = registry_get_dword(key:"SOFTWARE\Microsoft\INetStp", item:"MinorVersion");
  IISMajorVersion = registry_get_dword(key:"SOFTWARE\Microsoft\INetStp", item:"MajorVersion");

  ExchProductMajor = registry_get_dword(key:"SOFTWARE\Microsoft\Exchange\Setup", item:"MsiProductMajor");
  ExchProductMinor = registry_get_dword(key:"SOFTWARE\Microsoft\Exchange\Setup", item:"MsiProductMinor");
  ExchSPBuild = registry_get_dword(key:"SOFTWARE\Microsoft\Exchange\Setup", item:"ServicePackBuild");

  Exch2010ProductMajor = registry_get_dword(key:"Software\Microsoft\ExchangeServer\v14\Setup", item:"MsiProductMajor");
  Exch2010ProductMinor = registry_get_dword(key:"Software\Microsoft\ExchangeServer\v14\Setup", item:"MsiProductMinor");
  Exch2010BuildMajor = registry_get_dword(key:"Software\Microsoft\ExchangeServer\v14\Setup", item:"MsiBuildMajor");
  Exch2010BuildMinor = registry_get_dword(key:"Software\Microsoft\ExchangeServer\v14\Setup", item:"MsiBuildMinor");

  Exch2013ProductMajor = registry_get_dword(key:"Software\Microsoft\ExchangeServer\v15\Setup", item:"MsiProductMajor");
  Exch2013DispName = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Exchange v15", item:"DisplayName");

  vsdotnet2k2sp = registry_get_sz(key:"SOFTWARE\Microsoft\Updates\Visual Studio\7.0\S895309", item:"Type");
  vsdotnet2k3sp = registry_get_sz(key:"SOFTWARE\Microsoft\Updates\Visual Studio\7.1\S918007", item:"Type");

  ipnathlp = fetch_file_version(sysPath:OSSYSDIR + "\system32", file_name:"ipnathlp.dll");
  msxml3 =fetch_file_version(sysPath:OSSYSDIR + "\system32", file_name:"msxml3.dll");
  msxml4 = fetch_file_version(sysPath:OSSYSDIR + "\system32", file_name:"msxml4.dll");
  if(x64) msxml5 = fetch_file_version(sysPath:ComFilesDirx86 + "\Microsoft Shared\OFFICE11", file_name:"msxml5.dll");
  else msxml5 = fetch_file_version(sysPath:ComFilesDir + "\Microsoft Shared\OFFICE11", file_name:"msxml5.dll");
  msxml6 = fetch_file_version(sysPath:OSSYSDIR + "\system32", file_name:"msxml6.dll");

  smbsqlregentries = registry_enum_keys(key:"SOFTWARE\Microsoft\Microsoft SQL Server");
  if (x64)smbsqlregentriesx =  registry_enum_keys(key:"SOFTWARE\Wow6432Node\Microsoft\Microsoft SQL Server");

  messenger = registry_get_sz(key:"SOFTWARE\Microsoft\Active Setup\Installed Components\{5945c046-1e7d-11d1-bc44-00c04fd912be}", item:"Version");
  if (messenger)messenger = ereg_replace(pattern:",", replace:".", string:messenger);

  crmver = registry_get_sz(key:"SOFTWARE\NCompass\Resolution Content Server\VersionInfo", item:"Version");
  if(crmver)crmsp =  registry_get_sz(key:"SOFTWARE\NCompass\Resolution Content Server\VersionInfo", item:"Patches");

  isapath = registry_get_sz(key:"SOFTWARE\Microsoft\Fpc", item:"InstallDirectory");
  if (isapath) IsaVer = fetch_file_version(sysPath:isapath, file_name:"wspsrv.exe");

 if (x64){
   VS2002path = registry_get_sz(key:"SOFTWARE\Wow6432Node\Microsoft\VisualStudio\7.0", item:"Installdir");
  if (VS2002path) VS2002 = fetch_file_version(sysPath:VS2002path, file_name:"devenv.exe");

  VS2003path = registry_get_sz(key:"SOFTWARE\Wow6432Node\Microsoft\VisualStudio\7.1", item:"Installdir");
  if (VS2003path) VS2003 = fetch_file_version(sysPath:VS2003path, file_name:"devenv.exe");

  VS2005path = registry_get_sz(key:"SOFTWARE\Wow6432Node\Microsoft\VisualStudio\8.0", item:"Installdir");
  if (VS2005path) VS2005 = fetch_file_version(sysPath:VS2005path, file_name:"devenv.exe");
  if (VS2005path) VS2005SP = registry_get_dword(key:"SOFTWARE\Wow6432Node\Microsoft\DevDiv\VS\Servicing\8.0", item:"SP");

  VS2008path = registry_get_sz(key:"SOFTWARE\Wow6432Node\Microsoft\VisualStudio\9.0", item:"Installdir");
  if (VS2008path) VS2008 = fetch_file_version(sysPath:VS2008path, file_name:"devenv.exe");
  if (VS2008path) VS2008SP = registry_get_dword(key:"SOFTWARE\Wow6432Node\Microsoft\DevDiv\VS\Servicing\9.0", item:"SP");

  VS2010path = registry_get_sz(key:"SOFTWARE\Wow6432Node\Microsoft\VisualStudio\10.0", item:"Installdir");
  if (VS2010path) VS2010 = fetch_file_version(sysPath:VS2010path, file_name:"devenv.exe");
  if (VS2010path) VS2010SP = registry_get_dword(key:"SOFTWARE\Wow6432Node\Microsoft\DevDiv\VS\Servicing\10.0", item:"SP");

  VS2012path = registry_get_sz(key:"SOFTWARE\Wow6432Node\Microsoft\VisualStudio\11.0", item:"Installdir");
  if (VS2012path) VS2012 = fetch_file_version(sysPath:VS2012path, file_name:"devenv.exe");
  if (VS2012path) VS2012SP = registry_get_dword(key:"SOFTWARE\Wow6432Node\Microsoft\DevDiv\VS\Servicing\11.0", item:"SP");

  VS2013path = registry_get_sz(key:"SOFTWARE\Wow6432Node\Microsoft\VisualStudio\12.0", item:"Installdir");
  if (VS2013path) VS2013 = fetch_file_version(sysPath:VS2013path, file_name:"devenv.exe");
  if (VS2013path) VS2013SP = registry_get_dword(key:"SOFTWARE\Wow6432Node\Microsoft\DevDiv\VS\Servicing\12.0", item:"SP");

  VS2015path = registry_get_sz(key:"SOFTWARE\Wow6432Node\Microsoft\VisualStudio\14.0", item:"Installdir");
  if (VS2015path) VS2015 = fetch_file_version(sysPath:VS2015path, file_name:"devenv.exe");
  if (VS2015path) VS2015SP = registry_get_dword(key:"SOFTWARE\Wow6432Node\Microsoft\DevDiv\VS\Servicing\14.0", item:"SP");
 }
 else{
  VS2002path = registry_get_sz(key:"SOFTWARE\Microsoft\VisualStudio\7.0", item:"Installdir");
  if (VS2002path) VS2002 = fetch_file_version(sysPath:VS2002path, file_name:"devenv.exe");

  VS2003path = registry_get_sz(key:"SOFTWARE\Microsoft\VisualStudio\7.1", item:"Installdir");
  if (VS2003path) VS2003 = fetch_file_version(sysPath:VS2003path, file_name:"devenv.exe");

  VS2005path = registry_get_sz(key:"SOFTWARE\Microsoft\VisualStudio\8.0", item:"Installdir");
  if (VS2005path) VS2005 = fetch_file_version(sysPath:VS2005path, file_name:"devenv.exe");
  if (VS2005path) VS2005SP = registry_get_dword(key:"SOFTWARE\Microsoft\DevDiv\VS\Servicing\8.0", item:"SP");

  VS2008path = registry_get_sz(key:"SOFTWARE\Microsoft\VisualStudio\9.0", item:"Installdir");
  if (VS2008path) VS2008 = fetch_file_version(sysPath:VS2008path, file_name:"devenv.exe");
  if (VS2008path) VS2008SP = registry_get_dword(key:"SOFTWARE\Microsoft\DevDiv\VS\Servicing\9.0", item:"SP");

  VS2010path = registry_get_sz(key:"SOFTWARE\Microsoft\VisualStudio\10.0", item:"Installdir");
  if (VS2010path) VS2010 = fetch_file_version(sysPath:VS2010path, file_name:"devenv.exe");
  if (VS2010path) VS2010SP = registry_get_dword(key:"SOFTWARE\Microsoft\DevDiv\VS\Servicing\10.0", item:"SP");

  VS2012path = registry_get_sz(key:"SOFTWARE\Microsoft\VisualStudio\11.0", item:"Installdir");
  if (VS2012path) VS2012 = fetch_file_version(sysPath:VS2012path, file_name:"devenv.exe");
  if (VS2012path) VS2012SP = registry_get_dword(key:"SOFTWARE\Microsoft\DevDiv\VS\Servicing\11.0", item:"SP");

  VS2013path = registry_get_sz(key:"SOFTWARE\Microsoft\VisualStudio\12.0", item:"Installdir");
  if (VS2013path) VS2013 = fetch_file_version(sysPath:VS2013path, file_name:"devenv.exe");
  if (VS2013path) VS2013SP = registry_get_dword(key:"SOFTWARE\Microsoft\DevDiv\VS\Servicing\12.0", item:"SP");

  VS2015path = registry_get_sz(key:"SOFTWARE\Microsoft\VisualStudio\14.0", item:"Installdir");
  if (VS2015path) VS2015 = fetch_file_version(sysPath:VS2015path, file_name:"devenv.exe");
  if (VS2015path) VS2015SP = registry_get_dword(key:"SOFTWARE\Microsoft\DevDiv\VS\Servicing\14.0", item:"SP");
 }

  NDPv4Client = registry_get_dword(key:"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Client", item:"Install");
  NDPv4ClientVer = registry_get_sz(key:"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Client", item:"Version");
  NDPv4Full = registry_get_dword(key:"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full", item:"Install");
  NDPv4FullVer = registry_get_sz(key:"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full", item:"Version");

  MVS2005STen = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\0EEDF7F0258333042A16F38A4BEC64C6\InstallProperties", item:"DisplayName");
  MVS2005STja = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\67EC4B5345C7E7347BBA24CFF8B977B6\InstallProperties", item:"DisplayName");

  MVS2005ENTen = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\813ACF1D304B0FB43A2E440E1CF2ADD3\InstallProperties", item:"DisplayName");
  MVS2005ENTja = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\C31148E7379AA7C48BF2343AB582C3D8\InstallProperties", item:"DisplayName");

  MVS2005R2 = registry_get_sz(key:"SOFTWARE\Classes\Installer\Products\768AAF4834783C442BE25B1A2554D677", item:"ProductName");
  MVS2005R2ST = registry_get_sz(key:"SOFTWARE\Classes\Installer\Products\96CF2B3B315599C4A9E75C85A4295880", item:"ProductName");
  MVS2005R2ENT = registry_get_sz(key:"SOFTWARE\Classes\Installer\Products\2ACE96BF53CE47C46B808783D50059D9", item:"ProductName");

  MVP2004 = registry_get_sz(key:"SOFTWARE\Classes\Installer\Products\B56328045890A99429D04E4D14D45CF8", item:"ProductName");
  MVP2004SP1  = registry_get_sz(key:"SOFTWARE\Classes\Installer\Products\EDDFACCCCECE4EA4DB79400767BB4D9A", item:"ProductName");

  MVP2007 = registry_get_sz(key:"SOFTWARE\Classes\Installer\Products\42AAC7A832B7B0147A3C9F490B491406", item:"ProductName");
  MVP2007SP1  = registry_get_sz(key:"SOFTWARE\Classes\Installer\Products\899384DAA9E2504438FFE605A34FC9BB", item:"ProductName");

}
  ###WMI Part starts here:
else if(handle && handlereg){
  query1 = 'select OSArchitecture from Win32_OperatingSystem';
  query2 = 'select Caption from Win32_OperatingSystem';
  query3 = 'select OSProductSuite from Win32_OperatingSystem';
  query4 = 'select OtherTypeDescription from Win32_OperatingSystem';
  query5 = 'select SuiteMask from Win32_OperatingSystem';
  query6 = 'select Architecture from Win32_Processor';
  query7 = 'select OperatingSystemSKU from Win32_OperatingSystem';
  query8 = 'select OSType from Win32_OperatingSystem';
  query9 = "Select version from CIM_DataFile Where FileName = 'wmplayer' AND Extension = 'exe'";

  #TODO: Also query Windows Build Number for Windows 10 once the WMI Part is enabled

  OSVER = wmi_os_version(handle:handle);

  OSSP =  wmi_os_sp(handle:handle);
  if (OSSP){
    if (OSSP != 1){
        OSSP = eregmatch(pattern:"[0-9]", string:OSSP);
        OSSP = OSSP[0];
    }else OSSP = "0";
  }
  OSTYPE = wmi_os_type(handle:handle);

  OSArchitecture = wmi_query(wmi_handle:handle, query:query1);
  if (OSArchitecture)OSArchitecture = split(OSArchitecture, sep:'\n', keep:0);

  OSNAME = wmi_query(wmi_handle:handle, query:query2);
  if (OSNAME){
    OSNAME = split(OSNAME, sep:'\n', keep:0);
    if (OSVER <= 6){
     OSNAME = split(OSNAME[1], sep:'|', keep:0);
     OSNAME = OSNAME[0];
    }
    else OSNAME = OSNAME[1];
  }
  OSSYSDIR = wmi_os_sysdir(handle:handle);
  if (OSSYSDIR){
    OSSYSDIR = split(OSSYSDIR, sep:'\n', keep:0);
    if (OSVER <= 6){
     OSSYSDIR = split(OSSYSDIR[1], sep:'|', keep:0);
     OSSYSDIR = OSSYSDIR[3];
    }
    else OSSYSDIR = OSSYSDIR[1];
    OSSYSDIR = ereg_replace(pattern:"\\", replace:"\\", string:OSSYSDIR);
  }

  ComFilesDir = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Windows\CurrentVersion", key_name:"CommonFilesDir");
  if (ComFilesDir)ComFilesDir = ereg_replace(pattern:"\\", replace:"\\", string:ComFilesDir);
  ComFilesDirx86 = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Windows\CurrentVersion", key_name:"CommonFilesDir (x86)");
  if (ComFilesDirx86)ComFilesDirx86 = ereg_replace(pattern:"\\", replace:"\\", string:ComFilesDirx86);

  OSPRODS = wmi_query(wmi_handle:handle, query:query3);
  if (OSPRODS){
    OSPRODS = split(OSPRODS, sep:'\n', keep:0);
    if (OSVER <= 6){
      OSPRODS = split(OSPRODS[1], sep:'|', keep:0);
      OSPRODS = OSPRODS[3];
    }
    else OSPRODS = OSPRODS[1];
    if (OSPRODS){
      val = OSPRODS ^ 1;
      if (val < OSPRODS) SBS = "1";
      val = OSPRODS ^ 2;
      if (val < OSPRODS) Enterprise = "1";
      val = OSPRODS ^ 4;
      if (val < OSPRODS) BackOffice = "1";
      val = OSPRODS ^ 8;
      if (val < OSPRODS) CommServer = "1";
      val = OSPRODS ^ 16;
      if (val < OSPRODS) TerminalServices = "1";
      val = OSPRODS ^ 32;
      if (val < OSPRODS) SBS_R = "1";
      val = OSPRODS ^ 64;
      if (val < OSPRODS) Embedded_NT = "1";
      val = OSPRODS ^ 128;
      if (val < OSPRODS) DataCenter = "1";
      val = OSPRODS ^ 256;
      if (val < OSPRODS) TS_1_interact = "1";
      val = OSPRODS ^ 512;
      if (val < OSPRODS) XP_Home = "1";
      val = OSPRODS ^ 1024;
      if (val < OSPRODS) Web_2003 = "1";
      val = OSPRODS ^ 8192;
      if (val < OSPRODS) Stor_Serv_2003R2 = "1";
      val = OSPRODS ^ 16384;
      if (val < OSPRODS) Cluster_2003 = "1";
    }
  }
  OSOTD = wmi_query(wmi_handle:handle, query:query4);
  if (OSOTD){
    OSOTD = split(OSOTD, sep:'\n', keep:0);
    if (OSVER <= 6){
      OSOTD = split(OSOTD[1], sep:'|', keep:0);
      OSOTD = OSOTD[3];
    }
    else OSOTD = OSOTD[1];
  }
  OSSIUM = wmi_query(wmi_handle:handle, query:query5);
  if (OSSIUM){
    OSSIUM = split(OSSIUM, sep:'\n', keep:0);
    if (OSVER <= 6){
      OSSIUM = split(OSSIUM[1], sep:'|', keep:0);
      OSSIUM = OSSIUM[3];
    }
    else OSSIUM = OSSIUM[1];
    if (OSSIUM){
      val = OSSIUM ^ 1;
      if (val < OSSIUM) SBS = "1";
      val = OSSIUM ^ 2;
      if (val < OSSIUM) Enterprise = "1";
      val = OSSIUM ^ 4;
      if (val < OSSIUM) BackOffice = "1";
      val = OSSIUM ^ 8;
      if (val < OSSIUM) CommServer = "1";
      val = OSSIUM ^ 16;
      if (val < OSSIUM) TerminalServices = "1";
      val = OSSIUM ^ 32;
      if (val < OSSIUM) SBS_R = "1";
      val = OSSIUM ^ 64;
      if (val < OSSIUM) Embedded_NT = "1";
      val = OSSIUM ^ 128;
      if (val < OSSIUM) DataCenter = "1";
      val = OSSIUM ^ 256;
      if (val < OSSIUM) Single_User = "1";
      val = OSSIUM ^ 512;
      if (val < OSSIUM) Personal = "1";
      val = OSSIUM ^ 1024;
      if (val < OSSIUM) Blade = "1";
    }
  }
  OSCPU = wmi_query(wmi_handle:handle, query:query6);
  if (OSCPU){
    OSCPU = split(OSCPU, sep:'\n', keep:0);
    OSCPU = split(OSCPU[1], sep:'|', keep:0);
    OSCPU = OSCPU[0];
  }
  OSSKU = wmi_query(wmi_handle:handle, query:query7);
  if (OSSKU){
    OSSKU = split(OSSKU, sep:'\n', keep:0);
    OSSKU = OSSKU[1];
  }

  OS_TYPE = wmi_query(wmi_handle:handle, query:query8);
  if (OS_TYPE){
    OS_TYPE = split(OS_TYPE, sep:'\n', keep:0);
    OS_TYPE = split(OS_TYPE[1], sep:'|', keep:0);
    OS_TYPE = OS_TYPE[3];
  }
  type = wmi_reg_get_sz(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Control\ProductOptions", key_name:"ProductType");

  regentries = wmi_reg_enum_key(wmi_handle:handlereg, key:key);
  if (regentries){
    entry = split(regentries, sep:"|", keep:0);
    for(i=0; i<max_index(entry); i++)
    {
      if (entry[i] == "{ABEB838C-A1A7-4C5D-B7E1-8B4314600208}") MSNMess = "6.2";
      else if (entry[i] == "{ABEB838C-A1A7-4C5D-B7E1-8B4314600820}") MSNMess = "7.0";
      else if (entry[i] == "{CEB3A11A-03EA-11DA-BFBD-00065BBDC0B5}") MSNMess = "7.5";
      else if (entry[i] == "{FCE50DB8-C610-4C42-BE5C-193F46C6F812}" || entry[i] == "{7A837109-E671-470D-B489-F1EBE471D220}") MSNMess = "8.0";
      else if (entry[i] == "{571700F0-DB9D-4B3A-B03D-35A14BB5939F}") MSNMess = "8.1";
      val = wmi_reg_get_sz(wmi_handle:handlereg, key:key + entry[i], key_name:"DisplayName");
      if (val){
        keylist += val +";";
        keylist += wmi_reg_get_sz(wmi_handle:handlereg, key:key + entry[i], key_name:"DisplayVersion") + "|";
      }
    }
  }
  if("64" >< OSArchitecture[1] || "x64" >< OSNAME){
    x64 = "1";
    regentriesx += wmi_reg_enum_key(wmi_handle:handlereg, key:keyx);
    if (regentriesx){
      entryx = split(regentriesx, sep:"|", keep:0);
      for(i=0; i<max_index(entryx); i++)
      {
        if (!MSNMess){
          if (entryx[i] == "{ABEB838C-A1A7-4C5D-B7E1-8B4314600208}") MSNMess = "6.2";
          else if (entryx[i] == "{ABEB838C-A1A7-4C5D-B7E1-8B4314600820}") MSNMess = "7.0";
          else if (entryx[i] == "{CEB3A11A-03EA-11DA-BFBD-00065BBDC0B5}") MSNMess = "7.5";
          else if (entryx[i] == "{FCE50DB8-C610-4C42-BE5C-193F46C6F812}" || entryx[i] == "{7A837109-E671-470D-B489-F1EBE471D220}") MSNMess = "8.0";
          else if (entryx[i] == "{571700F0-DB9D-4B3A-B03D-35A14BB5939F}") MSNMess = "8.1";
        }
        valx = wmi_reg_get_sz(wmi_handle:handlereg, key:keyx + entryx[i], key_name:"DisplayName");
        if (valx){
          keylist += valx +";";
          keylist += wmi_reg_get_sz(wmi_handle:handlereg, key:keyx + entryx[i], key_name:"DisplayVersion") + "|";
        }
      }
    }
  }
  netfrmregentries = wmi_reg_enum_key(wmi_handle:handlereg, key:netfrm);
  if (netfrmregentries){
    entry = split(netfrmregentries, sep:"|", keep:0);
    for(i=0; i<max_index(entry); i++)
    {
      install = wmi_reg_get_dword_val(wmi_handle:handlereg, key:netfrm + entry[i], val_name:"Install");
      if (install){
        netfrmkeylist += entry[i] + ";";
        netfrmkeylist += wmi_reg_get_sz(wmi_handle:handlereg, key:netfrm + entry[i], key_name:"Version") + ";";
        netfrmkeylist += wmi_reg_get_dword_val(wmi_handle:handlereg, key:netfrm + entry[i], val_name:"SP") + "|";
      }
    }
  }
  officeregentries = wmi_reg_enum_key(wmi_handle:handlereg, key:officekey);
  if (officeregentries){
    entry = NULL;
    entry = split(officeregentries, sep:"|", keep:0);
    if(!entry)entry = officeregentries;
    for(i=0; i<max_index(entry); i++)
    {
      val = wmi_reg_get_sz(wmi_handle:handlereg, key:officekey + entry[i] + "\Common\InstallRoot\", key_name:"Path");
      if (val) {
        msodll = wmi_reg_get_sz(wmi_handle:handlereg, key:officekey + entry[i] + "\Common\FilesPaths\", key_name:"mso.dll");
        if (msodll) officepath  = val;
        officebakpath  += val + ";";
        OfficeVer = entry[i];
      }
      visiopath = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\visio.exe", key_name:"Path");
      if (visiopath){
        if(!VisioCRV)VisioCRV = wmi_reg_get_sz(wmi_handle:handlereg, key:officekey + entry[i] + "\Visio\", key_name:"CurrentlyRegisteredVersion");
        valv = wmi_reg_get_sz(wmi_handle:handlereg, key:officekey + entry[i] + "\Visio\", key_name:"InstalledVersion");
        if (valv )VisioRegVer = valv;
        if(!VisioRegVer){
          Visioregentries = wmi_reg_enum_key(wmi_handle:handlereg, key:officekey + entry[i] + "\Visio\");
          Visioentry = split(Visioregentries, sep:"|", keep:0);
          if(!Visioentry)Visioentry = Visioregentries;
          for(v=0; v<max_index(Visioentry); v++){
            valv = VisioRegVer = wmi_reg_get_sz(wmi_handle:handlereg, key:officekey + entry[i] + "\Visio\" + Visioentry[v], key_name:"InstalledVersion");
            if (valv )VisioRegVer = valv;
          }
        }
      }
    }
  }
  worksregentries = wmi_reg_enum_key(wmi_handle:handlereg, key:works);
  if(worksregentries){
    entry = NULL;
    entry = split(worksregentries, sep:"|", keep:0);
    if(!entry)entry = worksregentries;
    for(i=0; i<max_index(entry); i++)
    {
      val = wmi_reg_get_sz(wmi_handle:handlereg, key:works + entry[i], key_name:"Installdir");
      if (val) {
        ver = wmi_reg_get_sz(wmi_handle:handlereg, key:works + entry[i], key_name:"CurrentVersion");
        if (ver) workspath  = val;
        worksVer = ver;
      }
    }
  }
  if (x64){
    officeregentriesx = wmi_reg_enum_key(wmi_handle:handlereg, key:officexkey);
    if(officeregentriesx){
      entry = NULL;
      entry = split(officeregentriesx, sep:"|", keep:0);
      if(!entry)entry = officeregentriesx;
      for(i=0; i<max_index(entry); i++)
      {
        val1 = wmi_reg_get_sz(wmi_handle:handlereg, key:officexkey + entry[i] + "\Common\InstallRoot\", key_name:"Path");
        if (val1) {
          msodll1 = wmi_reg_get_sz(wmi_handle:handlereg, key:officexkey + entry[i] + "\Common\FilesPaths\", key_name:"mso.dll");
          if (msodll1) officepath  = val1;
          if (msodll1) msodll  = msodll1;
          officebakpath  += val1 + ";";
          OfficeVer = entry[i];
        }
        if(!visiopath)visiopath = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\App Paths\visio.exe", key_name:"Path");
        if (visiopath){
          if(!VisioCRV)VisioCRV = wmi_reg_get_sz(wmi_handle:handlereg, key:officexkey + entry[i] + "\Visio\", key_name:"CurrentlyRegisteredVersion");
          if(!VisioRegVer)xvalv = wmi_reg_get_sz(wmi_handle:handlereg, key:officexkey + entry[i] + "\Visio\", key_name:"InstalledVersion");
          if (xvalv )VisioRegVer = xvalv;
          if(!VisioRegVer){
            Visioregentries = wmi_reg_enum_key(wmi_handle:handlereg, key:officexkey + entry[i] + "\Visio\");
            Visioentry = split(Visioregentries, sep:"|", keep:0);
            if(!Visioentry)Visioentry = Visioregentries;
            for(v=0; v<max_index(Visioentry); v++){
              xvalv = wmi_reg_get_sz(wmi_handle:handlereg, key:officexkey + entry[i] + "\Visio\" + Visioentry[v], key_name:"InstalledVersion");
              if (xvalv )VisioRegVer = xvalv;
            }
          }
        }
      }
    }
    worksregentriesx = wmi_reg_enum_key(wmi_handle:handlereg, key:works);
    if(worksregentriesx){
      entry = NULL;
      entry = split(worksregentriesx, sep:"|", keep:0);
      if(!entry)entry = worksregentriesx;
      for(i=0; i<max_index(entry); i++)
      {
        val1 = wmi_reg_get_sz(wmi_handle:handlereg, key:works + entry[i], key_name:"Installdir");
        if (val1) {
          ver1 = wmi_reg_get_sz(wmi_handle:handlereg, key:works + entry[i], key_name:"CurrentVersion");
          if (ver1) workspath  = val1;
          if (ver1)worksVer = ver1;
        }
      }
    }
  }

  if(officepath)officepath = ereg_replace(pattern:"\\", replace:"\\", string:officepath);
  if(officebakpath)officebakpath = ereg_replace(pattern:"\\", replace:"\\", string:officebakpath);
  if(msodll)msodll = ereg_replace(pattern:"\\", replace:"\\", string:msodll);
  if(visiopath)visiopath = ereg_replace(pattern:"\\", replace:"\\", string:visiopath);

  if (OfficeVer == "10.0")
    Outlook = "OutLLib.dll";
  else
    Outlook = "OUTLOOK.exe";

  if (msodll){
    OfficeFileVer = wmi_query(wmi_handle:handle, query:'Select Version from CIM_DataFile Where Name = "' + msodll + '"' );
    if (OfficeFileVer){
      OfficeFileVer = split(OfficeFileVer, keep:0);
      OfficeFileVer = split(OfficeFileVer[1], sep:"|", keep:0);
      OfficeFileVer = OfficeFileVer[1];
    }
  }
  if (officepath){
    AccessVer = wmi_file_fileversion(handle:handle, filePath:officepath + Access, includeHeader:FALSE);
    ExcelVer = wmi_file_fileversion(handle:handle, filePath:officepath + Excel, includeHeader:FALSE);
    InfoPathVer = wmi_file_fileversion(handle:handle, filePath:officepath + InfoPath, includeHeader:FALSE);
    OneNoteVer = wmi_file_fileversion(handle:handle, filePath:officepath + OneNote, includeHeader:FALSE);
    OutlookVer = wmi_file_fileversion(handle:handle, filePath:officepath + Outlook, includeHeader:FALSE);
    PowerPointVer = wmi_file_fileversion(handle:handle, filePath:officepath + PowerPoint, includeHeader:FALSE);
    ProjectVer = wmi_file_fileversion(handle:handle, filePath:officepath + Project, includeHeader:FALSE);
    PublisherVer = wmi_file_fileversion(handle:handle, filePath:officepath + Publisher, includeHeader:FALSE);
    SharePoint_DesignerVer = wmi_file_fileversion(handle:handle, filePath:officepath + SharePoint_Designer, includeHeader:FALSE);
    SharePoint_WorkspaceVer = wmi_file_fileversion(handle:handle, filePath:officepath + SharePoint_Workspace, includeHeader:FALSE);
    WordVer = wmi_file_fileversion(handle:handle, filePath:officepath + Word, includeHeader:FALSE);
    VisioVer = wmi_file_fileversion(handle:handle, filePath:visiopath + Visio, includeHeader:FALSE);
    VisioSMBVer = fetch_file_version(sysPath:visiopath, file_name:Visio, includeHeader:FALSE);

    # TODO: This needs to be verified once WMI is enabled again.
    # For some unknown reason the following function was used
    # to split the return of wmi_file_fileversion():
    #function split_ver( value ) {
    #  val = split( value, keep:FALSE );
    #  if( "(x86)" >< val[1] ) {
    #    val = split( val[1], sep:"(x86)", keep:FALSE );
    #  }
    #  return val[1];
    #}
    # However the (x86) looks strange and its strange as well that
    # this should have been included in the version at all...
    # AccessVer = split_ver(value:AccessVer);
    # ExcelVer = split_ver(value:ExcelVer);
    # InfoPathVer = split_ver(value:InfoPathVer);
    # OneNoteVer = split_ver(value:OneNoteVer);
    # OutlookVer = split_ver(value:OutlookVer);
    # PowerPointVer = split_ver(value:PowerPointVer);
    # ProjectVer = split_ver(value:ProjectVer);
    # PublisherVer = split_ver(value:PublisherVer);
    # SharePoint_DesignerVer = split_ver(value:SharePoint_DesignerVer);
    # SharePoint_WorkspaceVer = split_ver(value:SharePoint_WorkspaceVer);
    # WordVer = split_ver(value:WordVer);
    # VisioVer = split_ver(value:VisioVer);
    # END TODO

    if (AccessVer && is_array(AccessVer)){
      foreach vers(keys(AccessVer)){
        if (AccessVer[vers] && version = egrep(string:AccessVer[vers], pattern:"([0-9.]+)" ) ) {
          AccessVer = version;
          break;
        }
      }
    }
    if (ExcelVer && is_array(ExcelVer)){
      foreach vers(keys(ExcelVer)){
        if (ExcelVer[vers] && version = egrep(string:ExcelVer[vers], pattern:"([0-9.]+)")){
          ExcelVer = version;
          break;
        }
      }
    }
    if (InfoPathVer && is_array(InfoPathVer)){
      foreach vers(keys(InfoPathVer)){
        if (InfoPathVer[vers] && version = egrep(string:InfoPathVer[vers], pattern:"([0-9.]+)")){
          InfoPathVer = version;
          break;
        }
      }
    }
    if (OneNoteVer && is_array(OneNoteVer)){
      foreach vers(keys(OneNoteVer)){
        if (OneNoteVer[vers] && version = egrep(string:OneNoteVer[vers], pattern:"([0-9.]+)")){
          OneNoteVer = version;
          break;
        }
      }
    }
    if (OutlookVer && is_array(OutlookVer)){
      foreach vers(keys(OutlookVer)){
        if (OutlookVer[vers] && version = egrep(string:OutlookVer[vers], pattern:"([0-9.]+)")){
          OutlookVer = version;
          break;
        }
      }
    }
    if (PowerPointVer && is_array(PowerPointVer)){
      foreach vers(keys(PowerPointVer)){
        if (PowerPointVer[vers] && version = egrep(string:PowerPointVer[vers], pattern:"([0-9.]+)")){
          PowerPointVer = version;
          break;
        }
      }
    }
    if (ProjectVer && is_array(ProjectVer)){
      foreach vers(keys(ProjectVer)){
        if (ProjectVer[vers] && version = egrep(string:ProjectVer[vers], pattern:"([0-9.]+)")){
          ProjectVer = version;
          break;
        }
      }
    }
    if (PublisherVer && is_array(PublisherVer)){
      foreach vers(keys(PublisherVer)){
        if (PublisherVer[vers] && version = egrep(string:PublisherVer[vers], pattern:"([0-9.]+)")){
          PublisherVer = version;
          break;
        }
      }
    }
    if (SharePoint_DesignerVer && is_array(SharePoint_DesignerVer)){
      foreach vers(keys(SharePoint_DesignerVer)){
        if (SharePoint_DesignerVer[vers] && version = egrep(string:SharePoint_DesignerVer[vers], pattern:"([0-9.]+)")){
          SharePoint_DesignerVer = version;
          break;
        }
      }
    }
    if (SharePoint_WorkspaceVer && is_array(SharePoint_WorkspaceVer)){
      foreach vers(keys(SharePoint_WorkspaceVer)){
        if (SharePoint_WorkspaceVer[vers] && version = egrep(string:SharePoint_WorkspaceVer[vers], pattern:"([0-9.]+)")){
          SharePoint_WorkspaceVer = version;
          break;
        }
      }
    }
    if (WordVer && is_array(WordVer)){
      foreach vers(keys(WordVer)){
        if (WordVer[vers] && version = egrep(string:WordVer[vers], pattern:"([0-9.]+)")){
          WordVer = version;
          break;
        }
      }
    }
    if (VisioVer && is_array(VisioVer)){
      foreach vers(keys(VisioVer)){
        if (VisioVer[vers] && version = egrep(string:VisioVer[vers], pattern:"([0-9.]+)")){
          VisioVer = version;
          break;
        }
      }
    }
  }
  if (!VisioRegVer && VisioSMBVer)VisioRegVer = VisioSMBVer;
  if(version_is_less(version:VisioRegVer, test_version:VisioSMBVer))VisioRegVer = VisioSMBVer;
  if (!VisioVer && VisioRegVer)VisioVer = VisioRegVer;

  directx = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\DirectX", key_name:"Version");
  iever = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Internet Explorer", key_name:"Version");
  oever= wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Outlook Express\Version Info", key_name:"Current");
  if(oever)oever = ereg_replace(pattern:",", replace:".", string:oever);
  wmplayer = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\wmplayer.exe", key_name:"Path");
  wmplayerver = fetch_file_version(sysPath:wmplayer, file_name:"wmplayer.exe");

  mdacfullver = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\DataAccess", key_name:"FullInstallVer");
  mdacver = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\DataAccess", key_name:"Version");

  IISMinorVersion = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\INetStp", val_name:"MinorVersion");
  IISMajorVersion = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\INetStp", val_name:"MajorVersion");

  ipnathlp = wmi_file_check_file_exists(handle:handle, filePath:OSSYSDIR + "\\ipnathlp.dll");

  ExchProductMajor = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Exchange\Setup", val_name:"MsiProductMajor");
  ExchProductMinor = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Exchange\Setup", val_name:"MsiProductMinor");
  ExchSPBuild = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Exchange\Setup", val_name:"ServicePackBuild");

  Exch2010ProductMajor = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"Software\Microsoft\ExchangeServer\v14\Setup", val_name:"MsiProductMajor");
  Exch2010ProductMinor = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"Software\Microsoft\ExchangeServer\v14\Setup", val_name:"MsiProductMinor");
  Exch2010BuildMajor = wmi_reg_get_dword_val(wmi_handle:handlereg, keyy:"Software\Microsoft\ExchangeServer\v14\Setup", val_name:"MsiBuildMajor");
  Exch2010BuildMinor = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"Software\Microsoft\ExchangeServer\v14\Setup", val_name:"MsiBuildMinor");

  Exch2013ProductMajor = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"Software\Microsoft\ExchangeServer\v15\Setup", val_name:"MsiProductMajor");
  Exch2013DispName = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Exchange v15", key_name:"DisplayName");

  msxml3 = wmi_file_check_file_exists(handle:handle, filePath:OSSYSDIR + "\\msxml3.dll");
  msxml4 = wmi_file_check_file_exists(handle:handle, filePath:OSSYSDIR + "\\msxml4.dll");
  if (x64)msxml5 = wmi_file_check_file_exists(handle:handle, filePath:ComFilesDirx86 + "\\Microsoft Shared\\OFFICE11\\msxml5.dll");
  else msxml5 = wmi_file_check_file_exists(handle:handle, filePath:ComFilesDir + "\\Microsoft Shared\\OFFICE11\\msxml5.dll");
  msxml6 = wmi_file_check_file_exists(handle:handle, filePath:OSSYSDIR + "\\msxml6.dll");

  NDPv4Client = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Client", val_name:"Install");
  NDPv4ClientVer = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Client", key_name:"Version");
  NDPv4Full = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full", val_name:"Install");
  NDPv4FullVer = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full", key_name:"Version");

#  wlmessenger = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{A85FD55B-891B-4314-97A5-EA96C0BD80B5}", key_name:"DisplayVersion")

  sqlregentries = wmi_reg_enum_key(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Microsoft SQL Server");
  if (x64)sqlregentriesx = wmi_reg_enum_key(wmi_handle:handlereg, key:"SOFTWARE\Wow6432Node\Microsoft\Microsoft SQL Server");

  messenger = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Active Setup\Installed Components\{5945c046-1e7d-11d1-bc44-00c04fd912be}", key_name:"Version");
  if (messenger)messenger = ereg_replace(pattern:",", replace:".", string:messenger);

  crmver = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\NCompass\Resolution Content Server\VersionInfo", key_name:"Version");
  if(crmver)crmsp = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\NCompass\Resolution Content Server\VersionInfo", key_name:"Patches");

  isapath = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Fpc", key_name:"InstallDirectory");
  if (isapath){
    isapath = ereg_replace(pattern:"\\", replace:"\\", string:isapath);
    IsaVer = wmi_file_fileversion(handle:handle, filePath:isapath + "wspsrv.exe", includeHeader:FALSE);
    if (IsaVer && is_array(IsaVer)){
      foreach vers(keys(IsaVer)){
        if (IsaVer[vers] && version = egrep(string:IsaVer[vers], pattern:"([0-9.]+)" ) ) {
          IsaVer = version;
          break;
        }
      }
    }
  }

  vsdotnet2k2sp = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Updates\Visual Studio\7.0\S895309", key_name:"Type");
  vsdotnet2k3sp = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Updates\Visual Studio\7.1\S918007", key_name:"Type");

 if (x64){
  VS2002path = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Wow6432Node\Microsoft\VisualStudio\7.0", key_name:"Installdir");
  if (VS2002path){
    VS2002path = ereg_replace(pattern:"\\", replace:"\\", string:VS2002path);
    VS2002 = wmi_file_check_file_exists(handle:handle, filePath:VS2002path + "devenv.exe");
  }
  VS2003path = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Wow6432Node\Microsoft\VisualStudio\7.1", key_name:"Installdir");
  if (VS2003path){
    VS2003path = ereg_replace(pattern:"\\", replace:"\\", string:VS2003path);
    VS2003 = wmi_file_check_file_exists(handle:handle, filePath:VS2003path + "devenv.exe");
  }
  VS2005path = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Wow6432Node\Microsoft\VisualStudio\8.0", key_name:"Installdir");
  if (VS2005path) {
    VS2005path = ereg_replace(pattern:"\\", replace:"\\", string:VS2005path);
    VS2005 = wmi_file_check_file_exists(handle:handle, filePath:VS2005path + "devenv.exe");
    VS2005SP = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SOFTWARE\Wow6432Node\Microsoft\DevDiv\VS\Servicing\8.0", val_name:"SP");
  }
  VS2008path = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Wow6432Node\Microsoft\VisualStudio\9.0", key_name:"Installdir");
  if (VS2008path){
    VS2008path = ereg_replace(pattern:"\\", replace:"\\", string:VS2008path);
    VS2008 = wmi_file_check_file_exists(handle:handle, filePath:VS2008path + "devenv.exe");
    VS2008SP = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SOFTWARE\Wow6432Node\Microsoft\DevDiv\VS\Servicing\9.0", val_name:"SP");
  }
  VS2010path = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Wow6432Node\Microsoft\VisualStudio\10.0", key_name:"Installdir");
  if (VS2010path){
    VS2010path = ereg_replace(pattern:"\\", replace:"\\", string:VS2010path);
    VS2010 = wmi_file_check_file_exists(handle:handle, filePath:VS2010path + "devenv.exe");
    VS2010SP = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SOFTWARE\Wow6432Node\Microsoft\DevDiv\VS\Servicing\10.0", val_name:"SP");
  }
  VS2012path = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Wow6432Node\Microsoft\VisualStudio\11.0", key_name:"Installdir");
  if (VS2012path){
    VS2012path = ereg_replace(pattern:"\\", replace:"\\", string:VS2012path);
    VS2012 = wmi_file_check_file_exists(handle:handle, filePath:VS2012path + "devenv.exe");
    VS2012SP = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SOFTWARE\Wow6432Node\Microsoft\DevDiv\VS\Servicing\11.0", val_name:"SP");
  }
  VS2013path = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Wow6432Node\Microsoft\VisualStudio\12.0", key_name:"Installdir");
  if (VS2013path){
    VS2013path = ereg_replace(pattern:"\\", replace:"\\", string:VS2013path);
    VS2013 = wmi_file_check_file_exists(handle:handle, filePath:VS2013path + "devenv.exe");
    VS2013SP = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SOFTWARE\Wow6432Node\Microsoft\DevDiv\VS\Servicing\12.0", val_name:"SP");
  }
  VS2015path = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Wow6432Node\Microsoft\VisualStudio\14.0", key_name:"Installdir");
  if (VS2015path){
    VS2015path = ereg_replace(pattern:"\\", replace:"\\", string:VS2015path);
    VS2015 = wmi_file_check_file_exists(handle:handle, filePath:VS2015path + "devenv.exe");
    VS2015SP = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SOFTWARE\Wow6432Node\Microsoft\DevDiv\VS\Servicing\14.0", val_name:"SP");
  }
 }
 else{
  VS2002path = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\VisualStudio\7.0", key_name:"Installdir");
  if (VS2002path){
    VS2002path = ereg_replace(pattern:"\\", replace:"\\", string:VS2002path);
    VS2002 = wmi_file_check_file_exists(handle:handle, filePath:VS2002path + "devenv.exe");
  }
  VS2003path = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\VisualStudio\7.1", key_name:"Installdir");
  if (VS2003path){
    VS2003path = ereg_replace(pattern:"\\", replace:"\\", string:VS2003path);
    VS2003 = wmi_file_check_file_exists(handle:handle, filePath:VS2003path + "devenv.exe");
  }
  VS2005path = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\VisualStudio\8.0", key_name:"Installdir");
  if (VS2005path) {
    VS2005path = ereg_replace(pattern:"\\", replace:"\\", string:VS2005path);
    VS2005 = wmi_file_check_file_exists(handle:handle, filePath:VS2005path + "devenv.exe");
    VS2005SP = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\DevDiv\VS\Servicing\8.0", val_name:"SP");
  }
  VS2008path = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\VisualStudio\9.0", key_name:"Installdir");
  if (VS2008path){
    VS2008path = ereg_replace(pattern:"\\", replace:"\\", string:VS2008path);
    VS2008 = wmi_file_check_file_exists(handle:handle, filePath:VS2008path + "devenv.exe");
    VS2008SP = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\DevDiv\VS\Servicing\9.0", val_name:"SP");
  }
  VS2010path = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\VisualStudio\10.0", key_name:"Installdir");
  if (VS2010path){
    VS2010path = ereg_replace(pattern:"\\", replace:"\\", string:VS2010path);
    VS2010 = wmi_file_check_file_exists(handle:handle, filePath:VS2010path + "devenv.exe");
    VS2010SP = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\DevDiv\VS\Servicing\10.0", val_name:"SP");
  }
  VS2012path = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\VisualStudio\11.0", key_name:"Installdir");
  if (VS2012path){
    VS2012path = ereg_replace(pattern:"\\", replace:"\\", string:VS2012path);
    VS2012 = wmi_file_check_file_exists(handle:handle, filePath:VS2012path + "devenv.exe");
    VS2012SP = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\DevDiv\VS\Servicing\11.0", val_name:"SP");
  }
  VS2013path = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\VisualStudio\12.0", key_name:"Installdir");
  if (VS2013path){
    VS2013path = ereg_replace(pattern:"\\", replace:"\\", string:VS2013path);
    VS2013 = wmi_file_check_file_exists(handle:handle, filePath:VS2013path + "devenv.exe");
    VS2013SP = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\DevDiv\VS\Servicing\12.0", val_name:"SP");
  }
  VS2015path = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\VisualStudio\14.0", key_name:"Installdir");
  if (VS2015path){
    VS2015path = ereg_replace(pattern:"\\", replace:"\\", string:VS2015path);
    VS2015 = wmi_file_check_file_exists(handle:handle, filePath:VS2015path + "devenv.exe");
    VS2015SP = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\DevDiv\VS\Servicing\14.0", val_name:"SP");
  }
 }

  MVS2005STen = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\0EEDF7F0258333042A16F38A4BEC64C6\InstallProperties", key_name:"DisplayName");
  MVS2005STja = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\67EC4B5345C7E7347BBA24CFF8B977B6\InstallProperties", key_name:"DisplayName");

  MVS2005ENTen = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\813ACF1D304B0FB43A2E440E1CF2ADD3\InstallProperties", key_name:"DisplayName");
  MVS2005ENTja = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\C31148E7379AA7C48BF2343AB582C3D8\InstallProperties", key_name:"DisplayName");

  MVS2005R2 = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Classes\Installer\Products\768AAF4834783C442BE25B1A2554D677", key_name:"ProductName");
  MVS2005R2ST = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Classes\Installer\Products\96CF2B3B315599C4A9E75C85A4295880", key_name:"ProductName");
  MVS2005R2ENT = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Classes\Installer\Products\2ACE96BF53CE47C46B808783D50059D9", key_name:"ProductName");

  MVP2004 = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Classes\Installer\Products\B56328045890A99429D04E4D14D45CF8", key_name:"ProductName");
  MVP2004SP1  = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Classes\Installer\Products\EDDFACCCCECE4EA4DB79400767BB4D9A", key_name:"ProductName");

  MVP2007 = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Classes\Installer\Products\42AAC7A832B7B0147A3C9F490B491406", key_name:"ProductName");
  MVP2007SP1  = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Classes\Installer\Products\899384DAA9E2504438FFE605A34FC9BB", key_name:"ProductName");

#  wmi_close(wmi_handle:handle);
#  wmi_close(wmi_handle:handlereg);
}

# nb: Check if keylist exists and set missing wmi variable for future work
if (!keylist) keylist = smbkeylist;
if (!sqlregentries) sqlregentries = smbsqlregentries;
if (!sqlregentriesx) sqlregentriesx = smbsqlregentriesx;

#if (!keylist) exit(0);
if (keylist)instprg = split(keylist, sep:"|", keep:0);
if (!OSNAME) OSNAME = smbosname;
if (OSNAME) lowOSNAME = tolower(OSNAME);
if (!OSVER) OSVER = version;
if (!OSSP && OSSP != "0") OSSP = spver;

if ("Windows NT" >< OSNAME && OSVER < 3) register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:"cpe:/o:microsoft:windows_nt", desc:SCRIPT_DESC);
else if (OSVER == "3.0.1") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:"cpe:/o:microsoft:windows_nt:3.0.1", desc:SCRIPT_DESC);
else if (OSVER == "3.1") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:"cpe:/o:microsoft:windows_nt:3.1", desc:SCRIPT_DESC);
else if (OSVER == "3.5") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:"cpe:/o:microsoft:windows_nt:3.5", desc:SCRIPT_DESC);
else if (OSVER == "3.5.1") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:"cpe:/o:microsoft:windows_nt:3.5.1", desc:SCRIPT_DESC);
else if (OSVER == "3.5.1" && OSSP != "0") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:"cpe:/o:microsoft:windows_nt:3.5.1:sp" + OSSP, desc:SCRIPT_DESC);
else if (OSVER == "3.51") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:"cpe:/o:microsoft:windows_nt:3.51", desc:SCRIPT_DESC);

else if (OSVER == "4.0"){
  cpe = "cpe:/o:microsoft:windows_nt";
  if (OSSP == "0") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":4.0:gold", desc:SCRIPT_DESC);
  else if (OSSP != "0") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":4.0:sp" + OSSP, desc:SCRIPT_DESC);
  else if (OSSP == "0" && "WinNT" >< type)register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":4.0:gold:workstation", desc:SCRIPT_DESC);
  else if (OSSP == "0" && ("ServerNT" >< type || "LanmanNT">< type))register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":4.0:gold:server", desc:SCRIPT_DESC);
  else if (OSSP == "0" && "Enterprise" >< type)register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":4.0:gold:enterprise", desc:SCRIPT_DESC);
  else if (OSSP == "0" && "Terminal Server">< type)register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":4.0:gold:terminal_server", desc:SCRIPT_DESC);
  else if (OSSP != "0" && "WinNT" >< type)register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":4.0:sp" + OSSP + ":workstation", desc:SCRIPT_DESC);
  else if (OSSP != "0" && ("ServerNT" >< type || "LanmanNT">< type))register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":4.0:sp" + OSSP + ":server", desc:SCRIPT_DESC);
  else if (OSSP != "0" && "Enterprise" >< type)register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":4.0:sp" + OSSP + ":enterprise", desc:SCRIPT_DESC);
  else if (OSSP != "0" && "Terminal Server" >< type)register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":4.0:sp" + OSSP + ":terminal_server", desc:SCRIPT_DESC);
  else register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":4.0", desc:SCRIPT_DESC);
}
if (OSVER == "5.0"){
  cpe = "cpe:/o:microsoft:windows_2000";

  if (OSSP == "0" ) register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold", desc:SCRIPT_DESC);
  else if (OSSP != "0") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp" + OSSP, desc:SCRIPT_DESC);
  else if (OSSP == "0" && ("ServerNT" >< type || "LanmanNT">< type))register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold:server", desc:SCRIPT_DESC);
  else if (OSSP == "0" && "WinNT" >< type)register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold:professional", desc:SCRIPT_DESC);
  else if (OSSP != "0" && "WinNT" >< type)register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp" + OSSP + ":professional", desc:SCRIPT_DESC);
  else if (OSSP != "0" && ("ServerNT" >< type || "LanmanNT">< type))register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp" + OSSP + ":server", desc:SCRIPT_DESC);
  else register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:"cpe:/o:microsoft:windows_2000", desc:SCRIPT_DESC);
}
if (OSVER == "5.1"){
  cpe = "cpe:/o:microsoft:windows_xp";
  if (OSSP == "0"){
    if (Embedded_NT)register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold:embedded", desc:SCRIPT_DESC);
    else if ("professional" >< lowOSNAME) register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold:professional", desc:SCRIPT_DESC);
    else if ("home" >< lowOSNAME) register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold:home", desc:SCRIPT_DESC);
    else if ("media" >< lowOSNAME) register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold:media_center", desc:SCRIPT_DESC);
    else if ("tablet" >< lowOSNAME) register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold:tablet_pc", desc:SCRIPT_DESC);
    else register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold", desc:SCRIPT_DESC);
  }
  else if (OSSP == "1" || OSSP == "2"){
    if (Embedded_NT)register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp" + OSSP + ":embedded", desc:SCRIPT_DESC);
    else if ("professional" >< lowOSNAME) register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp" + OSSP + ":professional", desc:SCRIPT_DESC);
    else if ("media" >< lowOSNAME) register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp" + OSSP + ":media_center", desc:SCRIPT_DESC);
    else if ("tablet" >< lowOSNAME) register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp" + OSSP + ":tablet_pc", desc:SCRIPT_DESC);
  }
  else if (OSSP == "3"){
    if (Embedded_NT)register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp3:embedded", desc:SCRIPT_DESC);
    else if ("professional" >< lowOSNAME) register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp3:professional", desc:SCRIPT_DESC);
    else if ("media" >< lowOSNAME) register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp3:media_center", desc:SCRIPT_DESC);
    else if ("tablet" >< lowOSNAME) register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp3:tablet_pc", desc:SCRIPT_DESC);
  }
  if (OSSP != "0" && ("home" >< lowOSNAME )) register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp" + OSSP + ":home", desc:SCRIPT_DESC);
  else if (OSSP != "0") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp" + OSSP, desc:SCRIPT_DESC);
  else if (!OSSP) register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:"cpe:/o:microsoft:windows_xp", desc:SCRIPT_DESC);
}
if (OSVER == "5.2"){
  if ("WinNT" >< type){
  cpe = "cpe:/o:microsoft:windows_xp";
    if (OSSP != "0" && x64 == "1") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp" + OSSP + ":x64", desc:SCRIPT_DESC);
    if (x64 != 1) register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:-:x86", desc:SCRIPT_DESC);
    if (OSSP == "2" && x64 != 1) register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp2:x86", desc:SCRIPT_DESC);
    if (OSSP == "0" && x64 == "1") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold:x64", desc:SCRIPT_DESC);
  }
  else if ("WinNT" >!< type){
    cpe = "cpe:/o:microsoft:windows_server_2003";
    if (OSCPU && OSOTD != "R2"){
      if (x64 != "1"){
        if (OSSP == "0" && !DataCenter && !Enterprise && !Web_2003 && !SBS_R) register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold:standard", desc:SCRIPT_DESC);
        else if (OSSP != "0" && !DataCenter && !Enterprise && !Web_2003 && !SBS_R) register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp" + OSSP + ":standard", desc:SCRIPT_DESC);
        else if (OSSP == "0" && DataCenter) register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold:datacenter", desc:SCRIPT_DESC);
        else if (OSSP == "0" && Enterprise) register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold:enterprise", desc:SCRIPT_DESC);
        else if (OSSP != "0" && DataCenter) register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp" + OSSP + ":datacenter", desc:SCRIPT_DESC);
        else if (OSSP != "0" && Enterprise) register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp" + OSSP + ":enterprise", desc:SCRIPT_DESC);
        else if (OSSP != "0") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp" + OSSP, desc:SCRIPT_DESC);
        else if (OSSP == "2") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp2", desc:SCRIPT_DESC);
        else if (OSSP == "0") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold", desc:SCRIPT_DESC);
      }
      else if (x64 == "1"){
        if (OSSP == "0" && OSCPU == "9" && !DataCenter && !Enterprise && !Web_2003 && !SBS_R) register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold:x64-standard", desc:SCRIPT_DESC);
        else if (OSSP != "0" && OSCPU == "9" && !DataCenter && !Enterprise && !Web_2003 && !SBS_R) register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp" + OSSP + ":x64-standard", desc:SCRIPT_DESC);
        else if (OSSP == "0" && OSCPU == "9" && DataCenter) register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold:x64-datacenter", desc:SCRIPT_DESC);
        else if (OSSP == "0" && OSCPU == "9" && Enterprise) register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold:x64-enterprise", desc:SCRIPT_DESC);
        else if (OSSP != "0" && OSCPU == "9") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp" + OSSP + ":x64", desc:SCRIPT_DESC);
        else if (OSSP == "0" && OSCPU == "9") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold:x64", desc:SCRIPT_DESC);

        if (OSSP == "2" && OSCPU == "9") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp2:x64", desc:SCRIPT_DESC);
        else if (OSSP == "0" && OSCPU == "9") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:-:x64", desc:SCRIPT_DESC);
      }

      if (OSSP == "0" && OSCPU == "6") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold:itanium", desc:SCRIPT_DESC);
      if (OSSP == "1" && OSCPU == "6") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp1:itanium", desc:SCRIPT_DESC);
      if (OSSP == "2" && OSCPU == "6") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp2:itanium", desc:SCRIPT_DESC);

    }
    else if (OSCPU && OSOTD == "R2"){
      if (x64 != "1"){
        if (16384 >= OSPRODS) register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":r2:-:compute_cluster", desc:SCRIPT_DESC);
        else if (Stor_Serv_2003R2) register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":r2:-:storage", desc:SCRIPT_DESC);
        else if (!DataCenter && !Enterprise && !Web_2003 && !SBS_R && !Stor_Serv_2003R2) register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":r2:-:standard", desc:SCRIPT_DESC);
        else if (Enterprise) register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":r2:-:enterprise", desc:SCRIPT_DESC);
        else if (DataCenter) register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":r2:-:datacenter", desc:SCRIPT_DESC);
        else register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":r2", desc:SCRIPT_DESC);
      }
      else if (x64 == "1"){
        if (OSCPU == "9" && !DataCenter && !Enterprise && !Web_2003 && !SBS_R && !Stor_Serv_2003R2) register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":r2:-:x64-standard", desc:SCRIPT_DESC);
        else if (Enterprise && OSCPU == "9") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":r2:-:x64-enterprise", desc:SCRIPT_DESC);
        else if (DataCenter && OSCPU == "9") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":r2:-:x64-datacenter", desc:SCRIPT_DESC);
        else if (OSCPU == "9") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":r2:-:x64", desc:SCRIPT_DESC);
      }
    }
    #SMB fallback. Is not so exactly as wmi.
    else if(!OSCPU){
      if (x64 != "1"){
#        if (OSSP == "0" && !DataCenter && !Enterprise && !Web_2003 && !SBS_R) register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold:standard", desc:SCRIPT_DESC);
#        else if (OSSP != "0" && !DataCenter && !Enterprise && !Web_2003 && !SBS_R) register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp" + OSSP + ":standard", desc:SCRIPT_DESC);
#        else if (OSSP == "0" && DataCenter) register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold:datacenter", desc:SCRIPT_DESC);
#        else if (OSSP == "0" && Enterprise) register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold:enterprise", desc:SCRIPT_DESC);
#        else if (OSSP != "0" && DataCenter) register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp" + OSSP + ":datacenter", desc:SCRIPT_DESC);
#        else if (OSSP != "0" && Enterprise) register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp" + OSSP + ":enterprise", desc:SCRIPT_DESC);
        if (OSSP != "0") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp" + OSSP, desc:SCRIPT_DESC);
        else if (OSSP == "2") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp2", desc:SCRIPT_DESC);
        else if (OSSP == "0") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold", desc:SCRIPT_DESC);
      }
      else if (x64 == "1"){
#        if (OSSP == "0" && cputype == "AMD64" && !DataCenter && !Enterprise && !Web_2003 && !SBS_R) register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold:x64-standard", desc:SCRIPT_DESC);
#        else if (OSSP != "0" && cputype == "AMD64" && !DataCenter && !Enterprise && !Web_2003 && !SBS_R) register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp" + OSSP + ":x64-standard", desc:SCRIPT_DESC);
#        else if (OSSP == "0" && cputype == "AMD64" && DataCenter) register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold:x64-datacenter", desc:SCRIPT_DESC);
#        else if (OSSP == "0" && cputype == "AMD64" && Enterprise) register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold:x64-enterprise", desc:SCRIPT_DESC);
        if (OSSP != "0" && cputype == "AMD64") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp" + OSSP + ":x64", desc:SCRIPT_DESC);
        else if (OSSP == "0" && cputype == "AMD64") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold:x64", desc:SCRIPT_DESC);
        else if (OSSP == "0" && cputype == "AMD64") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold:x64", desc:SCRIPT_DESC);
        if (OSSP == "2" && cputype == "AMD64") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp2:x64", desc:SCRIPT_DESC);
        else if (OSSP == "0" && cputype == "AMD64") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:-:x64", desc:SCRIPT_DESC);
      }
      if (OSSP == "0" && cputype =="IA64") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold:itanium", desc:SCRIPT_DESC);
      if (OSSP == "1" && cputype =="IA64") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp1:itanium", desc:SCRIPT_DESC);
      if (OSSP == "2" && cputype =="IA64") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp2:itanium", desc:SCRIPT_DESC);
    }
    else register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe, desc:SCRIPT_DESC);
  }
}
if (OSVER == "6.0"){
  if(OSTYPE == "1"){#Vista
    cpe = "cpe:/o:microsoft:windows_vista";
    if (OSSP == "0") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold", desc:SCRIPT_DESC);
    if (x64 != "1"){
      if (OSSP == "0"){
        if(OSSKU == "4")register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:-:x86-enterprise", desc:SCRIPT_DESC);
        else if(OSSKU == "1")register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:-:x86-ultimate", desc:SCRIPT_DESC);
        else register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:-:x86", desc:SCRIPT_DESC);
      }
      if (OSSP == "1"){
        if(OSSKU == "4")register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp1:x86-enterprise", desc:SCRIPT_DESC);
        else if(OSSKU == "1")register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp1:x86-ultimate", desc:SCRIPT_DESC);
        else{
          register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp1", desc:SCRIPT_DESC);
        }
      }
      if (OSSP == "2"){
        register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp2", desc:SCRIPT_DESC);
      }
    }
    else if (x64 == "1"){
      if (OSSP == "0"){
        if(OSSKU == "4")register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:-:x64-enterprise", desc:SCRIPT_DESC);
        else if(OSSKU == "1")register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:-:x64-ultimate", desc:SCRIPT_DESC);
        else {
          register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:-:x64", desc:SCRIPT_DESC);
        }
      }
      if (OSSP == "1"){
        if(OSSKU == "4")register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp1:x64-enterprise", desc:SCRIPT_DESC);
        else if(OSSKU == "1")register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp1:x64-ultimate", desc:SCRIPT_DESC);
        else if(OSSKU == "3")register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp1:x64-home_premium", desc:SCRIPT_DESC);
        else {
          register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp1:x64", desc:SCRIPT_DESC);
        }
      }
      if (OSSP == "2"){
        register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp2:x64", desc:SCRIPT_DESC);
      }
    }
    else register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe, desc:SCRIPT_DESC);
  }
  else if(OSTYPE == "2" || OSTYPE == "3"){#Windows 2008
    cpe = "cpe:/o:microsoft:windows_server_2008";
    if (x64 != "1"){
      if (OSSP == "0"){
        if(OSSKU == "8" || OSSKU == "12")register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold:datacenter", desc:SCRIPT_DESC);
        else if(OSSKU == "4" || OSSKU == "14"|| OSSKU == "10")register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold:enterprise", desc:SCRIPT_DESC);
        else if(OSSKU == "18")register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold:hpc", desc:SCRIPT_DESC);
        else if(OSSKU == "7" || OSSKU == "13")register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold:standard", desc:SCRIPT_DESC);
        else if(OSSKU == "20" || OSSKU == "21" || OSSKU == "22" || OSSKU == "23")register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold:storage", desc:SCRIPT_DESC);
        else if(OSSKU == "17")register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold:web", desc:SCRIPT_DESC);
        else register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold", desc:SCRIPT_DESC);
      }
      else if (OSSP == "1"){
        if(OSSKU == "4" || OSSKU == "14")register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp1:enterprise", desc:SCRIPT_DESC);
      }
      else if (OSSP == "2"){
        if(OSSKU == "8" || OSSKU == "12")register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp2:datacenter", desc:SCRIPT_DESC);
        else if(OSSKU == "4" || OSSKU == "14"|| OSSKU == "10")register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp2:enterprise", desc:SCRIPT_DESC);
        else if(OSSKU == "18")register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp2:hpc", desc:SCRIPT_DESC);
        else if(OSSKU == "7" || OSSKU == "13")register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp2:standard", desc:SCRIPT_DESC);
        else if(OSSKU == "20" || OSSKU == "21" || OSSKU == "22" || OSSKU == "23")register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp2:storage", desc:SCRIPT_DESC);
        else if(OSSKU == "17")register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp2:web", desc:SCRIPT_DESC);
        else {
          register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp2", desc:SCRIPT_DESC);
          register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp2:x32", desc:SCRIPT_DESC);
        }
      }
      else register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:-:x32", desc:SCRIPT_DESC);
    }
    else if (x64 == "1" && OSCPU != "6"){
      if (OSSP == "0"){
      }
      else if (OSSP == "1"){
        if(OSSKU == "4" || OSSKU == "14"|| OSSKU == "10")register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp1:enterprise_x64", desc:SCRIPT_DESC);
      }
      else if (OSSP == "2"){
        register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp2:x64", desc:SCRIPT_DESC);
        if(OSSKU == "4" || OSSKU == "14"|| OSSKU == "10")register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp2:enterprise_x64", desc:SCRIPT_DESC);
      }
      else{
        register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:-:x64", desc:SCRIPT_DESC);
      }
    }
    else if (OSSP == "0" && OSSKU == "15") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:-:itanium", desc:SCRIPT_DESC);
    else if (OSSP == "0" && OSSKU == "15") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold:itanium", desc:SCRIPT_DESC);
    else if (OSSP == "2" && OSSKU == "15") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp2:itanium", desc:SCRIPT_DESC);
    else register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe, desc:SCRIPT_DESC);
  }
  #SMB fallback. Is not so exactly as wmi.
  else if(!OSTYPE){
    if("Vista" >< OSNAME){#Vista
      cpe = "cpe:/o:microsoft:windows_vista";
      if (OSSP == "0") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold", desc:SCRIPT_DESC);
      if (x64 != "1"){
        if (OSSP == "0"){
          if("enterprise" >< lowOSNAME)register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:-:x86-enterprise", desc:SCRIPT_DESC);
          else if("ultimate" >< lowOSNAME)register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:-:x86-ultimate", desc:SCRIPT_DESC);
          else register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:-:x86", desc:SCRIPT_DESC);
        }
        if (OSSP == "1"){
          if("enterprise" >< lowOSNAME)register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp1:x86-enterprise", desc:SCRIPT_DESC);
          else if("ultimate" >< lowOSNAME)register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp1:x86-ultimate", desc:SCRIPT_DESC);
          else{
            register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp1", desc:SCRIPT_DESC);
          }
        }
        if (OSSP == "2"){
          register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp2", desc:SCRIPT_DESC);
        }
      }
      else if (x64 == "1"){
        if (OSSP == "0"){
          if("enterprise" >< lowOSNAME)register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:-:x64-enterprise", desc:SCRIPT_DESC);
          else if("ultimate" >< lowOSNAME)register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:-:x64-ultimate", desc:SCRIPT_DESC);
          else if("premium" >< lowOSNAME)register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:-:x64-home_premium", desc:SCRIPT_DESC);
          else {
            register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:-:x64", desc:SCRIPT_DESC);
          }
        }
        if (OSSP == "1"){
          if("enterprise" >< lowOSNAME)register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp1:x64-enterprise", desc:SCRIPT_DESC);
          else if("ultimate" >< lowOSNAME)register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp1:x64-ultimate", desc:SCRIPT_DESC);
          else if("premium" >< lowOSNAME)register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp1:x64-home_premium", desc:SCRIPT_DESC);
          else {
            register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp1:x64", desc:SCRIPT_DESC);
          }
        }
        if (OSSP == "2"){
          register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp2:x64", desc:SCRIPT_DESC);
        }
      }
      else register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe, desc:SCRIPT_DESC);
    }
    if("Windows Server 2008" >< OSNAME){#Windows 2008
      cpe = "cpe:/o:microsoft:windows_server_2008";
      if (x64 != "1"){
        if (OSSP == "0"){
          if("datacenter" >< lowOSNAME)register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold:datacenter", desc:SCRIPT_DESC);
          else if("enterprise" >< lowOSNAME)register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold:enterprise", desc:SCRIPT_DESC);
          else if("cluster" >< lowOSNAME)register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold:hpc", desc:SCRIPT_DESC);
          else if("standard" >< lowOSNAME)register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold:standard", desc:SCRIPT_DESC);
          else if("storage" >< lowOSNAME)register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold:storage", desc:SCRIPT_DESC);
          else if("web" >< lowOSNAME)register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold:web", desc:SCRIPT_DESC);
          else register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold", desc:SCRIPT_DESC);
        }
        else if (OSSP == "1"){
          if("enterprise" >< lowOSNAME)register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp1:enterprise", desc:SCRIPT_DESC);
        }
        else if (OSSP == "2"){
          if("datacenter" >< lowOSNAME)register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp2:datacenter", desc:SCRIPT_DESC);
          else if("enterprise" >< lowOSNAME)register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp2:enterprise", desc:SCRIPT_DESC);
          else if("cluster" >< lowOSNAME)register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp2:hpc", desc:SCRIPT_DESC);
          else if("standard" >< lowOSNAME)register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp2:standard", desc:SCRIPT_DESC);
          else if("storage" >< lowOSNAME)register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp2:storage", desc:SCRIPT_DESC);
          else if("web" >< lowOSNAME)register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp2:web", desc:SCRIPT_DESC);
          else {
            register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp2", desc:SCRIPT_DESC);
            register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp2:x32", desc:SCRIPT_DESC);
          }
        }
        else register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:-:x32", desc:SCRIPT_DESC);
      }
      else if (x64 == "1" && OSCPU != "6"){
        if (OSSP == "0"){
        }
        else if (OSSP == "1"){
          if("enterprise" >< lowOSNAME)register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp1:enterprise_x64", desc:SCRIPT_DESC);
        }
        else if (OSSP == "2"){
          register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp2:x64", desc:SCRIPT_DESC);
          if("enterprise" >< lowOSNAME)register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp2:enterprise_x64", desc:SCRIPT_DESC);
        }
        else{
          register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:-:x64", desc:SCRIPT_DESC);
        }
      }
      else if (OSSP == "0" && cputype =="IA64") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:-:itanium", desc:SCRIPT_DESC);
      else if (OSSP == "0" && cputype =="IA64") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:gold:itanium", desc:SCRIPT_DESC);
      else if (OSSP == "2" && cputype =="IA64") register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp2:itanium", desc:SCRIPT_DESC);
      else register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe, desc:SCRIPT_DESC);
    }
  }
}

if (OSVER == "6.1"){
  cpe = "cpe:/o:microsoft:windows_7";
  if(OSTYPE == "1"){#Windows 7
    if (x64 != "1"){
      if (OSSP == "0"){
        register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:-:x32", desc:SCRIPT_DESC);
      }
      if (OSSP == "1"){
        register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp1:x32", desc:SCRIPT_DESC);
      }
    }
    if (x64 == "1"){
      if (OSSP == "0"){
        register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:-:x64", desc:SCRIPT_DESC);
      }
      if (OSSP == "1"){
        register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp1:x64", desc:SCRIPT_DESC);
      }
    }
  }
  else if(OSTYPE == "2" || OSTYPE == "3"){#Windows 2008 R2
    cpe = "cpe:/o:microsoft:windows_server_2008:r2";
    if (OSSP == "0"){
      if (OSSKU != "15")register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe, desc:SCRIPT_DESC);
      if (OSSKU != "15")register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:x64", desc:SCRIPT_DESC);
      if (OSSKU == "15")register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:itanium", desc:SCRIPT_DESC);
    }
    if (OSSP == "1"){
      if (OSSKU != "15")register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":sp1:x64", desc:SCRIPT_DESC);
      if (OSSKU == "15")register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":sp1:itanium", desc:SCRIPT_DESC);
    }
  }
  #SMB fallback. Is not so exactly as wmi.
  else if(!OSTYPE){
    if ("Windows Server 2008" >< OSNAME){
      cpe = "cpe:/o:microsoft:windows_server_2008:r2";
      if (OSSP == "0"){
        if (cputype !="IA64")register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe, desc:SCRIPT_DESC);
        else if (cputype =="AMD64" && x64 == "1")register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:x64", desc:SCRIPT_DESC);
        else if (cputype =="IA64")register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:itanium", desc:SCRIPT_DESC);
      }
      if (OSSP == "1"){
        if (cputype =="AMD64" && x64 == "1")register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":sp1:x64", desc:SCRIPT_DESC);
        else if (cputype =="IA64")register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":sp1:itanium", desc:SCRIPT_DESC);
      }
    }
    else if ("Windows 7" >< OSNAME){
      cpe = "cpe:/o:microsoft:windows_7";
      if (x64 != "1"){
        if (OSSP == "0"){
          register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:-:x32", desc:SCRIPT_DESC);
        }
        if (OSSP == "1"){
          register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp1:x32", desc:SCRIPT_DESC);
        }
      }
      if (x64 == "1"){
        if (OSSP == "0"){
          register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:-:x64", desc:SCRIPT_DESC);
        }
        if (OSSP == "1"){
          register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:sp1:x64", desc:SCRIPT_DESC);
        }
      }
    }
  }

}
if (OSVER == "6.2"){
  cpe = "cpe:/o:microsoft:windows_8";
  if(OSTYPE == "1"){#Windows 8
    if (x64 != "1"){
      if (OSSP == "0"){
        register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:-:x86", desc:SCRIPT_DESC);
      }
    }
    if (x64 == "1"){
      if (OSSP == "0"){
        register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:-:x64", desc:SCRIPT_DESC);
      }
    }
  }
  else if(OSTYPE == "2" || OSTYPE == "3"){#Windows 2012
    if (OSSP == "0"){
      register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:"cpe:/o:microsoft:windows_server_2012", desc:SCRIPT_DESC);
    }
    if (OSSP == "1"){
      register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:"cpe:/o:microsoft:windows_server_2012:-:sp1", desc:SCRIPT_DESC);
    }
  }
  #SMB fallback. Is not so exactly as wmi.
  else if(!OSTYPE){
    if ("Windows Server 2012" >< OSNAME){
      if (OSSP == "0"){
        register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:"cpe:/o:microsoft:windows_server_2012", desc:SCRIPT_DESC);
      }
      if (OSSP == "1"){
        register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:"cpe:/o:microsoft:windows_server_2012:-:sp1", desc:SCRIPT_DESC);
      }
    }
    else if ("Windows 8" >< OSNAME){
      cpe = "cpe:/o:microsoft:windows_8";
      if (x64 != "1"){
        if (OSSP == "0"){
          register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:-:x86", desc:SCRIPT_DESC);
        }
      }
      if (x64 == "1"){
        if (OSSP == "0"){
          register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe + ":-:-:x64", desc:SCRIPT_DESC);
        }
      }
    }
  }
}

# TODO: Add Windows 10, Server 2016 and Windows Embedded support via WMI
if (OSVER == "6.3"){
  if(OSTYPE == "1"){#Windows 8.1
    register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:"cpe:/o:microsoft:windows_8.1", desc:SCRIPT_DESC);
  }
  else if(OSTYPE == "2" || OSTYPE == "3"){#Windows 2012 R2
    if (OSSP == "0"){
      register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:"cpe:/o:microsoft:windows_server_2012:r2", desc:SCRIPT_DESC);
    }
    if (OSSP == "1"){
      register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:"cpe:/o:microsoft:windows_server_2012:r2:sp1", desc:SCRIPT_DESC);
    }
  }
  #SMB fallback. Is not so exactly as wmi.
  else if(!OSTYPE){
    if ("Windows Server 2012 R2" >< OSNAME){
      if (OSSP == "0"){
        register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:"cpe:/o:microsoft:windows_server_2012:r2", desc:SCRIPT_DESC);
      }
      if (OSSP == "1"){
        register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:"cpe:/o:microsoft:windows_server_2012:r2:sp1", desc:SCRIPT_DESC);
      }
    }
    else if ("Windows 8.1" >< OSNAME){
      register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:"cpe:/o:microsoft:windows_8.1", desc:SCRIPT_DESC);
    }
    else if ("Windows Server 2016" >< OSNAME){
      register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:"cpe:/o:microsoft:windows_server_2016", desc:SCRIPT_DESC);
    }
    else if ("Windows Server 2019" >< OSNAME){
      register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:"cpe:/o:microsoft:windows_server_2019", desc:SCRIPT_DESC);
    }
    else if ("Windows 10" >< OSNAME){

      cpe = "cpe:/o:microsoft:windows_10";

      if( ver = get_version_from_build( string:build, win_name:"win10" ) )
        cpe += ":" + ver;
      else
        cpe += ":";

      if ("LTSB" >< OSNAME)
        cpe += ":ltsb";
      else if ("LTSC" >< OSNAME)
        cpe += ":ltsc";
      else
        cpe += ":cb";

      if ("Enterprise" >< OSNAME)
        cpe += ":enterprise";
      else if ("Education" >< OSNAME)
        cpe += ":education";
      else if ("Home" >< OSNAME)
        cpe += ":home";
      else if ("Pro" >< OSNAME)
        cpe += ":pro";
      else
        cpe += ":unknown_edition";

      if (x64 == "1")
        cpe += "_x64";

      register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:cpe, desc:SCRIPT_DESC);
    }
    else if ("Windows Embedded 8.1" >< OSNAME){
      register_and_report_os( os:OSNAME, runs_key:"windows", banner_type:BANNER_TYPE, cpe:"cpe:/o:microsoft:windows_embedded_8.1", desc:SCRIPT_DESC );
    }
  }
}

#nb: If updating / adding OS detection here please also update gb_smb_windows_detect.nasl and smb_reg_service_pack.nasl

if(netfrmkeylist){
  cpe = "cpe:/a:microsoft:.net_framework";
  netval = split(netfrmkeylist, sep:"|", keep:0);
  for(i=0; i<max_index(netval); i++){
    val = split(netval[i], sep:";", keep:0);
    if (val[0] == "v1.1.4322"){
      if (!val[2]){
        if (val[1] == "1.1.4322.573")register_host_detail(name:app, value:cpe + ":1.1:gold", desc:SCRIPT_DESC);
      }
      else if (val[2] == "1"){
        register_host_detail(name:app, value:cpe + ":1.1:sp1", desc:SCRIPT_DESC);
        if (val[1] == "1.1.4322.2300")register_host_detail(name:app, value:cpe + ":1.1:sp1:2003", desc:SCRIPT_DESC);
      }
      else if (val[2] == "2"){
        register_host_detail(name:app, value:cpe + ":1.1:sp2", desc:SCRIPT_DESC);
      }
      else if (val[2] == "3"){
        register_host_detail(name:app, value:cpe + ":1.1:sp3", desc:SCRIPT_DESC);
      }
      else register_host_detail(name:app, value:cpe + ":1.1", desc:SCRIPT_DESC);
    }
    else if (val[0] == "v2.0.50727"){
      if (!val[2]){
        if (val[1] == "2.0.50727.42")register_host_detail(name:app, value:cpe + ":2.0:gold", desc:SCRIPT_DESC);
      }
      else if (val[2] == "1"){
        register_host_detail(name:app, value:cpe + ":2.0:sp1", desc:SCRIPT_DESC);
      }
      else if (val[2] == "2"){
        register_host_detail(name:app, value:cpe + ":2.0:sp2", desc:SCRIPT_DESC);
      }
      else register_host_detail(name:app, value:cpe + ":2.0", desc:SCRIPT_DESC);
    }
    else if (val[0] == "v3.0"){
      if (!val[2]){
        if (val[1] == "3.0.4506.30")register_host_detail(name:app, value:cpe + ":3.0:gold", desc:SCRIPT_DESC);
      }
      #else if (val[2] == "1"){
      #}
      #else if (val[2] == "2"){
      #}
      else register_host_detail(name:app, value:cpe + ":3.0", desc:SCRIPT_DESC);
    }
    else if (val[0] == "v3.5"){
      if (!val[2]){
        register_host_detail(name:app, value:cpe + ":3.5", desc:SCRIPT_DESC);
      }
      else if (val[2] == "1"){
        register_host_detail(name:app, value:cpe + ":3.5:sp1", desc:SCRIPT_DESC);
      }
      else register_host_detail(name:app, value:cpe + ":3.5", desc:SCRIPT_DESC);
    }
    #if (!val[0]) register_host_detail(name:app, value:"cpe:/a:microsoft:.net_framework", desc:SCRIPT_DESC);
  }
}

if (NDPv4Client || NDPv4Full){
  if (NDPv4Client){
    if(version_is_greater_equal(version:NDPv4ClientVer, test_version:"4.5.50709")){
      register_host_detail(name:app, value:"cpe:/a:microsoft:.net_framework:4.5", desc:SCRIPT_DESC);
      register_host_detail(name:app, value:"cpe:/a:microsoft:.net_framework:4.5:client" , desc:SCRIPT_DESC);
      nf45 = "1";
    }
    if(version_is_less(version:NDPv4ClientVer, test_version:"4.5.50709")){
      register_host_detail(name:app, value:"cpe:/a:microsoft:.net_framework:4.0", desc:SCRIPT_DESC);
      register_host_detail(name:app, value:"cpe:/a:microsoft:.net_framework:4.0:client" , desc:SCRIPT_DESC);
      nf40 = "1";
    }
  }
  if (NDPv4Full){
    if(version_is_greater_equal(version:NDPv4FullVer, test_version:"4.5.50709")){
      if(!nf45)register_host_detail(name:app, value:"cpe:/a:microsoft:.net_framework:4.5", desc:SCRIPT_DESC);
      register_host_detail(name:app, value:"cpe:/a:microsoft:.net_framework:4.5:full" , desc:SCRIPT_DESC);
    }
    if(version_is_less(version:NDPv4FullVer, test_version:"4.5.50709")){
      if(!nf40)register_host_detail(name:app, value:"cpe:/a:microsoft:.net_framework:4.0", desc:SCRIPT_DESC);
      register_host_detail(name:app, value:"cpe:/a:microsoft:.net_framework:4.0:full" , desc:SCRIPT_DESC);
    }
  }
}

if (OfficeVer){
  cpe = "cpe:/a:microsoft:office";
  if (OfficeFileVer){
    if (OfficeVer == "9.0" )register_host_detail(name:app, value:cpe + ":2000", desc:SCRIPT_DESC);
    else if (version_in_range(version:OfficeFileVer, test_version:"10.0.2627.01", test_version2:"10.0.3520.0"))register_host_detail(name:app, value:cpe + ":xp", desc:SCRIPT_DESC);
    else if (version_in_range(version:OfficeFileVer, test_version:"10.0.3520.0", test_version2:"10.0.4330.0"))register_host_detail(name:app, value:cpe + ":xp:sp1", desc:SCRIPT_DESC);
    else if (version_in_range(version:OfficeFileVer, test_version:"10.0.4330.0", test_version2:"10.0.6626.0"))register_host_detail(name:app, value:cpe + ":xp:sp2", desc:SCRIPT_DESC);
    else if (version_in_range(version:OfficeFileVer, test_version:"10.0.6626.0", test_version2:"11.0.0.0"))register_host_detail(name:app, value:cpe + ":xp:sp3", desc:SCRIPT_DESC);
    else if (version_in_range(version:OfficeFileVer, test_version:"11.0.5614.0", test_version2:"11.0.6361.0"))register_host_detail(name:app, value:cpe + ":2003", desc:SCRIPT_DESC);
    else if (version_in_range(version:OfficeFileVer, test_version:"11.0.6361.0", test_version2:"11.0.7969.0"))register_host_detail(name:app, value:cpe + ":2003:sp1", desc:SCRIPT_DESC);
    else if (version_in_range(version:OfficeFileVer, test_version:"11.0.7969.0", test_version2:"11.0.8173.0"))register_host_detail(name:app, value:cpe + ":2003:sp2", desc:SCRIPT_DESC);
    else if (version_in_range(version:OfficeFileVer, test_version:"11.0.8173.0", test_version2:"12.0.0.0"))register_host_detail(name:app, value:cpe + ":2003:sp3", desc:SCRIPT_DESC);
    else if (version_in_range(version:OfficeFileVer, test_version:"12.0.4518.1014", test_version2:"12.0.6213.1000"))
    {
      NOD = 1;
      for(i=0; i<max_index(instprg); i++){
        val = split(instprg[i], sep:";", keep:0);
        if ("Microsoft Office Basic" >< val[0])register_host_detail(name:app, value:cpe + ":2007::basic", desc:SCRIPT_DESC);
        else if ("Microsoft Office Enterprise" >< val[0])register_host_detail(name:app, value:cpe + ":2007::enterprise", desc:SCRIPT_DESC);
        else if ("Microsoft Office Home" >< val[0])register_host_detail(name:app, value:cpe + ":2007::home_and_student", desc:SCRIPT_DESC);
        else if ("Microsoft Office Mobile" >< val[0])register_host_detail(name:app, value:cpe + ":2007::mobile", desc:SCRIPT_DESC);
        else if ("Microsoft Office Professional Plus" >< val[0])register_host_detail(name:app, value:cpe + ":2007::professional_plus", desc:SCRIPT_DESC);
        else if ("Microsoft Office Professional 2007">< val[0])register_host_detail(name:app, value:cpe + ":2007::professional", desc:SCRIPT_DESC);
        else if ("Microsoft Office Small" >< val[0])register_host_detail(name:app, value:cpe + ":2007::small_business", desc:SCRIPT_DESC);
        else if ("Microsoft Office Ultimate" >< val[0])register_host_detail(name:app, value:cpe + ":2007::ultimate", desc:SCRIPT_DESC);
        else if ("Microsoft Office Standard" >< val[0])register_host_detail(name:app, value:cpe + ":2007::standard", desc:SCRIPT_DESC);
        else NOD++;
      }
      if ( NOD == i)register_host_detail(name:app, value:cpe + ":2007", desc:SCRIPT_DESC);
    }
    else if (version_in_range(version:OfficeFileVer, test_version:"12.0.6213.1000", test_version2:"12.0.6425.1000"))
    {
      NOD = 1;
      for(i=0; i<max_index(instprg); i++){
        val = split(instprg[i], sep:";", keep:0);
        if ("Microsoft Office Professional 2007">< val[0])register_host_detail(name:app, value:cpe + ":2007:sp1:professional", desc:SCRIPT_DESC);
        else NOD++;
      }
      if ( NOD == i) register_host_detail(name:app, value:cpe + ":2007:sp1", desc:SCRIPT_DESC);
    }
    else if (version_in_range(version:OfficeFileVer, test_version:"12.0.6425.1000", test_version2:"13.0.0.0"))
    {
      NOD = 1;
      for(i=0; i<max_index(instprg); i++){
        val = split(instprg[i], sep:";", keep:0);
        if ("Microsoft Office Professional 2007">< val[0])register_host_detail(name:app, value:cpe + ":2007:sp2:professional", desc:SCRIPT_DESC);
        else NOD++;
      }
      if ( NOD == i) register_host_detail(name:app, value:cpe + ":2007:sp2", desc:SCRIPT_DESC);
    }
    else if (version_in_range(version:OfficeFileVer, test_version:"14.0.4760.1000", test_version2:"14.0.6023.1000"))register_host_detail(name:app, value:cpe + ":2010", desc:SCRIPT_DESC);
    else if (version_in_range(version:OfficeFileVer, test_version:"14.0.6023.1000", test_version2:"15.0.0.0"))register_host_detail(name:app, value:cpe + ":2010:sp1", desc:SCRIPT_DESC);
    else if (version_in_range(version:OfficeFileVer, test_version:"15.0.4420.1017", test_version2:"16.0.0.0"))register_host_detail(name:app, value:cpe + ":2013", desc:SCRIPT_DESC);
    else register_host_detail(name:app, value:cpe + " debug:" + OfficeVer + " debug:" + OfficeFileVer, desc:SCRIPT_DESC);
  }
  else  {
    if (OfficeVer == "9.0" )register_host_detail(name:app, value:cpe + ":2000", desc:SCRIPT_DESC);
    else if (OfficeVer == "10.0" )register_host_detail(name:app, value:cpe + ":xp", desc:SCRIPT_DESC);
    else if (OfficeVer == "11.0" )register_host_detail(name:app, value:cpe + ":2003", desc:SCRIPT_DESC);
    else if (OfficeVer == "12.0" )
    {
      for(i=0; i<max_index(instprg); i++){
        val = split(instprg[i], sep:";", keep:0);
        if ("Microsoft Office Basic" >< val[0])register_host_detail(name:app, value:cpe + ":2007::basic", desc:SCRIPT_DESC);
        else if ("Microsoft Office Enterprise" >< val[0])register_host_detail(name:app, value:cpe + ":2007::enterprise", desc:SCRIPT_DESC);
        else if ("Microsoft Office Home" >< val[0])register_host_detail(name:app, value:cpe + ":2007::home_and_student", desc:SCRIPT_DESC);
        else if ("Microsoft Office Mobile" >< val[0])register_host_detail(name:app, value:cpe + ":2007::mobile", desc:SCRIPT_DESC);
        else if ("Microsoft Office Professional Plus" >< val[0])register_host_detail(name:app, value:cpe + ":2007::professional_plus", desc:SCRIPT_DESC);
        else if ("Microsoft Office Professional 2007">< val[0])
        {
          if (version_in_range(version:OfficeFileVer, test_version:"12.0.4518.1014", test_version2:"12.0.6213.1000"))register_host_detail(name:app, value:cpe + ":2007::professional", desc:SCRIPT_DESC);
          else if (version_in_range(version:OfficeFileVer, test_version:"12.0.6213.1000", test_version2:"12.0.6425.1000"))register_host_detail(name:app, value:cpe + ":2007:sp1:professional", desc:SCRIPT_DESC);
          else if (version_in_range(version:OfficeFileVer, test_version:"12.0.6425.1000", test_version2:"13.0.0.0"))register_host_detail(name:app, value:cpe + ":2007:sp2:professional", desc:SCRIPT_DESC);
        }
        else if ("Microsoft Office Small" >< val[0])register_host_detail(name:app, value:cpe + ":2007::small_business", desc:SCRIPT_DESC);
        else if ("Microsoft Office Ultimate" >< val[0])register_host_detail(name:app, value:cpe + ":2007::ultimate", desc:SCRIPT_DESC);
        else if ("Microsoft Office Standard" >< val[0])register_host_detail(name:app, value:cpe + ":2007::standard", desc:SCRIPT_DESC);
        else register_host_detail(name:app, value:cpe + ":2007", desc:SCRIPT_DESC);
      }
    }
    else if (OfficeVer == "14.0" )
    {
      register_host_detail(name:app, value:cpe + ":2010", desc:SCRIPT_DESC);
    }
    else if (OfficeVer == "15.0" )
    {
      register_host_detail(name:app, value:cpe + ":2013", desc:SCRIPT_DESC);
    }

    else register_host_detail(name:app, value:cpe + " debug:" + OfficeVer + " debug:" + OfficeFileVer, desc:SCRIPT_DESC);
  }
}
if (AccessVer){
  cpe = "cpe:/a:microsoft:access";
  if (version_in_range(version:AccessVer, test_version:"9.0.2720", test_version2:"9.0.3821"))register_host_detail(name:app, value:cpe + ":2000", desc:SCRIPT_DESC);
  else if (version_in_range(version:AccessVer, test_version:"9.0.3821", test_version2:"9.0.440"))register_host_detail(name:app, value:cpe + ":2000:sr1", desc:SCRIPT_DESC);
  else if (version_in_range(version:AccessVer, test_version:"9.0.440", test_version2:"9.0.6926"))register_host_detail(name:app, value:cpe + ":2000:sp2", desc:SCRIPT_DESC);
  else if (version_in_range(version:AccessVer, test_version:"9.0.6926", test_version2:"10.0.0"))register_host_detail(name:app, value:cpe + ":2000:sp3", desc:SCRIPT_DESC);
  else if (version_in_range(version:AccessVer, test_version:"10.0.2627.1", test_version2:"10.0.3409.0"))register_host_detail(name:app, value:cpe + ":2002", desc:SCRIPT_DESC);
  else if (version_in_range(version:AccessVer, test_version:"10.0.3409.0", test_version2:"10.0.4302.0"))register_host_detail(name:app, value:cpe + ":2002:sp1", desc:SCRIPT_DESC);
  else if (version_in_range(version:AccessVer, test_version:"10.0.4302.0", test_version2:"10.0.3409.0"))register_host_detail(name:app, value:cpe + ":2002:sp2", desc:SCRIPT_DESC);
  else if (version_in_range(version:AccessVer, test_version:"10.0.6501.0", test_version2:"11.0.0.0"))register_host_detail(name:app, value:cpe + ":2002:sp3", desc:SCRIPT_DESC);
  else if (version_in_range(version:AccessVer, test_version:"11.0.5614.0", test_version2:"11.0.6355.0"))register_host_detail(name:app, value:cpe + ":2003", desc:SCRIPT_DESC);
  else if (version_in_range(version:AccessVer, test_version:"11.0.6355.0", test_version2:"11.0.7969.0"))register_host_detail(name:app, value:cpe + ":2003:sp1", desc:SCRIPT_DESC);
  else if (version_in_range(version:AccessVer, test_version:"11.0.7969.0", test_version2:"11.0.8173.0"))register_host_detail(name:app, value:cpe + ":2003:sp2", desc:SCRIPT_DESC);
  else if (version_in_range(version:AccessVer, test_version:"11.0.8173.0", test_version2:"12.0.0.0"))register_host_detail(name:app, value:cpe + ":2003:sp3", desc:SCRIPT_DESC);
  else if (version_in_range(version:AccessVer, test_version:"12.0.4518.1014", test_version2:"12.0.6211.1000"))register_host_detail(name:app, value:cpe + ":2007", desc:SCRIPT_DESC);
  else if (version_in_range(version:AccessVer, test_version:"12.0.6211.1000", test_version2:"12.0.6423.1000"))register_host_detail(name:app, value:cpe + ":2007:sp1", desc:SCRIPT_DESC);
  else if (version_in_range(version:AccessVer, test_version:"12.0.6423.1000", test_version2:"13.0.0.0"))register_host_detail(name:app, value:cpe + ":2007:sp2", desc:SCRIPT_DESC);
  else if (version_in_range(version:AccessVer, test_version:"14.0.4750.1000", test_version2:"14.0.6024.1000"))register_host_detail(name:app, value:cpe + ":2010", desc:SCRIPT_DESC);
  else if (version_in_range(version:AccessVer, test_version:"14.0.6024.1000", test_version2:"15.0.0.0"))register_host_detail(name:app, value:cpe + ":2010:sp1", desc:SCRIPT_DESC);
  else if (version_in_range(version:AccessVer, test_version:"15.0.4420.1017", test_version2:"16.0.0.0"))register_host_detail(name:app, value:cpe + ":2013", desc:SCRIPT_DESC);
  else register_host_detail(name:app, value:"cpe:/a:microsoft:access", desc:SCRIPT_DESC);
}
if (ExcelVer){
  cpe = "cpe:/a:microsoft:excel";
  if (ExcelVer == "9.0.2720")register_host_detail(name:app, value:cpe + ":2000:gold", desc:SCRIPT_DESC);
  else if (version_in_range(version:ExcelVer, test_version:"9.0.2720", test_version2:"9.0.3821"))register_host_detail(name:app, value:cpe + ":2000", desc:SCRIPT_DESC);
  else if (version_in_range(version:ExcelVer, test_version:"9.0.3821", test_version2:"9.0.4402"))register_host_detail(name:app, value:cpe + ":2000:sr1", desc:SCRIPT_DESC);
  else if (version_in_range(version:ExcelVer, test_version:"9.0.4402", test_version2:"9.0.6926"))register_host_detail(name:app, value:cpe + ":2000:sp2", desc:SCRIPT_DESC);
  else if (version_in_range(version:ExcelVer, test_version:"9.0.6926", test_version2:"10.0.0"))register_host_detail(name:app, value:cpe + ":2000:sp3", desc:SCRIPT_DESC);
  else if (ExcelVer == "10.0.2614.0")register_host_detail(name:app, value:cpe + ":2002:gold", desc:SCRIPT_DESC);
  else if (version_in_range(version:ExcelVer, test_version:"10.0.2614.0", test_version2:"10.0.3506.0"))register_host_detail(name:app, value:cpe + ":2002", desc:SCRIPT_DESC);
  else if (version_in_range(version:ExcelVer, test_version:"10.0.3506.0", test_version2:"10.0.4302.0"))register_host_detail(name:app, value:cpe + ":2002:sp1", desc:SCRIPT_DESC);
  else if (version_in_range(version:ExcelVer, test_version:"10.0.4302.0", test_version2:"10.0.3409.0"))register_host_detail(name:app, value:cpe + ":2002:sp2", desc:SCRIPT_DESC);
  else if (version_in_range(version:ExcelVer, test_version:"10.0.6501.0", test_version2:"11.0.0.0"))register_host_detail(name:app, value:cpe + ":2002:sp3", desc:SCRIPT_DESC);
  else if (ExcelVer == "11.0.5612.0")register_host_detail(name:app, value:cpe + ":2003:gold", desc:SCRIPT_DESC);
  else if (version_in_range(version:ExcelVer, test_version:"11.0.5612.0", test_version2:"11.0.6355.0"))register_host_detail(name:app, value:cpe + ":2003", desc:SCRIPT_DESC);
  else if (version_in_range(version:ExcelVer, test_version:"11.0.6355.0", test_version2:"11.0.7969.0"))register_host_detail(name:app, value:cpe + ":2003:sp1", desc:SCRIPT_DESC);
  else if (version_in_range(version:ExcelVer, test_version:"11.0.7969.0", test_version2:"11.0.8173.0"))register_host_detail(name:app, value:cpe + ":2003:sp2", desc:SCRIPT_DESC);
  else if (version_in_range(version:ExcelVer, test_version:"11.0.8173.0", test_version2:"12.0.0.0"))register_host_detail(name:app, value:cpe + ":2003:sp3", desc:SCRIPT_DESC);
  else if (version_in_range(version:ExcelVer, test_version:"12.0.4518.1014", test_version2:"12.0.6214.1000"))register_host_detail(name:app, value:cpe + ":2007", desc:SCRIPT_DESC);
  else if (version_in_range(version:ExcelVer, test_version:"12.0.6214.1000", test_version2:"12.0.6425.1000"))register_host_detail(name:app, value:cpe + ":2007:sp1", desc:SCRIPT_DESC);
  else if (version_in_range(version:ExcelVer, test_version:"12.0.6425.1000", test_version2:"13.0.0.0"))register_host_detail(name:app, value:cpe + ":2007:sp2", desc:SCRIPT_DESC);
  else if (version_in_range(version:ExcelVer, test_version:"14.0.4756.1000", test_version2:"14.0.6024.1000"))register_host_detail(name:app, value:cpe + ":2010", desc:SCRIPT_DESC);
  else if (version_in_range(version:ExcelVer, test_version:"14.0.6024.1000", test_version2:"15.0.0.0"))register_host_detail(name:app, value:cpe + ":2010:sp1", desc:SCRIPT_DESC);
  else if (version_in_range(version:ExcelVer, test_version:"15.0.4420.1017", test_version2:"16.0.0.0"))register_host_detail(name:app, value:cpe + ":2013", desc:SCRIPT_DESC);
  else register_host_detail(name:app, value:"cpe:/a:microsoft:excel", desc:SCRIPT_DESC);
}
if (InfoPathVer){
  cpe = "cpe:/a:microsoft:infopath";
  if (version_in_range(version:InfoPathVer, test_version:"11.0.5531.0", test_version2:"12.0.0.0"))register_host_detail(name:app, value:cpe + ":2003", desc:SCRIPT_DESC);
  else if (version_in_range(version:InfoPathVer, test_version:"12.0.4518.1014", test_version2:"13.0.0.0"))register_host_detail(name:app, value:cpe + ":2007", desc:SCRIPT_DESC);
  else if (version_in_range(version:InfoPathVer, test_version:"14.0.4763.1000", test_version2:"14.0.6009.1000"))register_host_detail(name:app, value:cpe + ":2010", desc:SCRIPT_DESC);
  else if (version_in_range(version:InfoPathVer, test_version:"14.0.6009.1000", test_version2:"15.0.0.0"))register_host_detail(name:app, value:cpe + ":2010:sp1", desc:SCRIPT_DESC);
  else if (version_in_range(version:InfoPathVer, test_version:"15.0.4420.1017", test_version2:"16.0.0.0"))register_host_detail(name:app, value:cpe + ":2013", desc:SCRIPT_DESC);
  else register_host_detail(name:app, value:"cpe:/a:microsoft:infopath", desc:SCRIPT_DESC);
}
if (OneNoteVer){
  cpe = "cpe:/a:microsoft:onenote";
  if (version_in_range(version:OneNoteVer, test_version:"11.0.5614.0", test_version2:"12.0.0.0"))register_host_detail(name:app, value:cpe + ":2003", desc:SCRIPT_DESC);
  else if (version_in_range(version:OneNoteVer, test_version:"12.0.4518.1014", test_version2:"13.0.0.0"))register_host_detail(name:app, value:cpe + ":2007", desc:SCRIPT_DESC);
  else if (version_in_range(version:OneNoteVer, test_version:"14.0.4763.1000", test_version2:"14.0.6022.1000"))register_host_detail(name:app, value:cpe + ":2010", desc:SCRIPT_DESC);
  else if (version_in_range(version:OneNoteVer, test_version:"14.0.6022.1000", test_version2:"15.0.0.0"))register_host_detail(name:app, value:cpe + ":2010:sp1", desc:SCRIPT_DESC);

  else if (version_in_range(version:OneNoteVer, test_version:"15.0.4420.1017", test_version2:"16.0.0.0"))register_host_detail(name:app, value:cpe + ":2013", desc:SCRIPT_DESC);
  else register_host_detail(name:app, value:"cpe:/a:microsoft:onenote", desc:SCRIPT_DESC);
}

if (OutlookVer){
  cpe = "cpe:/a:microsoft:outlook";
  if (version_in_range(version:OutlookVer, test_version:"9.0.0.2711", test_version2:"9.0.0.3821"))register_host_detail(name:app, value:cpe + ":2000", desc:SCRIPT_DESC);
  else if (version_in_range(version:OutlookVer, test_version:"9.0.0.3821", test_version2:"9.0.0.4527"))register_host_detail(name:app, value:cpe + ":2000:sr1", desc:SCRIPT_DESC);
  else if (version_in_range(version:OutlookVer, test_version:"9.0.0.4527", test_version2:"9.0.0.6627"))register_host_detail(name:app, value:cpe + ":2000:sp2", desc:SCRIPT_DESC);
  else if (version_in_range(version:OutlookVer, test_version:"9.0.0.6627", test_version2:"10.0.0"))register_host_detail(name:app, value:cpe + ":2000:sp3", desc:SCRIPT_DESC);
  else if (version_in_range(version:OutlookVer, test_version:"10.0.2627.1", test_version2:"11.0.0.0"))register_host_detail(name:app, value:cpe + ":xp", desc:SCRIPT_DESC);
  else if (version_in_range(version:OutlookVer, test_version:"10.0.2627.1", test_version2:"10.0.3416.0"))register_host_detail(name:app, value:cpe + ":2002", desc:SCRIPT_DESC);
  else if (version_in_range(version:OutlookVer, test_version:"10.0.3416.0", test_version2:"10.0.4024.0"))register_host_detail(name:app, value:cpe + ":2002:sp1", desc:SCRIPT_DESC);
  else if (version_in_range(version:OutlookVer, test_version:"10.0.4024.0", test_version2:"10.0.6626.0"))register_host_detail(name:app, value:cpe + ":2002:sp2", desc:SCRIPT_DESC);
  else if (version_in_range(version:OutlookVer, test_version:"10.0.6626.0", test_version2:"11.0.0.0"))register_host_detail(name:app, value:cpe + ":2002:sp3", desc:SCRIPT_DESC);
  else if (version_in_range(version:OutlookVer, test_version:"11.0.5510.0", test_version2:"11.0.6353.0"))register_host_detail(name:app, value:cpe + ":2003", desc:SCRIPT_DESC);
  else if (version_in_range(version:OutlookVer, test_version:"11.0.6353.0", test_version2:"11.0.7969.0"))register_host_detail(name:app, value:cpe + ":2003:sp1", desc:SCRIPT_DESC);
  else if (version_in_range(version:OutlookVer, test_version:"11.0.7969.0", test_version2:"11.0.8173.0"))register_host_detail(name:app, value:cpe + ":2003:sp2", desc:SCRIPT_DESC);
  else if (version_in_range(version:OutlookVer, test_version:"11.0.8173.0", test_version2:"12.0.0.0"))register_host_detail(name:app, value:cpe + ":2003:sp3", desc:SCRIPT_DESC);
  else if (version_in_range(version:OutlookVer, test_version:"12.0.4518.1014", test_version2:"12.0.6212.1000"))register_host_detail(name:app, value:cpe + ":2007", desc:SCRIPT_DESC);
  else if (version_in_range(version:OutlookVer, test_version:"12.0.6212.1000", test_version2:"12.0.6423.1000"))register_host_detail(name:app, value:cpe + ":2007:sp1", desc:SCRIPT_DESC);
  else if (version_in_range(version:OutlookVer, test_version:"12.0.6423.1000", test_version2:"13.0.0.0"))register_host_detail(name:app, value:cpe + ":2007:sp2", desc:SCRIPT_DESC);
  else if (version_in_range(version:OutlookVer, test_version:"14.0.4760.1000", test_version2:"14.0.6025.1000"))register_host_detail(name:app, value:cpe + ":2010", desc:SCRIPT_DESC);
  else if (version_in_range(version:OutlookVer, test_version:"14.0.6025.1000", test_version2:"15.0.0.0"))register_host_detail(name:app, value:cpe + ":2010:sp1", desc:SCRIPT_DESC);
  else if (version_in_range(version:OutlookVer, test_version:"15.0.4420.1017", test_version2:"16.0.0.0"))register_host_detail(name:app, value:cpe + ":2013", desc:SCRIPT_DESC);
  else register_host_detail(name:app, value:"cpe:/a:microsoft:outlook", desc:SCRIPT_DESC);
}

if (PowerPointVer){
  cpe = "cpe:/a:microsoft:powerpoint";
  if (version_in_range(version:PowerPointVer, test_version:"9.0.2716", test_version2:"9.0.3821"))register_host_detail(name:app, value:cpe + ":2000", desc:SCRIPT_DESC);
  else if (version_in_range(version:PowerPointVer, test_version:"9.0.3821", test_version2:"9.0.4527"))register_host_detail(name:app, value:cpe + ":2000:sr1", desc:SCRIPT_DESC);
  else if (version_in_range(version:PowerPointVer, test_version:"9.0.4527", test_version2:"9.0.6620"))register_host_detail(name:app, value:cpe + ":2000:sp2", desc:SCRIPT_DESC);
  else if (version_in_range(version:PowerPointVer, test_version:"9.0.6620", test_version2:"10.0.0"))register_host_detail(name:app, value:cpe + ":2000:sp3", desc:SCRIPT_DESC);
  else if (version_in_range(version:PowerPointVer, test_version:"10.0.2623.0", test_version2:"10.0.3506.0"))register_host_detail(name:app, value:cpe + ":2002", desc:SCRIPT_DESC);
  else if (version_in_range(version:PowerPointVer, test_version:"10.0.3506.0", test_version2:"10.0.4205.0"))register_host_detail(name:app, value:cpe + ":2002:sp1", desc:SCRIPT_DESC);
  else if (version_in_range(version:PowerPointVer, test_version:"10.0.4205.0", test_version2:"10.0.6501.0"))register_host_detail(name:app, value:cpe + ":2002:sp2", desc:SCRIPT_DESC);
  else if (version_in_range(version:PowerPointVer, test_version:"10.0.6501.0", test_version2:"11.0.0.0"))register_host_detail(name:app, value:cpe + ":2002:sp3", desc:SCRIPT_DESC);
  else if (version_in_range(version:PowerPointVer, test_version:"11.0.5529.0", test_version2:"11.0.6361.0"))register_host_detail(name:app, value:cpe + ":2003", desc:SCRIPT_DESC);
  else if (version_in_range(version:PowerPointVer, test_version:"11.0.6361.0", test_version2:"11.0.7969.0"))register_host_detail(name:app, value:cpe + ":2003:sp1", desc:SCRIPT_DESC);
  else if (version_in_range(version:PowerPointVer, test_version:"11.0.7969.0", test_version2:"11.0.8173.0"))register_host_detail(name:app, value:cpe + ":2003:sp2", desc:SCRIPT_DESC);
  else if (version_in_range(version:PowerPointVer, test_version:"11.0.8173.0", test_version2:"12.0.0.0"))register_host_detail(name:app, value:cpe + ":2003:sp3", desc:SCRIPT_DESC);
  else if (version_in_range(version:PowerPointVer, test_version:"12.0.4518.1014", test_version2:"12.0.6211.1000"))register_host_detail(name:app, value:cpe + ":2007", desc:SCRIPT_DESC);
  else if (version_in_range(version:PowerPointVer, test_version:"12.0.6211.1000", test_version2:"12.0.6425.1000"))register_host_detail(name:app, value:cpe + ":2007:sp1", desc:SCRIPT_DESC);
  else if (version_in_range(version:PowerPointVer, test_version:"12.0.6425.1000", test_version2:"13.0.0.0"))register_host_detail(name:app, value:cpe + ":2007:sp2", desc:SCRIPT_DESC);
  else if (version_in_range(version:PowerPointVer, test_version:"14.0.4754.1000", test_version2:"14.0.6026.1000"))register_host_detail(name:app, value:cpe + ":2010", desc:SCRIPT_DESC);
  else if (version_in_range(version:PowerPointVer, test_version:"14.0.6026.1000", test_version2:"15.0.0.0"))register_host_detail(name:app, value:cpe + ":2010:sp1", desc:SCRIPT_DESC);
  else if (version_in_range(version:PowerPointVer, test_version:"15.0.4420.1017", test_version2:"16.0.0.0"))register_host_detail(name:app, value:cpe + ":2013", desc:SCRIPT_DESC);
  else register_host_detail(name:app, value:"cpe:/a:microsoft:powerpoint", desc:SCRIPT_DESC);
}

if (ProjectVer){
  cpe = "cpe:/a:microsoft:project";
  if (version_in_range(version:ProjectVer, test_version:"9.0.0", test_version2:"10.0.0"))register_host_detail(name:app, value:cpe + ":2000", desc:SCRIPT_DESC);
  else if (version_in_range(version:ProjectVer, test_version:"10.0.2915.0", test_version2:"10.0.8326.0"))register_host_detail(name:app, value:cpe + ":2002", desc:SCRIPT_DESC);
  else if (version_in_range(version:ProjectVer, test_version:"10.0.8326.0", test_version2:"11.0.0.0"))register_host_detail(name:app, value:cpe + ":2002:sp1", desc:SCRIPT_DESC);
  else if (version_in_range(version:ProjectVer, test_version:"11.0.5614.0", test_version2:"11.0.6707.0"))register_host_detail(name:app, value:cpe + ":2003", desc:SCRIPT_DESC);
  else if (version_in_range(version:ProjectVer, test_version:"11.0.6707.0", test_version2:"11.0.7969.0"))register_host_detail(name:app, value:cpe + ":2003:sp1", desc:SCRIPT_DESC);
  else if (version_in_range(version:ProjectVer, test_version:"11.0.7969.0", test_version2:"11.0.8173.0"))register_host_detail(name:app, value:cpe + ":2003:sp2", desc:SCRIPT_DESC);
  else if (version_in_range(version:ProjectVer, test_version:"11.0.8173.0", test_version2:"12.0.0.0"))register_host_detail(name:app, value:cpe + ":2003:sp3", desc:SCRIPT_DESC);
  else if (version_in_range(version:ProjectVer, test_version:"12.0.4518.1014", test_version2:"12.0.6211.1000"))register_host_detail(name:app, value:cpe + ":2007", desc:SCRIPT_DESC);
  else if (version_in_range(version:ProjectVer, test_version:"12.0.6211.1000", test_version2:"12.0.6423.1000"))register_host_detail(name:app, value:cpe + ":2007:sp1", desc:SCRIPT_DESC);
  else if (version_in_range(version:ProjectVer, test_version:"12.0.6423.1000", test_version2:"13.0.0.0"))register_host_detail(name:app, value:cpe + ":2007:sp2", desc:SCRIPT_DESC);
  else if (version_in_range(version:ProjectVer, test_version:"14.0.4751.1000", test_version2:"14.0.6023.1000"))register_host_detail(name:app, value:cpe + ":2010", desc:SCRIPT_DESC);
  else if (version_in_range(version:ProjectVer, test_version:"14.0.6023.1000", test_version2:"15.0.0.0"))register_host_detail(name:app, value:cpe + ":2010:sp1", desc:SCRIPT_DESC);
  else if (version_in_range(version:ProjectVer, test_version:"15.0.4420.1017", test_version2:"16.0.0.0"))register_host_detail(name:app, value:cpe + ":2013", desc:SCRIPT_DESC);
  else register_host_detail(name:app, value:"cpe:/a:microsoft:project", desc:SCRIPT_DESC);
}

if (PublisherVer){
  cpe = "cpe:/a:microsoft:publisher";
  if (version_is_less(version:PublisherVer, test_version:"10.0.0"))register_host_detail(name:app, value:cpe + ":2000", desc:SCRIPT_DESC);
  else if (version_in_range(version:PublisherVer, test_version:"10.0.2621.0", test_version2:"10.0.3402.0"))register_host_detail(name:app, value:cpe + ":2002", desc:SCRIPT_DESC);
  else if (version_in_range(version:PublisherVer, test_version:"10.0.3402.0", test_version2:"10.0.4016.0"))register_host_detail(name:app, value:cpe + ":2002:sp1", desc:SCRIPT_DESC);
  else if (version_in_range(version:PublisherVer, test_version:"10.0.4016.0", test_version2:"10.0.6308.0"))register_host_detail(name:app, value:cpe + ":2002:sp2", desc:SCRIPT_DESC);
  else if (version_in_range(version:PublisherVer, test_version:"10.0.6308.0", test_version2:"11.0.0.0"))register_host_detail(name:app, value:cpe + ":2002:sp3", desc:SCRIPT_DESC);
  else if (version_in_range(version:PublisherVer, test_version:"11.0.5525.0", test_version2:"11.0.6255.0"))register_host_detail(name:app, value:cpe + ":2003", desc:SCRIPT_DESC);
  else if (version_in_range(version:PublisherVer, test_version:"11.0.6255.0", test_version2:"11.0.7969.0"))register_host_detail(name:app, value:cpe + ":2003:sp1", desc:SCRIPT_DESC);
  else if (version_in_range(version:PublisherVer, test_version:"11.0.7969.0", test_version2:"11.0.8173.0"))register_host_detail(name:app, value:cpe + ":2003:sp2", desc:SCRIPT_DESC);
  else if (version_in_range(version:PublisherVer, test_version:"11.0.8173.0", test_version2:"12.0.0.0"))register_host_detail(name:app, value:cpe + ":2003:sp3", desc:SCRIPT_DESC);
  else if (version_in_range(version:PublisherVer, test_version:"12.0.4518.1014", test_version2:"12.0.6211.1000"))register_host_detail(name:app, value:cpe + ":2007", desc:SCRIPT_DESC);
  else if (version_in_range(version:PublisherVer, test_version:"12.0.6211.1000", test_version2:"12.0.6423.1000"))register_host_detail(name:app, value:cpe + ":2007:sp1", desc:SCRIPT_DESC);
  else if (version_in_range(version:PublisherVer, test_version:"12.0.6423.1000", test_version2:"13.0.0.0"))register_host_detail(name:app, value:cpe + ":2007:sp2", desc:SCRIPT_DESC);
  else if (version_in_range(version:PublisherVer, test_version:"14.0.4750.1000", test_version2:"14.0.6026.1000"))register_host_detail(name:app, value:cpe + ":2010", desc:SCRIPT_DESC);
  else if (version_in_range(version:PublisherVer, test_version:"14.0.6026.1000", test_version2:"15.0.0.0"))register_host_detail(name:app, value:cpe + ":2010:sp1", desc:SCRIPT_DESC);
  else if (version_in_range(version:PublisherVer, test_version:"15.0.4420.1017", test_version2:"16.0.0.0"))register_host_detail(name:app, value:cpe + ":2013", desc:SCRIPT_DESC);
  else register_host_detail(name:app, value:"cpe:/a:microsoft:publisher", desc:SCRIPT_DESC);
}

if (SharePoint_DesignerVer){
  cpe = "cpe:/a:microsoft:sharepoint_designer";
  if (version_in_range(version:SharePoint_DesignerVer, test_version:"12.0.4518.1014", test_version2:"12.0.6211.1000"))register_host_detail(name:app, value:cpe + ":2007", desc:SCRIPT_DESC);
  else if (version_in_range(version:SharePoint_DesignerVer, test_version:"12.0.6211.1000", test_version2:"12.0.6423.1000"))register_host_detail(name:app, value:cpe + ":2007:sp1", desc:SCRIPT_DESC);
  else if (version_in_range(version:SharePoint_DesignerVer, test_version:"12.0.6423.1000", test_version2:"13.0.0.0"))register_host_detail(name:app, value:cpe + ":2007:sp2", desc:SCRIPT_DESC);
  else if (version_in_range(version:SharePoint_DesignerVer, test_version:"14.0.4750.1000", test_version2:"15.0.0.0"))register_host_detail(name:app, value:cpe + ":2010", desc:SCRIPT_DESC);
  else register_host_detail(name:app, value:"cpe:/a:microsoft:sharepoint_designer", desc:SCRIPT_DESC);
}

#SharePoint_Workspace(Microsoft SkyDrive Pro)

if (WordVer){
  cpe = "cpe:/a:microsoft:word";
  if (version_in_range(version:WordVer, test_version:"9.0.2720", test_version2:"9.0.3821"))register_host_detail(name:app, value:cpe + ":2000", desc:SCRIPT_DESC);
  else if (version_in_range(version:WordVer, test_version:"9.0.3821", test_version2:"9.0.4402"))register_host_detail(name:app, value:cpe + ":2000:sr1", desc:SCRIPT_DESC);
  else if (version_in_range(version:WordVer, test_version:"9.0.4402", test_version2:"9.0.6926"))register_host_detail(name:app, value:cpe + ":2000:sp2", desc:SCRIPT_DESC);
  else if (version_in_range(version:WordVer, test_version:"9.0.6926", test_version2:"10.0.0"))register_host_detail(name:app, value:cpe + ":2000:sp3", desc:SCRIPT_DESC);
  else if (version_in_range(version:WordVer, test_version:"10.0.2627.0", test_version2:"10.0.3416.0"))register_host_detail(name:app, value:cpe + ":2002", desc:SCRIPT_DESC);
  else if (version_in_range(version:WordVer, test_version:"10.0.3416.0", test_version2:"10.0.4219.0"))register_host_detail(name:app, value:cpe + ":2002:sp1", desc:SCRIPT_DESC);
  else if (version_in_range(version:WordVer, test_version:"10.0.4219.0", test_version2:"10.0.6612.0"))register_host_detail(name:app, value:cpe + ":2002:sp2", desc:SCRIPT_DESC);
  else if (version_in_range(version:WordVer, test_version:"10.0.6612.0", test_version2:"11.0.0.0"))register_host_detail(name:app, value:cpe + ":2002:sp3", desc:SCRIPT_DESC);
  else if (version_in_range(version:WordVer, test_version:"11.0.5604.0", test_version2:"11.0.6359.0"))register_host_detail(name:app, value:cpe + ":2003", desc:SCRIPT_DESC);
  else if (version_in_range(version:WordVer, test_version:"11.0.6359.0", test_version2:"11.0.7969.0"))register_host_detail(name:app, value:cpe + ":2003:sp1", desc:SCRIPT_DESC);
  else if (version_in_range(version:WordVer, test_version:"11.0.7969.0", test_version2:"11.0.8173.0"))register_host_detail(name:app, value:cpe + ":2003:sp2", desc:SCRIPT_DESC);
  else if (version_in_range(version:WordVer, test_version:"11.0.8173.0", test_version2:"12.0.0.0"))register_host_detail(name:app, value:cpe + ":2003:sp3", desc:SCRIPT_DESC);
  else if (version_in_range(version:WordVer, test_version:"12.0.4518.1014", test_version2:"12.0.6211.1000"))register_host_detail(name:app, value:cpe + ":2007", desc:SCRIPT_DESC);
  else if (version_in_range(version:WordVer, test_version:"12.0.6211.1000", test_version2:"12.0.6425.1000"))register_host_detail(name:app, value:cpe + ":2007:sp1", desc:SCRIPT_DESC);
  else if (version_in_range(version:WordVer, test_version:"12.0.6425.1000", test_version2:"13.0.0.0"))register_host_detail(name:app, value:cpe + ":2007:sp2", desc:SCRIPT_DESC);
  else if (version_in_range(version:WordVer, test_version:"14.0.4762.1000", test_version2:"14.0.6024.1000"))register_host_detail(name:app, value:cpe + ":2010", desc:SCRIPT_DESC);
  else if (version_in_range(version:WordVer, test_version:"14.0.6024.1000", test_version2:"15.0.0.0"))register_host_detail(name:app, value:cpe + ":2010:sp1", desc:SCRIPT_DESC);
  else if (version_in_range(version:WordVer, test_version:"15.0.4420.1017", test_version2:"16.0.0.0"))register_host_detail(name:app, value:cpe + ":2013", desc:SCRIPT_DESC);
  else register_host_detail(name:app, value:"cpe:/a:microsoft:word", desc:SCRIPT_DESC);
}

if (VisioVer){
  cpe = "cpe:/a:microsoft:visio";
  if (version_in_range(version:VisioVer, test_version:"9.0.0", test_version2:"10.0.0"))register_host_detail(name:app, value:cpe + ":2000", desc:SCRIPT_DESC);
  else if (version_in_range(version:VisioVer, test_version:"12.0.4518.1014", test_version2:"12.0.6211.1000"))register_host_detail(name:app, value:cpe + ":2007", desc:SCRIPT_DESC);
  else if (version_in_range(version:VisioVer, test_version:"12.0.6211.1000", test_version2:"12.0.6423.1000"))register_host_detail(name:app, value:cpe + ":2007:sp1", desc:SCRIPT_DESC);
  else if (version_in_range(version:VisioVer, test_version:"12.0.6423.1000", test_version2:"13.0.0.0"))register_host_detail(name:app, value:cpe + ":2007:sp2", desc:SCRIPT_DESC);
  else if (version_in_range(version:VisioVer, test_version:"14.0.4756.1000", test_version2:"15.0.0.0"))register_host_detail(name:app, value:cpe + ":2010", desc:SCRIPT_DESC);
  else if (VisioVer != VisioSMBVer){
    if (version_in_range(version:VisioVer, test_version:"10.0.525", test_version2:"10.1.2514"))register_host_detail(name:app, value:cpe + ":2002", desc:SCRIPT_DESC);
    else if (version_in_range(version:VisioVer, test_version:"10.1.2514", test_version2:"10.2.5110"))register_host_detail(name:app, value:cpe + ":2002:sp1", desc:SCRIPT_DESC);
    else if (version_in_range(version:VisioVer, test_version:"10.2.5110", test_version2:"11.0.0.0"))register_host_detail(name:app, value:cpe + ":2002:sp2", desc:SCRIPT_DESC);
    else if (version_in_range(version:VisioVer, test_version:"11.0.3216.5614", test_version2:"11.0.4301.6360"))register_host_detail(name:app, value:cpe + ":2003", desc:SCRIPT_DESC);
    else if (version_in_range(version:VisioVer, test_version:"11.0.4301.6360", test_version2:"11.0.7969.0"))register_host_detail(name:app, value:cpe + ":2003:sp1", desc:SCRIPT_DESC);
    else if (version_in_range(version:VisioVer, test_version:"11.0.7969.0", test_version2:"11.0.8173.0")){
      for(i=0; i<max_index(instprg); i++){
        val = split(instprg[i], sep:";", keep:0);
        if ("Microsoft Office Visio Professional" >< val[0])register_host_detail(name:app, value:cpe + ":2003:sp2:professional", desc:SCRIPT_DESC);
        else if ("Microsoft Office Visio Standard" >< val[0])register_host_detail(name:app, value:cpe + ":2003:sp2:standard", desc:SCRIPT_DESC);
        else register_host_detail(name:app, value:cpe + ":2003:sp2", desc:SCRIPT_DESC);
      }
    }
    else if (version_in_range(version:VisioVer, test_version:"11.0.8173.0", test_version2:"12.0.0.0"))register_host_detail(name:app, value:cpe + ":2003:sp3", desc:SCRIPT_DESC);
  }
  else if (VisioVer == VisioSMBVer){
    if (version_in_range(version:VisioVer, test_version:"10.0.525", test_version2:"10.0.2420.4"))register_host_detail(name:app, value:cpe + ":2002", desc:SCRIPT_DESC);
    else if (version_in_range(version:VisioVer, test_version:"10.0.2420.4", test_version2:"10.0.5006.4"))register_host_detail(name:app, value:cpe + ":2002:sp1", desc:SCRIPT_DESC);
    else if (version_in_range(version:VisioVer, test_version:"10.0.5006.4", test_version2:"11.0.0.0"))register_host_detail(name:app, value:cpe + ":2002:sp2", desc:SCRIPT_DESC);
    else if (version_in_range(version:VisioVer, test_version:"11.0.3216.0", test_version2:"11.0.4301.0"))register_host_detail(name:app, value:cpe + ":2003", desc:SCRIPT_DESC);
    else if (version_in_range(version:VisioVer, test_version:"11.0.4301.0", test_version2:"11.0.5509.0"))register_host_detail(name:app, value:cpe + ":2003:sp1", desc:SCRIPT_DESC);
    else if (version_in_range(version:VisioVer, test_version:"11.0.5509.0", test_version2:"11.0.8161.0")){
      for(i=0; i<max_index(instprg); i++){
        val = split(instprg[i], sep:";", keep:0);
        if ("Microsoft Office Visio Professional" >< val[0])register_host_detail(name:app, value:cpe + ":2003:sp2:professional", desc:SCRIPT_DESC);
        else if ("Microsoft Office Visio Standard" >< val[0])register_host_detail(name:app, value:cpe + ":2003:sp2:standard", desc:SCRIPT_DESC);
        else register_host_detail(name:app, value:cpe + ":2003:sp2", desc:SCRIPT_DESC);
      }
    }
    else if (version_in_range(version:VisioVer, test_version:"11.0.8161.0", test_version2:"12.0.0.0"))register_host_detail(name:app, value:cpe + ":2003:sp3", desc:SCRIPT_DESC);
  }
  else register_host_detail(name:app, value:"cpe:/a:microsoft:visio", desc:SCRIPT_DESC);
}
else if (VisioCRV){
  cpe = "cpe:/a:microsoft:visio";
  if (version_in_range(version:VisioCRV, test_version:"9.0", test_version2:"10.0"))register_host_detail(name:app, value:cpe + ":2000", desc:SCRIPT_DESC);
  else if (version_in_range(version:VisioCRV, test_version:"10.0", test_version2:"11.0"))register_host_detail(name:app, value:cpe + ":2002", desc:SCRIPT_DESC);
  else if (version_in_range(version:VisioCRV, test_version:"11.0", test_version2:"12.0"))register_host_detail(name:app, value:cpe + ":2003", desc:SCRIPT_DESC);
  else if (version_in_range(version:VisioCRV, test_version:"12.0", test_version2:"13.0"))register_host_detail(name:app, value:cpe + ":2007", desc:SCRIPT_DESC);
  else if (version_in_range(version:VisioCRV, test_version:"14.0.4756.1000", test_version2:"14.0.6022.1000"))register_host_detail(name:app, value:cpe + ":2010", desc:SCRIPT_DESC);
  else if (version_in_range(version:VisioCRV, test_version:"14.0.6022.1000", test_version2:"15.0.0.0"))register_host_detail(name:app, value:cpe + ":2010:sp1", desc:SCRIPT_DESC);
  else register_host_detail(name:app, value:"cpe:/a:microsoft:visio", desc:SCRIPT_DESC);
}
if (directx){
  cpe = "cpe:/a:microsoft:directx";
  if (version_in_range(version:directx, test_version:"4.05.01.1600", test_version2:"4.05.01.1998"))register_host_detail(name:app, value:cpe + ":5.2", desc:SCRIPT_DESC);
  else if (directx == "4.06.02.0436")register_host_detail(name:app, value:cpe + ":6.1", desc:SCRIPT_DESC);
  else if (directx == "4.07.00.0700")register_host_detail(name:app, value:cpe + ":7.0", desc:SCRIPT_DESC);
  else if (directx == "4.07.00.0716")register_host_detail(name:app, value:cpe + ":7a", desc:SCRIPT_DESC);
  else if (directx == "4.07.01.3000")register_host_detail(name:app, value:cpe + ":7.1", desc:SCRIPT_DESC);
  else if (directx == "4.08.00.0400" && OS_TYPE != "16")register_host_detail(name:app, value:cpe + ":8.0", desc:SCRIPT_DESC);
  else if (directx == "4.08.00.0400" && OS_TYPE == "16")register_host_detail(name:app, value:cpe + ":8.0a", desc:SCRIPT_DESC);
  else if (version_in_range(version:directx, test_version:"4.08.01.0810", test_version2:"4.08.01.0882"))register_host_detail(name:app, value:cpe + ":8.1", desc:SCRIPT_DESC);
  else if (directx == "4.08.01.0901" && OSVER != "5.0")register_host_detail(name:app, value:cpe + ":8.1a", desc:SCRIPT_DESC);
  else if (directx == "4.08.01.0901" && OSVER == "5.0")register_host_detail(name:app, value:cpe + ":8.1b", desc:SCRIPT_DESC);
  else if (directx == "4.08.02.0134")register_host_detail(name:app, value:cpe + ":8.2", desc:SCRIPT_DESC);
  else if (directx == "4.09.00.0900")register_host_detail(name:app, value:cpe + ":9.0", desc:SCRIPT_DESC);
  else if (directx == "4.09.00.0901")register_host_detail(name:app, value:cpe + ":9.0a", desc:SCRIPT_DESC);
  else if (directx == "4.09.00.0902")register_host_detail(name:app, value:cpe + ":9.0b", desc:SCRIPT_DESC);
  else if (directx == "4.09.00.0903" || directx == "4.09.00.0904")register_host_detail(name:app, value:cpe + ":9.0c", desc:SCRIPT_DESC);
  else if (directx == "6.00.6000.16386")register_host_detail(name:app, value:cpe + ":10.0", desc:SCRIPT_DESC);
  else if (directx == "6.01.7600.0000")register_host_detail(name:app, value:cpe + ":11.0", desc:SCRIPT_DESC);
  else register_host_detail(name:app, value:"cpe:/a:microsoft:directx", desc:SCRIPT_DESC);
}

if (iever){
  cpe = "cpe:/a:microsoft:ie";
  if (version_is_equal(version:iever, test_version:"4.70.1155"))register_host_detail(name:app, value:cpe + ":3.0", desc:SCRIPT_DESC);
  else if (version_is_equal(version:iever, test_version:"4.70.1158"))register_host_detail(name:app, value:cpe + ":3.0", desc:SCRIPT_DESC);
  else if (version_is_equal(version:iever, test_version:"4.70.1215"))register_host_detail(name:app, value:cpe + ":3.0.1", desc:SCRIPT_DESC);
  else if (version_is_equal(version:iever, test_version:"4.70.1300"))register_host_detail(name:app, value:cpe + ":3.0.2", desc:SCRIPT_DESC);
  else if (version_is_equal(version:iever, test_version:"4.71.1712.6"))register_host_detail(name:app, value:cpe + ":4.0", desc:SCRIPT_DESC);
  else if (version_is_equal(version:iever ,test_version:"4.72.2106.8"))register_host_detail(name:app, value:cpe + ":4.0.1", desc:SCRIPT_DESC);
  else if (version_is_equal(version:iever ,test_version:"4.72.3110.8"))register_host_detail(name:app, value:cpe + ":4.0.1:sp1", desc:SCRIPT_DESC);
  else if (version_is_equal(version:iever ,test_version:"4.72.3612.1713"))register_host_detail(name:app, value:cpe + ":4.0.1:sp2", desc:SCRIPT_DESC);
  else if (version_is_equal(version:iever ,test_version:"4.72.2106.8"))register_host_detail(name:app, value:cpe + ":4.01", desc:SCRIPT_DESC);
  else if (version_is_equal(version:iever ,test_version:"4.72.3110.8"))register_host_detail(name:app, value:cpe + ":4.01:sp1", desc:SCRIPT_DESC);
  else if (version_is_equal(version:iever, test_version:"4.40.308"))register_host_detail(name:app, value:cpe + ":4.40.308", desc:SCRIPT_DESC);
  else if (version_is_equal(version:iever, test_version:"4.40.520"))register_host_detail(name:app, value:cpe + ":4.40.520", desc:SCRIPT_DESC);
  else if (version_is_equal(version:iever, test_version:"4.70.1155"))register_host_detail(name:app, value:cpe + ":4.70.1155", desc:SCRIPT_DESC);
  else if (version_is_equal(version:iever, test_version:"4.70.1158"))register_host_detail(name:app, value:cpe + ":4.70.1158", desc:SCRIPT_DESC);
  else if (version_is_equal(version:iever, test_version:"4.70.1215"))register_host_detail(name:app, value:cpe + ":4.70.1215", desc:SCRIPT_DESC);
  else if (version_is_equal(version:iever, test_version:"4.70.1300"))register_host_detail(name:app, value:cpe + ":4.70.1300", desc:SCRIPT_DESC);
  else if (version_is_equal(version:iever, test_version:"4.71.1008.3"))register_host_detail(name:app, value:cpe + ":4.71.1008.3", desc:SCRIPT_DESC);
  else if (version_is_equal(version:iever, test_version:"4.71.1712.6"))register_host_detail(name:app, value:cpe + ":4.71.1712.6", desc:SCRIPT_DESC);
  else if (version_is_equal(version:iever, test_version:"4.71.544"))register_host_detail(name:app, value:cpe + ":4.71.544", desc:SCRIPT_DESC);
  else if (version_is_equal(version:iever, test_version:"4.72.2106.8"))register_host_detail(name:app, value:cpe + ":4.72.2106.8", desc:SCRIPT_DESC);
  else if (version_is_equal(version:iever, test_version:"4.72.3110.8"))register_host_detail(name:app, value:cpe + ":4.72.3110.8", desc:SCRIPT_DESC);
  else if (version_is_equal(version:iever, test_version:"4.72.3612.1713"))register_host_detail(name:app, value:cpe + ":4.72.3612.1713", desc:SCRIPT_DESC);
  else if (version_is_equal(version:iever, test_version:"5.00.0518.10"))
  {
    register_host_detail(name:app, value:cpe + ":5.00.0518.10", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe + ":5.00.0910.1309", desc:SCRIPT_DESC);
  }
  else if (version_is_equal(version:iever, test_version:"5.00.2014.0216"))
  {
    register_host_detail(name:app, value:cpe + ":5.00.2014.0216", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe + ":5", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe + ":5.0", desc:SCRIPT_DESC);
  }
  else if (version_is_equal(version:iever, test_version:"5.00.2314.1003"))
  {
    register_host_detail(name:app, value:cpe + ":5.00.2314.1003", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe + ":5", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe + ":5.0", desc:SCRIPT_DESC);
  }
  else if (version_is_equal(version:iever, test_version:"5.00.2516.1900"))register_host_detail(name:app, value:cpe + ":5.00.2516.1900", desc:SCRIPT_DESC);

  else if (version_is_equal(version:iever, test_version:"5.00.2614.3500"))
  {
    register_host_detail(name:app, value:cpe + ":5.00.2614.3500", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe + ":5", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe + ":5.0", desc:SCRIPT_DESC);
  }
  else if (version_is_equal(version:iever, test_version:"5.00.2919.3800"))register_host_detail(name:app, value:cpe + ":5.00.2919.3800", desc:SCRIPT_DESC);

  else if (version_is_equal(version:iever, test_version:"5.00.2919.6307"))
  {
    register_host_detail(name:app, value:cpe + ":5.00.2919.6307", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe + ":5.0.1", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe + ":5.01", desc:SCRIPT_DESC);
  }
  else if (version_is_equal(version:iever, test_version:"5.00.2919.800"))register_host_detail(name:app, value:cpe + ":5.00.2919.800", desc:SCRIPT_DESC);

  else if (version_is_equal(version:iever, test_version:"5.00.2920.0000"))
  {
    register_host_detail(name:app, value:cpe + ":5.00.2920.0000", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe + ":5.0.1", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe + ":5.01", desc:SCRIPT_DESC);
  }
  else if (version_is_equal(version:iever, test_version:"5.00.3103.1000"))
  {
    register_host_detail(name:app, value:cpe + ":5.00.3103.1000", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe + ":5.0.1:sp1", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe + ":5.01:sp1", desc:SCRIPT_DESC);
  }
  else if (version_is_equal(version:iever, test_version:"5.00.3105.0106"))
  {
    register_host_detail(name:app, value:cpe + ":5.00.3105.0106", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe + ":5.0.1:sp1", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe + ":5.01:sp1", desc:SCRIPT_DESC);
  }
  else if (version_is_equal(version:iever, test_version:"5.00.3314.2101"))
  {
    register_host_detail(name:app, value:cpe + ":5.00.3314.2101", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe + ":5.0.1:sp2", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe + ":5.01:sp2", desc:SCRIPT_DESC);
  }
  else if (version_is_equal(version:iever, test_version:"5.00.3315.1000"))
  {
    register_host_detail(name:app, value:cpe + ":5.00.3315.1000", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe + ":5.0.1:sp2", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe + ":5.01:sp2", desc:SCRIPT_DESC);
  }
  else if (version_is_equal(version:iever, test_version:"5.00.3502.1000"))
  {
    register_host_detail(name:app, value:cpe + ":5.00.3502.1000", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe + ":5.0.1:sp3", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe + ":5.01:sp3", desc:SCRIPT_DESC);
  }
  else if (version_is_equal(version:iever, test_version:"5.00.3700.1000"))
  {
    register_host_detail(name:app, value:cpe + ":5.00.3700.1000", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe + ":5.01:sp4", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe + ":5.0.1:sp4", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:"cpe:/a:microsoft:internet_explorer:5.01:sp4", desc:SCRIPT_DESC);
  }
  else if (version_is_equal(version:iever, test_version:"5.50.4134.0100"))register_host_detail(name:app, value:cpe + ":5.5", desc:SCRIPT_DESC);
  else if (version_is_equal(version:iever, test_version:"5.50.4134.0600"))register_host_detail(name:app, value:cpe + ":5.5", desc:SCRIPT_DESC);

  else if (version_is_equal(version:iever, test_version:"5.50.3825.1300"))
  {
    register_host_detail(name:app, value:cpe + ":5.5:preview", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe + ":5.50.3825.1300", desc:SCRIPT_DESC);
  }
  else if (version_is_equal(version:iever, test_version:"5.50.4030.2400"))register_host_detail(name:app, value:cpe + ":5.50.4030.2400", desc:SCRIPT_DESC);
  else if (version_is_equal(version:iever, test_version:"5.50.4134.0100"))register_host_detail(name:app, value:cpe + ":5.50.4134.0100", desc:SCRIPT_DESC);
  else if (version_is_equal(version:iever, test_version:"5.50.4134.0600"))register_host_detail(name:app, value:cpe + ":5.50.4134.0600", desc:SCRIPT_DESC);
  else if (version_is_equal(version:iever, test_version:"5.50.4308.2900"))register_host_detail(name:app, value:cpe + ":5.50.4308.2900", desc:SCRIPT_DESC);
  else if (version_is_equal(version:iever, test_version:"5.50.4522.1800"))
  {
    register_host_detail(name:app, value:cpe + ":5.50.4522.1800", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe + ":5.5:sp1", desc:SCRIPT_DESC);
  }
  else if (version_is_equal(version:iever, test_version:"5.50.4807.2300"))
  {
    register_host_detail(name:app, value:cpe + ":5.5:sp2", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe + ":5.50.4807.2300", desc:SCRIPT_DESC);
  }
  else if (version_is_equal(version:iever, test_version:"6.00.2462.0000"))register_host_detail(name:app, value:cpe + ":6.00.2462.0000", desc:SCRIPT_DESC);
  else if (version_is_equal(version:iever, test_version:"6.00.2479.0006"))register_host_detail(name:app, value:cpe + ":6.00.2479.0006", desc:SCRIPT_DESC);
  else if (version_is_equal(version:iever, test_version:"6.00.2600.0000") || version_is_equal(version:iever, test_version:"6.0.2600")){
    if (version_is_equal(version:iever, test_version:"6.0.2600"))register_host_detail(name:app, value:cpe + ":6.0.2600", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe + ":6", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:"cpe:/a:microsoft:internet_explorer:6", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe + ":6.0", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe + ":6.00.2600.0000", desc:SCRIPT_DESC);
  }
  else if (version_in_range(version:iever, test_version:"6.00.2900.2180", test_version2:"6.00.3790.1830")){
    register_host_detail(name:app, value:cpe + ":6", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe + ":6.0", desc:SCRIPT_DESC);
    if (version_is_equal(version:iever, test_version:"6.00.2900.2180"))register_host_detail(name:app, value:cpe + ":6.00.2900.2180", desc:SCRIPT_DESC);
  }
  else if (version_in_range(version:iever, test_version:"6.0.2900.2180", test_version2:"6.0.3790.1830")){
    register_host_detail(name:app, value:cpe + ":6", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe + ":6.0", desc:SCRIPT_DESC);
    if (version_is_equal(version:iever, test_version:"6.0.2900.2180"))register_host_detail(name:app, value:cpe + ":6.0.2900.2180", desc:SCRIPT_DESC);
  }
  else if (version_is_equal(version:iever, test_version:"6.00.2800.1106") || version_is_equal(version:iever, test_version:"6.0.2800.1106")){
    if (version_is_equal(version:iever, test_version:"6.0.2800.1106"))register_host_detail(name:app, value:cpe + ":6.0.2800.1106", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe + ":6:sp1", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:"cpe:/a:microsoft:internet_explorer:6:sp1", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe + ":6.00.2800.1106", desc:SCRIPT_DESC);
  }
  else if (version_is_equal(version:iever, test_version:"6.0.2800"))register_host_detail(name:app, value:cpe + ":6.0.2800", desc:SCRIPT_DESC);
  else if (version_is_equal(version:iever, test_version:"6.0.2900"))register_host_detail(name:app, value:cpe + ":6.0.2900", desc:SCRIPT_DESC);
  else if (version_is_equal(version:iever, test_version:"6.00.3663.0000"))register_host_detail(name:app, value:cpe + ":6.00.3663.0000", desc:SCRIPT_DESC);
  else if (version_is_equal(version:iever, test_version:"6.00.3718.0000"))register_host_detail(name:app, value:cpe + ":6.00.3718.0000", desc:SCRIPT_DESC);
  else if (version_is_equal(version:iever, test_version:"6.00.3790.0000"))register_host_detail(name:app, value:cpe + ":6.00.3790.0000", desc:SCRIPT_DESC);
  else if (version_is_equal(version:iever, test_version:"6.00.3790.1830"))register_host_detail(name:app, value:cpe + ":6.00.3790.1830", desc:SCRIPT_DESC);
  else if (version_is_equal(version:iever, test_version:"6.00.3790.3959"))
  {
    register_host_detail(name:app, value:cpe + ":6.00.3790.3959", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe + ":6:sp2", desc:SCRIPT_DESC);
  }
  else if (version_is_equal(version:iever ,test_version:"7.0.5112.0"))register_host_detail(name:app, value:cpe + ":7.0:beta1", desc:SCRIPT_DESC);
  else if (version_is_equal(version:iever ,test_version:"7.0.5346.5"))register_host_detail(name:app, value:cpe + ":7.0:beta2", desc:SCRIPT_DESC);
  else if (version_is_equal(version:iever ,test_version:"7.0.5335.5"))register_host_detail(name:app, value:cpe + ":7.0:beta2", desc:SCRIPT_DESC);
  else if (version_is_equal(version:iever ,test_version:"7.0.5450.4"))register_host_detail(name:app, value:cpe + ":7.0:beta3", desc:SCRIPT_DESC);
  else if (version_in_range(version:iever, test_version:"7.0.5112.0", test_version2:"7.0.5450.4"))register_host_detail(name:app, value:cpe + ":7.0:beta", desc:SCRIPT_DESC);
  else if (version_in_range(version:iever, test_version:"7.00.5730.1100", test_version2:"7.00.6001.1800")){
    register_host_detail(name:app, value:cpe + ":7", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:"cpe:/a:microsoft:internet_explorer:7", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe + ":7.0", desc:SCRIPT_DESC);
  }
  else if (version_is_equal(version:iever, test_version:"7.00.5730.1100")){
    register_host_detail(name:app, value:cpe + ":7.0.5730:unknown:gold", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:"cpe:/a:microsoft:internet_explorer:7.0.5730", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe + ":7.00.5730.11", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe + ":7.00.5730.1100", desc:SCRIPT_DESC);
  }
  else if (version_is_equal(version:iever, test_version:"7.00.6000.16386"))register_host_detail(name:app, value:cpe + ":7.00.6000.16386", desc:SCRIPT_DESC);
  else if (version_is_equal(version:iever, test_version:"7.00.6000.16441"))register_host_detail(name:app, value:cpe + ":7.00.6000.16441", desc:SCRIPT_DESC);
  else if (version_in_range(version:iever, test_version:"8.00.6001.17184", test_version2:"8.00.6001.18372")){
    register_host_detail(name:app, value:cpe + ":8.0.6001", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe + ":8.0.6001:beta", desc:SCRIPT_DESC);
  }
  else if (version_in_range(version:iever, test_version:"8.00.6001.18702", test_version2:"8.00.7601.17514"))register_host_detail(name:app, value:cpe + ":8", desc:SCRIPT_DESC);
  else if (version_is_equal(version:iever, test_version:"9.0.8112.16421"))register_host_detail(name:app, value:cpe + ":9", desc:SCRIPT_DESC);
  else if (version_in_range(version:iever, test_version:"9.10.9200.16384", test_version2:"9.10.9200.99999"))register_host_detail(name:app, value:cpe + ":10", desc:SCRIPT_DESC);
  else if (version_is_equal(version:iever, test_version:"9.11.9600.16384"))register_host_detail(name:app, value:cpe + ":11", desc:SCRIPT_DESC);
  else if (version_is_equal(version:iever, test_version:"9.11.9600.17031"))register_host_detail(name:app, value:cpe + ":11", desc:SCRIPT_DESC);
  else register_host_detail(name:app, value:"cpe:/a:microsoft:ie", desc:SCRIPT_DESC);
}

if(oever){
  cpe = "cpe:/a:microsoft:outlook_express";
  if (version_is_equal(version:oever, test_version:"4.71.1712.6"))register_host_detail(name:app, value:cpe + ":4.0", desc:SCRIPT_DESC);
  else if (version_is_equal(version:oever, test_version:"4.72.2106.8"))register_host_detail(name:app, value:cpe + ":4.01", desc:SCRIPT_DESC);
  else if (version_is_equal(version:oever, test_version:"4.72.3612.1713"))register_host_detail(name:app, value:cpe + ":4.01:sp2", desc:SCRIPT_DESC);
  else if (version_is_equal(version:oever, test_version:"4.72.2106.4"))register_host_detail(name:app, value:cpe + ":4.72.2106.4", desc:SCRIPT_DESC);
  else if (version_is_equal(version:oever, test_version:"4.72.3120.0"))register_host_detail(name:app, value:cpe + ":4.72.3120.0", desc:SCRIPT_DESC);
  else if (version_is_equal(version:oever, test_version:"4.72.3612.1700"))register_host_detail(name:app, value:cpe + ":4.72.3612.1700", desc:SCRIPT_DESC);
  else if (version_is_equal(version:oever, test_version:"5.00.2014.0216"))register_host_detail(name:app, value:cpe + ":5.0", desc:SCRIPT_DESC);
  else if (version_is_equal(version:oever, test_version:"5.00.2314.1003"))register_host_detail(name:app, value:cpe + ":5.0", desc:SCRIPT_DESC);
  else if (version_is_equal(version:oever, test_version:"5.00.2614.3500"))register_host_detail(name:app, value:cpe + ":5.0", desc:SCRIPT_DESC);
  else if (version_is_equal(version:oever, test_version:"5.00.2919.6307"))register_host_detail(name:app, value:cpe + ":5.0.1", desc:SCRIPT_DESC);
  else if (version_is_equal(version:oever, test_version:"5.00.2920.0000"))register_host_detail(name:app, value:cpe + ":5.0.1", desc:SCRIPT_DESC);
  else if (version_is_equal(version:oever, test_version:"5.00.2919.6307"))register_host_detail(name:app, value:cpe + ":5.01", desc:SCRIPT_DESC);
  else if (version_is_equal(version:oever, test_version:"5.00.2920.0000"))register_host_detail(name:app, value:cpe + ":5.01", desc:SCRIPT_DESC);
  else if (version_is_equal(version:oever, test_version:"5.50.4134.0100"))register_host_detail(name:app, value:cpe + ":5.5", desc:SCRIPT_DESC);
  else if (version_is_equal(version:oever, test_version:"5.50.4134.0600"))register_host_detail(name:app, value:cpe + ":5.5", desc:SCRIPT_DESC);
  else if (version_is_equal(version:oever, test_version:"5.50.4522.1800"))register_host_detail(name:app, value:cpe + ":5.5:sp1", desc:SCRIPT_DESC);
  else if (version_is_equal(version:oever, test_version:"5.50.4807.2300"))register_host_detail(name:app, value:cpe + ":5.5:sp2", desc:SCRIPT_DESC);
  else if (version_is_equal(version:oever, test_version:"5.50.4807.1700"))register_host_detail(name:app, value:cpe + ":5.5:sp2", desc:SCRIPT_DESC);
  else if (version_is_equal(version:oever, test_version:"6.00.2800.1106"))register_host_detail(name:app, value:cpe + ":6.00.2800.1106", desc:SCRIPT_DESC);
  else if (version_is_equal(version:oever, test_version:"6.00.2900.2180"))register_host_detail(name:app, value:cpe + ":6.00.2900.2180", desc:SCRIPT_DESC);
  else if (version_is_equal(version:oever, test_version:"6.00.2900.5512"))register_host_detail(name:app, value:cpe + ":6.00.2900.5512", desc:SCRIPT_DESC);
  else if (version_in_range(version:iever, test_version:"6.00.0.0", test_version2:"7.00.0.0"))register_host_detail(name:app, value:cpe + ":6.0", desc:SCRIPT_DESC);
  else register_host_detail(name:app, value:"cpe:/a:microsoft:outlook_express", desc:SCRIPT_DESC);
}

if(wmplayerver){
  cpe = "cpe:/a:microsoft:windows_media_player";
  if (version_in_range(version:wmplayerver, test_version:"6.3.0.0", test_version2:"6.4.0.0"))register_host_detail(name:app, value:cpe + ":6.3", desc:SCRIPT_DESC);
  else if (version_in_range(version:wmplayerver, test_version:"6.4.0.0", test_version2:"7.00.0.0"))register_host_detail(name:app, value:cpe + ":6.4", desc:SCRIPT_DESC);
  else if (version_in_range(version:wmplayerver, test_version:"6.4.0.0", test_version2:"7.01.00.3055"))register_host_detail(name:app, value:cpe + ":7", desc:SCRIPT_DESC);
  else if (version_in_range(version:wmplayerver, test_version:"7.01.00.3055", test_version2:"8.0.0.0"))register_host_detail(name:app, value:cpe + ":7.1", desc:SCRIPT_DESC);
  else if (version_is_equal(version:wmplayerver, test_version:"8.00.00.4477"))register_host_detail(name:app, value:cpe + ":8.00.00.4477", desc:SCRIPT_DESC);
  else if (version_in_range(version:wmplayerver, test_version:"8.00.00.4477", test_version2:"9.00.0.0"))
  {
    register_host_detail(name:app, value:cpe + ":xp", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe + ":8", desc:SCRIPT_DESC);
  }
  else if (version_is_equal(version:wmplayerver, test_version:"9.00.00.2980"))register_host_detail(name:app, value:cpe + ":9.00.00.2980", desc:SCRIPT_DESC);
  else if (version_is_equal(version:wmplayerver, test_version:"9.00.00.3250"))register_host_detail(name:app, value:cpe + ":9.00.00.3250", desc:SCRIPT_DESC);
  else if (version_is_equal(version:wmplayerver, test_version:"9.00.00.3349"))register_host_detail(name:app, value:cpe + ":9.00.00.3349", desc:SCRIPT_DESC);
  else if (version_in_range(version:wmplayerver, test_version:"9.00.00.2980", test_version2:"10.00.0.0"))register_host_detail(name:app, value:cpe + ":9", desc:SCRIPT_DESC);
  else if (version_is_equal(version:wmplayerver, test_version:"10.00.00.3646"))register_host_detail(name:app, value:cpe + ":10.00.00.3646", desc:SCRIPT_DESC);
  else if (version_is_equal(version:wmplayerver, test_version:"10.00.00.3990"))register_host_detail(name:app, value:cpe + ":10.00.00.3990", desc:SCRIPT_DESC);
  else if (version_is_equal(version:wmplayerver, test_version:"10.00.00.4019"))register_host_detail(name:app, value:cpe + ":10.00.00.4019", desc:SCRIPT_DESC);
  else if (version_is_equal(version:wmplayerver, test_version:"10.00.00.4036"))register_host_detail(name:app, value:cpe + ":10.00.00.4036", desc:SCRIPT_DESC);
  else if (version_in_range(version:wmplayerver, test_version:"10.00.00.3646", test_version2:"11.00.0.0"))register_host_detail(name:app, value:cpe + ":10", desc:SCRIPT_DESC);
  else if (version_is_equal(version:wmplayerver, test_version:"11.0.5721.5145"))register_host_detail(name:app, value:cpe + ":11.0.5721.5145", desc:SCRIPT_DESC);
  else if (version_is_equal(version:wmplayerver, test_version:"11.0.6000.6324"))register_host_detail(name:app, value:cpe + ":11.0.6000.6324", desc:SCRIPT_DESC);
  else if (version_in_range(version:wmplayerver, test_version:"11.0.5721.5230", test_version2:"12.0.0.0"))register_host_detail(name:app, value:cpe + ":11", desc:SCRIPT_DESC);
  else if (version_in_range(version:wmplayerver, test_version:"12.0.0.0", test_version2:"13.0.0.0"))register_host_detail(name:app, value:cpe + ":12", desc:SCRIPT_DESC);
  else register_host_detail(name:app, value:"cpe:/a:microsoft:windows_media_player", desc:SCRIPT_DESC);
}

if(mdacfullver || mdacver){
  cpe = "cpe:/a:microsoft:data_access_components";
  if (!mdacfullver)mdacfullver = mdacver;
  if (version_in_range(version:mdacfullver, test_version:"1.50.3004.0", test_version2:"2.00.0.0"))register_host_detail(name:app, value:cpe + ":1.5", desc:SCRIPT_DESC);
  else if (version_in_range(version:mdacfullver, test_version:"2.00.3002.4", test_version2:"2.10.0.0"))register_host_detail(name:app, value:cpe + ":2.0", desc:SCRIPT_DESC);
  else if (version_in_range(version:mdacfullver, test_version:"2.10.3513.0", test_version2:"2.10.3711.2"))register_host_detail(name:app, value:cpe + ":2.1", desc:SCRIPT_DESC);
  else if (version_is_equal(version:mdacfullver, test_version:"2.10.3711.2"))register_host_detail(name:app, value:cpe + ":2.1.1.3711.11", desc:SCRIPT_DESC);
  else if (version_is_equal(version:mdacfullver, test_version:"2.10.3711.2"))register_host_detail(name:app, value:cpe + ":2.1.1.3711.11:ga", desc:SCRIPT_DESC);
  else if (version_is_equal(version:mdacfullver, test_version:"2.12.4202.3"))register_host_detail(name:app, value:cpe + ":2.12.4202.3", desc:SCRIPT_DESC);
  else if (version_is_equal(version:mdacfullver, test_version:"2.50.4403.12"))register_host_detail(name:app, value:cpe + ":2.5:gold", desc:SCRIPT_DESC);
  else if (version_in_range(version:mdacfullver, test_version:"2.51.5303.0", test_version2:"2.52.6019.0"))register_host_detail(name:app, value:cpe + ":2.5:sp1", desc:SCRIPT_DESC);
  else if (version_in_range(version:mdacfullver, test_version:"2.52.6019.0", test_version2:"2.53.6200.0"))register_host_detail(name:app, value:cpe + ":2.5:sp2", desc:SCRIPT_DESC);
  else if (version_in_range(version:mdacfullver, test_version:"2.53.6200.0", test_version2:"2.60.0.0"))register_host_detail(name:app, value:cpe + ":2.5:sp3", desc:SCRIPT_DESC);
  else if (version_in_range(version:mdacfullver, test_version:"2.50.4403.6", test_version2:"2.60.0.0"))register_host_detail(name:app, value:cpe + ":2.5", desc:SCRIPT_DESC);
  else if (version_is_equal(version:mdacfullver, test_version:"2.60.6526.0"))register_host_detail(name:app, value:cpe + ":2.6:gold", desc:SCRIPT_DESC);
  else if (version_in_range(version:mdacfullver, test_version:"2.61.7326.0", test_version2:"2.62.7926.0"))register_host_detail(name:app, value:cpe + ":2.6:sp1", desc:SCRIPT_DESC);
  else if (version_in_range(version:mdacfullver, test_version:"2.62.7926.0", test_version2:"2.70.0.0"))register_host_detail(name:app, value:cpe + ":2.6:sp2", desc:SCRIPT_DESC);
  else if (version_in_range(version:mdacfullver, test_version:"2.60.6526.0", test_version2:"2.70.0.0"))register_host_detail(name:app, value:cpe + ":2.6", desc:SCRIPT_DESC);
  else if (version_is_equal(version:mdacfullver, test_version:"2.70.7713.0"))register_host_detail(name:app, value:cpe + ":2.7:gold", desc:SCRIPT_DESC);
  else if (version_in_range(version:mdacfullver, test_version:"2.71.9030.0", test_version2:"2.80.0.0"))register_host_detail(name:app, value:cpe + ":2.7:sp1", desc:SCRIPT_DESC);
  else if (version_in_range(version:mdacfullver, test_version:"2.70.7713.0", test_version2:"2.80.0.0"))register_host_detail(name:app, value:cpe + ":2.7", desc:SCRIPT_DESC);
  else if (version_in_range(version:mdacfullver, test_version:"2.81.1117.0", test_version2:"2.82.1830.0"))register_host_detail(name:app, value:cpe + ":2.8:sp1", desc:SCRIPT_DESC);
  else if (version_in_range(version:mdacfullver, test_version:"2.82.1830.0", test_version2:"2.90.0.0"))register_host_detail(name:app, value:cpe + ":2.8:sp2", desc:SCRIPT_DESC);
  else if (version_in_range(version:mdacfullver, test_version:"2.80.1022.0", test_version2:"2.90.0.0"))register_host_detail(name:app, value:cpe + ":2.8", desc:SCRIPT_DESC);
  else register_host_detail(name:app, value:"cpe:/a:microsoft:data_access_components", desc:SCRIPT_DESC);
}

if (IISMajorVersion >= "1" && IISMinorVersion){
  cpe = "cpe:/a:microsoft:internet_information_server";
  cpe1 = "cpe:/a:microsoft:iis";
  if (IISMajorVersion == "4" && IISMinorVersion == "0"){
    register_host_detail(name:app, value:cpe + ":4.0", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe1 + ":4.0", desc:SCRIPT_DESC);
  }
  else if (IISMajorVersion == "5" && IISMinorVersion == "0"){
    register_host_detail(name:app, value:"cpe:/a:microsoft:internet_information_services:5.0", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe1 + ":5.0", desc:SCRIPT_DESC);
  }
  else if (IISMajorVersion == "5" && IISMinorVersion == "1"){
    register_host_detail(name:app, value:cpe + ":5.1", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe1 + ":5.1", desc:SCRIPT_DESC);
  }
  else if (IISMajorVersion == "6" && IISMinorVersion == "0"){
    register_host_detail(name:app, value:cpe + ":6.0", desc:SCRIPT_DESC);
    register_host_detail(name:app, value:cpe1 + ":6.0", desc:SCRIPT_DESC);
  }
  else if (IISMajorVersion == "7" && IISMinorVersion == "0"){
    register_host_detail(name:app, value:cpe1 + ":7.0", desc:SCRIPT_DESC);
  }
  else if (IISMajorVersion == "7" && IISMinorVersion == "5"){
    register_host_detail(name:app, value:cpe1 + ":7.5", desc:SCRIPT_DESC);
  }
  else register_host_detail(name:app, value:"cpe:/a:microsoft:internet_information_server", desc:SCRIPT_DESC);
}

if (ipnathlp)register_host_detail(name:app, value:"cpe:/a:microsoft:windows_nt_helper_components", desc:SCRIPT_DESC);

if (ExchProductMajor || Exch2010ProductMajor || Exch2013ProductMajor){
  cpe = "cpe:/a:microsoft:exchange_server";
  set_kb_item( name:"MS/Exchange/Server/installed", value:TRUE );
  if (ExchProductMajor != "0"){
    if(ExchSPBuild == "837")register_host_detail(name:app, value:cpe + ":4.0", desc:SCRIPT_DESC);
    else if(ExchSPBuild == "1457")register_host_detail(name:app, value:cpe + ":5.0", desc:SCRIPT_DESC);
    else if(ExchSPBuild == "1458")register_host_detail(name:app, value:cpe + ":5.0:sp1", desc:SCRIPT_DESC);
    else if(ExchSPBuild == "1460")register_host_detail(name:app, value:cpe + ":5.0:sp2", desc:SCRIPT_DESC);
    else if(ExchSPBuild == "1960")register_host_detail(name:app, value:cpe + ":5.5", desc:SCRIPT_DESC);
    else if(ExchSPBuild == "2232")register_host_detail(name:app, value:cpe + ":5.5:sp1", desc:SCRIPT_DESC);
    else if(ExchSPBuild == "2448")register_host_detail(name:app, value:cpe + ":5.5:sp2", desc:SCRIPT_DESC);
    else if(ExchSPBuild == "2650")register_host_detail(name:app, value:cpe + ":5.5:sp3", desc:SCRIPT_DESC);
    else if(ExchSPBuild == "4417")register_host_detail(name:app, value:cpe + ":2000", desc:SCRIPT_DESC);
    else if(ExchSPBuild == "4712")register_host_detail(name:app, value:cpe + ":2000:sp1", desc:SCRIPT_DESC);
    else if(ExchSPBuild == "5762")register_host_detail(name:app, value:cpe + ":2000:sp2", desc:SCRIPT_DESC);
    else if(ExchSPBuild >= "6249" && ExchSPBuild <= "6620")register_host_detail(name:app, value:cpe + ":2000:sp3", desc:SCRIPT_DESC);
    else if(ExchSPBuild == "6944")register_host_detail(name:app, value:cpe + ":2003", desc:SCRIPT_DESC);
    else if(ExchSPBuild == "7226")register_host_detail(name:app, value:cpe + ":2003:sp1", desc:SCRIPT_DESC);
    else if(ExchSPBuild == "7638" && ExchSPBuild <= "7654")register_host_detail(name:app, value:cpe + ":2003:sp2", desc:SCRIPT_DESC);
    else if(ExchProductMajor == "8" && ExchProductMinor == "0")register_host_detail(name:app, value:cpe + ":2007", desc:SCRIPT_DESC);
    else if(ExchProductMajor == "8" && ExchProductMinor == "1")register_host_detail(name:app, value:cpe + ":2007:sp1", desc:SCRIPT_DESC);
    else if(ExchProductMajor == "8" && ExchProductMinor == "2" && x64 == "1")register_host_detail(name:app, value:cpe + ":2007:sp2:x64", desc:SCRIPT_DESC);
    else if(ExchProductMajor == "8" && ExchProductMinor == "3")register_host_detail(name:app, value:cpe + ":2007:sp3", desc:SCRIPT_DESC);
    else register_host_detail(name:app, value:"cpe:/a:microsoft:exchange_server", desc:SCRIPT_DESC);
  }
  if (Exch2010ProductMajor == "E"){
    if (Exch2010ProductMajor == "E" && Exch2010ProductMinor == "0")register_host_detail(name:app, value:cpe + ":2010:-:x64", desc:SCRIPT_DESC);
    else if (Exch2010ProductMajor == "E" && Exch2010ProductMinor == "1")register_host_detail(name:app, value:cpe + ":2010:sp1", desc:SCRIPT_DESC);
    else if (Exch2010ProductMajor == "E" && Exch2010ProductMinor == "2")register_host_detail(name:app, value:cpe + ":2010:sp2", desc:SCRIPT_DESC);
    else if (Exch2010ProductMajor == "E" && Exch2010ProductMinor == "3")register_host_detail(name:app, value:cpe + ":2010:sp3", desc:SCRIPT_DESC);
    else register_host_detail(name:app, value:cpe + ":2013", desc:SCRIPT_DESC);
  }if (Exch2013ProductMajor == "F"){
    if (Exch2013ProductMajor == "F" && Exch2013DispName >< "Microsoft Exchange Server 2013 Cumulative Update 1")register_host_detail(name:app, value:cpe + ":cu1", desc:SCRIPT_DESC);
    else if (Exch2013ProductMajor == "F" && Exch2013DispName >< "Microsoft Exchange Server 2013 Cumulative Update 2")register_host_detail(name:app, value:cpe + ":cu2", desc:SCRIPT_DESC);
    else register_host_detail(name:app, value:"cpe:/a:microsoft:exchange_server", desc:SCRIPT_DESC);
  }
}


if (msxml3 || msxml4 || msxml5 || msxml6){
  if (msxml3)register_host_detail(name:app, value:"cpe:/a:microsoft:xml_core_services:3.0", desc:SCRIPT_DESC);
  if (msxml4)register_host_detail(name:app, value:"cpe:/a:microsoft:xml_core_services:4.0", desc:SCRIPT_DESC);
  if (msxml5)register_host_detail(name:app, value:"cpe:/a:microsoft:xml_core_services:5.0", desc:SCRIPT_DESC);
  if (msxml6)register_host_detail(name:app, value:"cpe:/a:microsoft:xml_core_services:6.0", desc:SCRIPT_DESC);
}


if (worksVer){
  register_host_detail(name:app, value:"cpe:/a:microsoft:works:" + worksVer, desc:SCRIPT_DESC);
}


if (sqlregentries || sqlregentriesx){
  mssql = NULL;
  cpe = "cpe:/a:microsoft:sql_server";
  if(sqlregentries){
    entry = NULL;
    if (!smbsqlregentries)entry = split(sqlregentries, sep:"|", keep:FALSE);
    if(!entry)entry = sqlregentries;
    for(i=0; i<max_index(entry); i++)
    {
      val = NULL;
      if(handlereg)val = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Microsoft SQL Server\" + entry[i] + "\MSSQLServer\CurrentVersion", key_name:"CurrentVersion");
      else val = registry_get_sz(key:"SOFTWARE\Microsoft\Microsoft SQL Server\" + entry[i] + "\MSSQLServer\CurrentVersion", item:"CurrentVersion");

      if( ! val || isnull( val ) ) continue;

      if (version_in_range(version:val, test_version:"6.00.121", test_version2:"6.50.000"))register_host_detail(name:app, value:cpe + ":6.0", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"7.00.623", test_version2:"7.00.677"))register_host_detail(name:app, value:cpe + ":7.0", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"7.00.677", test_version2:"7.00.689"))register_host_detail(name:app, value:cpe + ":7.0", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"6.50.201", test_version2:"7.00.000"))register_host_detail(name:app, value:cpe + ":6.5", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"7.00.699", test_version2:"7.00.835"))register_host_detail(name:app, value:cpe + ":7.0:sp1", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"7.00.842", test_version2:"7.00.961"))register_host_detail(name:app, value:cpe + ":7.0:sp2", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"7.00.961", test_version2:"7.00.1063"))register_host_detail(name:app, value:cpe + ":7.0:sp3", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"7.00.1063", test_version2:"8.00.0000"))register_host_detail(name:app, value:cpe + ":7.0:sp4", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"8.00.194", test_version2:"8.00.382"))
      {
        register_host_detail(name:app, value:cpe + ":2000", desc:SCRIPT_DESC);
        register_host_detail(name:app, value:cpe + ":2000:gold", desc:SCRIPT_DESC);
      }
      else if (version_in_range(version:val, test_version:"8.00.382", test_version2:"8.00.534"))register_host_detail(name:app, value:cpe + ":2000:sp1", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"8.00.534", test_version2:"8.00.760"))register_host_detail(name:app, value:cpe + ":2000:sp2", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"8.00.760", test_version2:"8.00.2039"))
      {
        register_host_detail(name:app, value:cpe + ":2000:sp3", desc:SCRIPT_DESC);
        register_host_detail(name:app, value:cpe + ":2000:sp3a", desc:SCRIPT_DESC);
      }
      else if (version_in_range(version:val, test_version:"8.00.2039", test_version2:"9.00.000"))register_host_detail(name:app, value:cpe + ":2000:sp4", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"9.00.1399", test_version2:"9.00.2047"))register_host_detail(name:app, value:cpe + ":2005", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"9.00.2047", test_version2:"9.00.3042"))register_host_detail(name:app, value:cpe + ":2005:sp1", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"9.00.3042", test_version2:"9.00.4035"))register_host_detail(name:app, value:cpe + ":2005:sp2", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"9.00.4035", test_version2:"9.00.5000"))register_host_detail(name:app, value:cpe + ":2005:sp3", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"9.00.5000", test_version2:"10.00.0"))register_host_detail(name:app, value:cpe + ":2005:sp4", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"10.00.1600.22", test_version2:"10.00.2531.00"))register_host_detail(name:app, value:cpe + ":2008", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"10.00.2531.00", test_version2:"10.00.4000.00"))register_host_detail(name:app, value:cpe + ":2008:sp1", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"10.00.4000.00", test_version2:"10.00.5500.00"))register_host_detail(name:app, value:cpe + ":2008:sp2", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"10.00.5500.00", test_version2:"10.50.1600.1"))register_host_detail(name:app, value:cpe + ":2008:sp3", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"10.50.1600.1", test_version2:"10.50.2500.0"))register_host_detail(name:app, value:cpe + ":2008:r2", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"10.50.2500.0", test_version2:"10.50.4000.0"))register_host_detail(name:app, value:cpe + ":2008:r2:sp1", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"10.50.4000.0", test_version2:"11.0.0.0"))register_host_detail(name:app, value:cpe + ":2008:r2:sp2", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"11.00.3000.00", test_version2:"11.00.2100.60"))register_host_detail(name:app, value:cpe + ":2012", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"11.00.2100.60", test_version2:"12.0.0.0"))register_host_detail(name:app, value:cpe + ":2012:sp1", desc:SCRIPT_DESC);
      else
      {
        if (val && !mssql) mssql = "1";
        else if (val && mssql == "2") mssql = "1";
        else mssql = "2";
        if(mssql == "1"){
          register_host_detail(name:app, value:"cpe:/a:microsoft:sql_server", desc:SCRIPT_DESC);
          mssql = "3";
        }
      }
    }
  }
  if(sqlregentriesx){
    entry = NULL;
    if (!smbsqlregentriesx)entry = split(sqlregentriesx, sep:"|", keep:FALSE);
    if(!entry)entry = sqlregentriesx;
    for(i=0; i<max_index(entry); i++)
    {
      val = NULL;
      if(handlereg)val = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Microsoft SQL Server\" + entry[i] + "\MSSQLServer\CurrentVersion", key_name:"CurrentVersion");
      else val = registry_get_sz(key:"SOFTWARE\Microsoft\Microsoft SQL Server\" + entry[i] + "\MSSQLServer\CurrentVersion", item:"CurrentVersion");

      if( ! val || isnull( val ) ) continue;

      if (version_in_range(version:val, test_version:"6.00.121", test_version2:"6.50.000"))register_host_detail(name:app, value:cpe + ":6.0", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"6.50.201", test_version2:"7.00.000"))register_host_detail(name:app, value:cpe + ":6.5", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"7.00.623", test_version2:"7.00.677"))register_host_detail(name:app, value:cpe + ":7.0", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"7.00.677", test_version2:"7.00.689"))register_host_detail(name:app, value:cpe + ":7.0", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"7.00.699", test_version2:"7.00.835"))register_host_detail(name:app, value:cpe + ":7.0:sp1", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"7.00.842", test_version2:"7.00.961"))register_host_detail(name:app, value:cpe + ":7.0:sp2", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"7.00.961", test_version2:"7.00.1063"))register_host_detail(name:app, value:cpe + ":7.0:sp3", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"7.00.1063", test_version2:"8.00.0000"))register_host_detail(name:app, value:cpe + ":7.0:sp4", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"8.00.194", test_version2:"8.00.382"))
      {
        register_host_detail(name:app, value:cpe + ":2000", desc:SCRIPT_DESC);
        register_host_detail(name:app, value:cpe + ":2000:gold", desc:SCRIPT_DESC);
      }
      else if (version_in_range(version:val, test_version:"8.00.382", test_version2:"8.00.534"))register_host_detail(name:app, value:cpe + ":2000:sp1", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"8.00.534", test_version2:"8.00.760"))register_host_detail(name:app, value:cpe + ":2000:sp2", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"8.00.760", test_version2:"8.00.2039"))
      {
        register_host_detail(name:app, value:cpe + ":2000:sp3", desc:SCRIPT_DESC);
        register_host_detail(name:app, value:cpe + ":2000:sp3a", desc:SCRIPT_DESC);
      }
      else if (version_in_range(version:val, test_version:"8.00.2039", test_version2:"9.00.000"))register_host_detail(name:app, value:cpe + ":2000:sp4", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"9.00.1399", test_version2:"9.00.2047"))register_host_detail(name:app, value:cpe + ":2005", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"9.00.2047", test_version2:"9.00.3042"))register_host_detail(name:app, value:cpe + ":2005:sp1", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"9.00.3042", test_version2:"9.00.4035"))register_host_detail(name:app, value:cpe + ":2005:sp2", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"9.00.4035", test_version2:"9.00.5000"))register_host_detail(name:app, value:cpe + ":2005:sp3", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"9.00.5000", test_version2:"10.00.0"))register_host_detail(name:app, value:cpe + ":2005:sp4", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"10.00.1600.22", test_version2:"10.00.2531.00"))register_host_detail(name:app, value:cpe + ":2008", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"10.00.2531.00", test_version2:"10.00.4000.00"))register_host_detail(name:app, value:cpe + ":2008:sp1", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"10.00.4000.00", test_version2:"10.00.5500.00"))register_host_detail(name:app, value:cpe + ":2008:sp2", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"10.00.5500.00", test_version2:"10.50.1600.1"))register_host_detail(name:app, value:cpe + ":2008:sp3", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"10.50.1600.1", test_version2:"10.50.2500.0"))register_host_detail(name:app, value:cpe + ":2008:r2", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"10.50.2500.0", test_version2:"10.50.4000.0"))register_host_detail(name:app, value:cpe + ":2008:r2:sp1", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"10.50.4000.0", test_version2:"11.0.0.0"))register_host_detail(name:app, value:cpe + ":2008:r2:sp2", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"11.00.3000.00", test_version2:"11.00.2100.60"))register_host_detail(name:app, value:cpe + ":2012", desc:SCRIPT_DESC);
      else if (version_in_range(version:val, test_version:"11.00.2100.60", test_version2:"12.0.0.0"))register_host_detail(name:app, value:cpe + ":2012:sp1", desc:SCRIPT_DESC);

      else
      {
        if (val && !mssql) mssql = "1";
        else if (val && mssql == "2") mssql = "1";
        else mssql = "2";
        if(mssql == "1"){
          register_host_detail(name:app, value:"cpe:/a:microsoft:sql_server", desc:SCRIPT_DESC);
          mssql = "3";
        }
      }
    }
  }
}

if (messenger){
  if (version_in_range(version:messenger, test_version:"5.0", test_version2:"5.1"))register_host_detail(name:app, value:"cpe:/a:microsoft:windows_messenger:5.0", desc:SCRIPT_DESC);
  else register_host_detail(name:app, value:"cpe:/a:microsoft:windows_messenger", desc:SCRIPT_DESC);
}

if (crmver){
  if ( crmver =~ '^4.10..*' && "SP1" >< crmsp)register_host_detail(name:app, value:"cpe:/a:microsoft:content_management_server:2001:sp1", desc:SCRIPT_DESC);
  else if ( crmver =~ '^4.10..*')register_host_detail(name:app, value:"cpe:/a:microsoft:content_management_server:2001", desc:SCRIPT_DESC);
  else if ( crmver =~ '^5.0..*' && "SP2" >< crmsp)register_host_detail(name:app, value:"cpe:/a:microsoft:content_management_server:2002:sp2", desc:SCRIPT_DESC);
  else if ( crmver =~ '^5.0..*')register_host_detail(name:app, value:"cpe:/a:microsoft:content_management_server:2002", desc:SCRIPT_DESC);
  else register_host_detail(name:app, value:"cpe:/a:microsoft:content_management_server", desc:SCRIPT_DESC);

}

if (IsaVer){
  cpe = "cpe:/a:microsoft:isa_server";
  if (version_in_range(version:IsaVer, test_version:"3.0.1200.50", test_version2:"3.0.1200.166"))register_host_detail(name:app, value:cpe + ":2000", desc:SCRIPT_DESC);
  else if (version_in_range(version:IsaVer, test_version:"3.0.1200.166", test_version2:"3.0.1200.235"))register_host_detail(name:app, value:cpe + ":2000:sp1", desc:SCRIPT_DESC);
  else if (version_in_range(version:IsaVer, test_version:"3.0.1200.235", test_version2:"3.0.1200.365"))register_host_detail(name:app, value:cpe + ":2000:fp1", desc:SCRIPT_DESC);
  else if (version_in_range(version:IsaVer, test_version:"4.0.2161.50", test_version2:"4.0.2163.213"))register_host_detail(name:app, value:cpe + ":2004", desc:SCRIPT_DESC);
  else if (version_in_range(version:IsaVer, test_version:"4.0.2163.213", test_version2:"4.0.2165.594"))register_host_detail(name:app, value:cpe + ":2004:sp1", desc:SCRIPT_DESC);
  else if (version_in_range(version:IsaVer, test_version:"4.0.2165.594", test_version2:"4.0.2167.887"))register_host_detail(name:app, value:cpe + ":2004:sp2", desc:SCRIPT_DESC);
  else if (version_in_range(version:IsaVer, test_version:"4.0.3439.50", test_version2:"4.0.3443.594"))register_host_detail(name:app, value:cpe + ":2004", desc:SCRIPT_DESC);
  else if (version_in_range(version:IsaVer, test_version:"4.0.3443.594", test_version2:"4.0.3445.887"))register_host_detail(name:app, value:cpe + ":2004:sp1", desc:SCRIPT_DESC);
  else if (version_in_range(version:IsaVer, test_version:"4.0.3445.887", test_version2:"5.0.0.0"))register_host_detail(name:app, value:cpe + ":2004:sp2", desc:SCRIPT_DESC);
  else register_host_detail(name:app, value:"cpe:/a:microsoft:isa_server", desc:SCRIPT_DESC);
}

if (VS2002)register_host_detail(name:app, value:"cpe:/a:microsoft:visual_studio:2002", desc:SCRIPT_DESC);
if (VS2003)register_host_detail(name:app, value:"cpe:/a:microsoft:visual_studio:2003", desc:SCRIPT_DESC);
if (VS2005){
  cpe = "cpe:/a:microsoft:visual_studio:2005";
  if(VS2005SP)register_host_detail(name:app, value:cpe + ":SP1", desc:SCRIPT_DESC);
  else register_host_detail(name:app, value:"cpe:/a:microsoft:visual_studio:2005", desc:SCRIPT_DESC);
}
if (VS2008){
  cpe = "cpe:/a:microsoft:visual_studio:2008";
  if(VS2008SP)register_host_detail(name:app, value:cpe + ":SP1", desc:SCRIPT_DESC);
  else register_host_detail(name:app, value:"cpe:/a:microsoft:visual_studio:2008", desc:SCRIPT_DESC);
}
if (VS2010){
  cpe = "cpe:/a:microsoft:visual_studio:2010";
  if(VS2010SP)register_host_detail(name:app, value:cpe + ":SP1", desc:SCRIPT_DESC);
  else register_host_detail(name:app, value:"cpe:/a:microsoft:visual_studio:2010", desc:SCRIPT_DESC);
}
if (VS2012){
  cpe = "cpe:/a:microsoft:visual_studio:2012";
  if(VS2012SP)register_host_detail(name:app, value:cpe + ":SP1", desc:SCRIPT_DESC);
  else register_host_detail(name:app, value:"cpe:/a:microsoft:visual_studio:2012", desc:SCRIPT_DESC);
}
if (VS2013){
  cpe = "cpe:/a:microsoft:visual_studio:2013";
  if(VS2013SP)register_host_detail(name:app, value:cpe + ":SP1", desc:SCRIPT_DESC);
  else register_host_detail(name:app, value:"cpe:/a:microsoft:visual_studio:2013", desc:SCRIPT_DESC);
}
if (VS2015){
  cpe = "cpe:/a:microsoft:visual_studio:2015";
  if(VS2015SP)register_host_detail(name:app, value:cpe + ":SP1", desc:SCRIPT_DESC);
  else register_host_detail(name:app, value:"cpe:/a:microsoft:visual_studio:2015", desc:SCRIPT_DESC);
}
if(MSNMess){
  cpe = "cpe:/a:microsoft:msn_messenger";
  if (MSNMess == "6.2") register_host_detail(name:app, value:cpe + ":6.2", desc:SCRIPT_DESC);
  else if (MSNMess == "7.0") register_host_detail(name:app, value:cpe + ":7.0", desc:SCRIPT_DESC);
  else if (MSNMess == "7.5") register_host_detail(name:app, value:cpe + ":7.5", desc:SCRIPT_DESC);
  else if (MSNMess == "8.0") register_host_detail(name:app, value:cpe + ":8.0", desc:SCRIPT_DESC);
  else if (MSNMess == "8.1") register_host_detail(name:app, value:cpe + ":8.1", desc:SCRIPT_DESC);
}

if(MVS2005STen || MVS2005STja)register_host_detail(name:app, value:"cpe:/a:microsoft:virtual_server:2005::std", desc:SCRIPT_DESC);
if(MVS2005ENTen || MVS2005ENTja)register_host_detail(name:app, value:"cpe:/a:microsoft:virtual_server:2005::enterprise", desc:SCRIPT_DESC);
if("Microsoft Virtual Server 2005 R2 SP1" >< MVS2005R2)register_host_detail(name:app, value:"cpe:/a:microsoft:virtual_server:2005:r2", desc:SCRIPT_DESC);
if(MVS2005R2ST)register_host_detail(name:app, value:"cpe:/a:microsoft:virtual_server:2005:r2:std", desc:SCRIPT_DESC);
if(MVS2005R2ENT)register_host_detail(name:app, value:"cpe:/a:microsoft:virtual_server:2005:r2:enterprise", desc:SCRIPT_DESC);

if(MVP2004){
  cpe = "cpe:/a:microsoft:virtual_pc:2004";
  if (MVP2004SP1)register_host_detail(name:app, value:cpe + ":SP1", desc:SCRIPT_DESC);
  else register_host_detail(name:app, value:"cpe:/a:microsoft:virtual_pc:2004", desc:SCRIPT_DESC);
}
if(MVP2007){
  cpe = "cpe:/a:microsoft:virtual_pc:2007";
  if (MVP2007SP1)register_host_detail(name:app, value:cpe + ":SP1", desc:SCRIPT_DESC);
  else register_host_detail(name:app, value:"cpe:/a:microsoft:virtual_pc:2007", desc:SCRIPT_DESC);
}

if (instprg){
  for(i=0; i<max_index(instprg); i++){
    val = split(instprg[i], sep:";", keep:0);
    if ("Microsoft Baseline Security Analyzer" >< val[0]){
      if (version_in_range(version:val[1], test_version:"1.0.0", test_version2:"1.1.0"))register_host_detail(name:app, value:"cpe:/a:microsoft:baseline_security_analyzer:1.0", desc:SCRIPT_DESC);
      else if (version_in_range(version:val[1], test_version:"1.2.0", test_version2:"1.3.0"))register_host_detail(name:app, value:"cpe:/a:microsoft:baseline_security_analyzer:1.2", desc:SCRIPT_DESC);
      else register_host_detail(name:app, value:"cpe:/a:microsoft:baseline_security_analyzer", desc:SCRIPT_DESC);
      }
    if ("Microsoft Virtual PC" >< val[0]){
      if ("Microsoft Virtual PC 2004" >< val[0])register_host_detail(name:app, value:"cpe:/a:microsoft:virtual_pc:2004", desc:SCRIPT_DESC);
      else register_host_detail(name:app, value:"cpe:/a:microsoft:virtual_pc", desc:SCRIPT_DESC);
    }
    if ("Microsoft Virtual Server" >< val[0]){
      if ("Microsoft Virtual Server 2005 R2" >< val[0])register_host_detail(name:app, value:"cpe:/a:microsoft:virtual_server:2005:r2", desc:SCRIPT_DESC);
      else if ("Microsoft Virtual Server 2005" >< val[0])register_host_detail(name:app, value:"cpe:/a:microsoft:virtual_server:2005", desc:SCRIPT_DESC);
      else register_host_detail(name:app, value:"cpe:/a:microsoft:virtual_server", desc:SCRIPT_DESC);
    }
    if ("Windows Live Messenger" >< val[0]){
    cpe = "cpe:/a:microsoft:windows_live_messenger";
      if (version_in_range(version:val[1], test_version:"8.0.0000.0000", test_version2:"8.1.0000.0000"))register_host_detail(name:app, value:cpe + ":8.0", desc:SCRIPT_DESC);
      else if (version_in_range(version:val[1], test_version:"8.1.0000.0000", test_version2:"8.2.0000.0000"))register_host_detail(name:app, value:cpe + ":8.1", desc:SCRIPT_DESC);
      else if (version_in_range(version:val[1], test_version:"8.5.0000.0000", test_version2:"8.5.1000.0000"))register_host_detail(name:app, value:cpe + ":8.5", desc:SCRIPT_DESC);
      else if (version_in_range(version:val[1], test_version:"8.5.1000.0000", test_version2:"8.5.2000.0000"))register_host_detail(name:app, value:cpe + ":8.5.1", desc:SCRIPT_DESC);
      else if (version_in_range(version:val[1], test_version:"14.0.8050.1202", test_version2:"15.0.0000.0000"))register_host_detail(name:app, value:"cpe:/a:microsoft:live_messenger:9.0", desc:SCRIPT_DESC);
      else register_host_detail(name:app, value:"cpe:/a:microsoft:windows_live_messenger", desc:SCRIPT_DESC);
    }
    if ("MSN Messenger" >< val[0]){
      cpe = "cpe:/a:microsoft:msn_messenger";
      if (version_in_range(version:val[1], test_version:"1.0.0.0", test_version2:"2.0.0.0"))register_host_detail(name:app, value:cpe + ":1.0", desc:SCRIPT_DESC);
      else if (version_in_range(version:val[1], test_version:"2.0.0.0", test_version2:"2.2.0.0"))register_host_detail(name:app, value:cpe + ":2.0", desc:SCRIPT_DESC);
      else if (version_in_range(version:val[1], test_version:"2.2.0.0", test_version2:"3.0.0.0"))register_host_detail(name:app, value:cpe + ":2.2", desc:SCRIPT_DESC);
      else if (version_in_range(version:val[1], test_version:"3.0.0.0", test_version2:"3.6.0.0"))register_host_detail(name:app, value:cpe + ":3.0", desc:SCRIPT_DESC);
      else if (version_in_range(version:val[1], test_version:"3.6.0.0", test_version2:"4.0.0.0"))register_host_detail(name:app, value:cpe + ":3.6", desc:SCRIPT_DESC);
      else if (version_in_range(version:val[1], test_version:"4.0.0.0", test_version2:"4.5.0.0"))register_host_detail(name:app, value:cpe + ":4.0", desc:SCRIPT_DESC);
      else if (version_in_range(version:val[1], test_version:"4.5.0.0", test_version2:"4.6.0.0"))register_host_detail(name:app, value:cpe + ":4.5", desc:SCRIPT_DESC);
      else if (version_in_range(version:val[1], test_version:"4.6.0.0", test_version2:"4.7.0.0"))register_host_detail(name:app, value:cpe + ":4.6", desc:SCRIPT_DESC);
      else if (version_in_range(version:val[1], test_version:"4.7.0.0", test_version2:"4.8.0.0"))register_host_detail(name:app, value:cpe + ":4.7", desc:SCRIPT_DESC);
      else if (version_in_range(version:val[1], test_version:"6.0.0.0", test_version2:"6.1.0.0"))register_host_detail(name:app, value:cpe + ":6.0", desc:SCRIPT_DESC);
      else if (version_in_range(version:val[1], test_version:"6.1.0.0", test_version2:"6.2.0.0"))register_host_detail(name:app, value:cpe + ":6.1", desc:SCRIPT_DESC);
      else register_host_detail(name:app, value:cpe + "_service", desc:SCRIPT_DESC);
    }
    if ("Microsoft Commerce Server" >< val[0]){
      cpe = "cpe:/a:microsoft:commerce_server";
      if("Microsoft Commerce Server 2000 Service Pack 1" >< val[0])
      {
        register_host_detail(name:app, value:cpe + ":2000:sp1", desc:SCRIPT_DESC);
        mcssp = 1;
      }
      else if(!mcssp && "Microsoft Commerce Server 2000" >< val[0])register_host_detail(name:app, value:cpe + ":2000", desc:SCRIPT_DESC);
      else if("Microsoft Commerce Server 2002 Service Pack 1" >< val[0])
      {
        register_host_detail(name:app, value:cpe + ":2002:sp1", desc:SCRIPT_DESC);
        mcssp = 1;
      }
      else if(!mcssp && "Microsoft Commerce Server 2002" >< val[0])register_host_detail(name:app, value:cpe + ":2002", desc:SCRIPT_DESC);
      else if (!mcssp)register_host_detail(name:app, value:"Microsoft Commerce Server 2002", desc:SCRIPT_DESC);
    }
    if(val[0] =~ '^Microsoft Forefront Unified Access Gateway.*$'){
      cpe = "cpe:/a:microsoft:forefront_unified_access_gateway:2010";
      if (version_in_range(version:val[1], test_version:"4.0.1152.0", test_version2:"4.0.1152.150"))register_host_detail(name:app, value:"cpe:/a:microsoft:forefront_unified_access_gateway:2010", desc:SCRIPT_DESC);
      if (version_in_range(version:val[1], test_version:"4.0.1152.150", test_version2:"4.0.1269.250"))register_host_detail(name:app, value:cpe + ":update1", desc:SCRIPT_DESC);
      if (version_is_greater_equal(version:val[1], test_version:"4.0.1269.250"))register_host_detail(name:app, value:cpe + ":update2", desc:SCRIPT_DESC);

    }
    if(val[0] =~ '^Microsoft Visual Studio .NET .* 2000.*'){
      cpe = "cpe:/a:microsoft:visual_studio_.net:2000";
      register_host_detail(name:app, value:"cpe:/a:microsoft:visual_studio_.net:2000", desc:SCRIPT_DESC);
    }
    if(val[0] =~ '^Microsoft Visual Studio .NET .* 2002.*'){
      cpe = "cpe:/a:microsoft:visual_studio_.net:2002";
      if (vsdotnet2k2sp)register_host_detail(name:app, value:cpe + ":sp1", desc:SCRIPT_DESC);
      else register_host_detail(name:app, value:"cpe:/a:microsoft:visual_studio_.net:2002", desc:SCRIPT_DESC);
    }
    if(val[0] =~ '^Microsoft Visual Studio .NET .* 2003.*'){
      cpe = "cpe:/a:microsoft:visual_studio_.net:2003";
      if (vsdotnet2k3sp)register_host_detail(name:app, value:cpe + ":sp1", desc:SCRIPT_DESC);
      else register_host_detail(name:app, value:"cpe:/a:microsoft:visual_studio_.net:2003", desc:SCRIPT_DESC);
    }
  }
}
wmi_close(wmi_handle:handle);
wmi_close(wmi_handle:handlereg);
exit(0);
