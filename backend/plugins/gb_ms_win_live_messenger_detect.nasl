###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_win_live_messenger_detect.nasl 14329 2019-03-19 13:57:49Z cfischer $
#
# Microsoft Windows Live Messenger Client Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800331");
  script_version("$Revision: 14329 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:57:49 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-01-08 07:43:30 +0100 (Thu, 08 Jan 2009)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Microsoft Windows Live Messenger Client Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of Microsoft Windows Live Messenger.

  The script logs in via smb, searches for Microsoft Windows Live Messenger
  in the registry and gets the version from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("version_func.inc");
include("host_details.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

osArch = get_kb_item("SMB/Windows/Arch");
if(!osArch){
  exit(0);
}

if("x86" >< osArch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

else if("x64" >< osArch){
 key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                      "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

checkduplicate = ""; # nb: To make openvas-nasl-lint happy...
checkduplicate_path = "";

foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    appName = registry_get_sz(key:key + item, item:"DisplayName");

    if("Windows Live Messenger" >< appName)
    {
      livemgrVer = registry_get_sz(key:key + item, item:"DisplayVersion");

      appLoc = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!appLoc){
        appLoc = "Couldn find the install location from registry";
      }

      if(livemgrVer)
      {
        if (livemgrVer + ", " >< checkduplicate && appLoc + ", " >< checkduplicate_path){
          continue;
        }
        ##Assign detected version value to checkduplicate so as to check in next loop iteration
        checkduplicate  += livemgrVer + ", ";
        checkduplicate_path += appLoc + ", ";

        set_kb_item(name:"MS/LiveMessenger/Installed", value:TRUE);

        ## 64 bit apps on 64 bit platform
        if("x64" >< osArch && "Wow6432Node" >!< key)  {
          set_kb_item(name:"MS/LiveMessenger64/Ver", value:livemgrVer);
          register_and_report_cpe( app:appName, ver:livemgrVer, base:"cpe:/a:microsoft:windows_live_messenger:x64:", expr:"^([0-9.]+)", insloc:appLoc );
        } else {
          set_kb_item(name:"MS/LiveMessenger/Ver", value:livemgrVer);
          register_and_report_cpe( app:appName, ver:livemgrVer, base:"cpe:/a:microsoft:windows_live_messenger:", expr:"^([0-9.]+)", insloc:appLoc );
        }
      }
    }

    # Messenger Plus!
    if("Messenger Plus!" >< appName)
    {
      msgPlusVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      plusPath = registry_get_sz(key:key + item, item:"UninstallString");
      plusPath = eregmatch(pattern:'"(.*)"', string:plusPath);

      if(isnull(msgPlusVer) && plusPath[1])
      {
        file = plusPath[1];
        if("Uninstall.exe" >< file)
        {
          file -= "Uninstall.exe";
          msgPlusVer =  fetch_file_version(sysPath:file, file_name:"MPTools.exe");

          if(!msgPlusVer){
            msgPlusVer = fetch_file_version(sysPath:file, file_name:"WinksViewer.exe");
          }
        }
        else if("MsgPlus.exe" >< file)
        {
          file -= "MsgPlus.exe";
          msgPlusVer = fetch_file_version(sysPath:file, file_name:"MsgPlus.exe");
        }
      }

      if(!isnull(msgPlusVer))
      {
        set_kb_item(name:"MS/MessengerPlus/Path", value:plusPath[1]);
        set_kb_item(name:"MS/MessengerPlus/Installed", value:TRUE);

        ## 64 bit apps on 64 bit platform
        if("x64" >< osArch && "Wow6432Node" >!< key) {
          set_kb_item(name:"MS/MessengerPlus64/Ver", value:msgPlusVer);
          register_and_report_cpe( app:appName, ver:msgPlusVer, base:"cpe:/a:microsoft:messenger_plus%21_live:x64:", expr:"^([0-9.]+)", insloc:plusPath[1] );
        } else {
          set_kb_item(name:"MS/MessengerPlus/Ver", value:msgPlusVer);
          register_and_report_cpe( app:appName, ver:msgPlusVer, base:"cpe:/a:microsoft:messenger_plus%21_live:", expr:"^([0-9.]+)", insloc:plusPath[1] );
        }
      }
    }
  }
}
