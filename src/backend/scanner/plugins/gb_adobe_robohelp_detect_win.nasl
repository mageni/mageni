###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_robohelp_detect_win.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# Adobe RoboHelp Version Detection (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2014-06-17
# Updated plugin completely according to CR57 and to support 32 and 64 bit
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803770");
  script_version("$Revision: 11279 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-10-17 15:40:00 +0530 (Thu, 17 Oct 2013)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe RoboHelp Version Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of Adobe RoboHelp on Windows.

The script logs in via smb, searches for Adobe RoboHelp in the registry
and gets the version from registry.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("cpe.inc");
include("smb_nt.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

if(!registry_key_exists(key:"SOFTWARE\Adobe\RoboHelp"))
{
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\Adobe\RoboHelp")){
    exit(0);
  }
}

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

## Presently Adobe RoboHelp 64bit application is not available
else if("x64" >< os_arch){
  key =  "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  arhName = registry_get_sz(key:key + item, item:"DisplayName");

  if("Adobe RoboHelp" >< arhName)
  {
    arhInsPath = registry_get_sz(key:key + item, item:"DisplayIcon");
    if(arhInsPath){
      arhInsPath = arhInsPath - "\ARPRobohelp.ico";
    } else {
      arhInsPath = "Could not find the install location from registry";
    }

    arhVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(arhVer) {
      if("Server" >< arhName) {
        set_kb_item(name:"Adobe/RoboHelp/Server/Win/Ver", value: arhVer);
        register_and_report_cpe( app:arhName, ver:arhVer, concluded:arhVer, base:"cpe:/a:adobe:robohelp_server:", expr:"^([0-9.]+)", insloc:arhInsPath );
      } else {
        set_kb_item(name:"Adobe/RoboHelp/Win/Ver", value: arhVer);
        set_kb_item(name:"Adobe/RoboHelp/Win/InstallPath", value: arhInsPath);
        register_and_report_cpe( app:arhName, ver:arhVer, concluded:arhVer, base:"cpe:/a:adobe:robohelp:", expr:"^([0-9.]+)", insloc:arhInsPath );
      }
    }
  }
}
