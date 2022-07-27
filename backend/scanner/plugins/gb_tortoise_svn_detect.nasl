###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tortoise_svn_detect.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# TortoiseSVN Version Detection
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2014-05-28
# Updated according to CR57 and to support 32 and 64 bit.
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801289");
  script_version("$Revision: 11279 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2010-09-21 16:43:08 +0200 (Tue, 21 Sep 2010)");
  script_tag(name:"qod_type", value:"registry");
  script_name("TortoiseSVN Version Detection");


  script_tag(name:"summary", value:"Detects the installed version of TortoiseSVN on Windows.

The script logs in via smb, searches for TortoiseSVN in the
registry and gets the version.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

if(!registry_key_exists(key:"SOFTWARE\TortoiseSVN\")){
  exit(0);
}

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

## 32bit app can't be installed on 64bit OS
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  AppName = registry_get_sz(key:key + item, item:"DisplayName");
  if("TortoiseSVN" >< AppName)
  {
    AppVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(AppVer != NULL)
    {
      insLoc = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!insLoc){
        insLoc = "Could not find the install location from registry";
      }

      set_kb_item(name:"TortoiseSVN/Installed", value:TRUE);

      if("64" >< os_arch) {
        set_kb_item(name:"TortoiseSVN64/Ver", value:AppVer);
        register_and_report_cpe( app:AppName, ver:AppVer, concluded:AppVer, base:"cpe:/a:tigris:tortoisesvn:x64:", expr:"^([0-9.]+)", insloc:insLoc );
      } else {
        set_kb_item(name:"TortoiseSVN/Ver", value:AppVer);
        register_and_report_cpe( app:AppName, ver:AppVer, concluded:AppVer, base:"cpe:/a:tigris:tortoisesvn:", expr:"^([0-9.]+)", insloc:insLoc );
      }
    }
  }
}
