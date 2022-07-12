###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_seamonkey_detect_win.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# Mozilla Seamonkey Version Detection (Windows)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Upgrade to detect the latest version
# - By Sharath S <sharaths@secpod.com> On 2009-11-02 #5567
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2014-07-02
# Updated to support 32 and 64 bit
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800016");
  script_version("$Revision: 11279 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2008-10-06 13:07:14 +0200 (Mon, 06 Oct 2008)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Mozilla SeaMonkey Version Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of Mozilla SeaMonkey on Windows.

The script logs in via smb, searches for Mozilla SeaMonkey in the registry
and gets the version from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 SecPod");
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

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key = "SOFTWARE";
}

## Presently 64bit application is not available
else if("x64" >< os_arch){
  key =  "SOFTWARE\Wow6432Node";
}

seaVer = registry_get_sz(key: key + "\mozilla.org\SeaMonkey",
                               item:"CurrentVersion");
if(!seaVer){
  seaVer = registry_get_sz(key: key + "\Mozilla\SeaMonkey",
                                 item:"CurrentVersion");
}

seaVer = eregmatch(pattern:"[0-9.]+", string:seaVer);
seaVer = seaVer[0];

# To get the appName and Path
key = key + "\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  appName = registry_get_sz(key:key + item, item:"DisplayName");

  if("SeaMonkey" >< appName)
  {
    if(!seaVer)
      seaVer = registry_get_sz(key:key + item, item:"DisplayVersion");

    if(seaVer)
    {
      ## Not sure about the purpose of the below line
      if(seaVer <= 0)exit(0);

      insPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!insPath)
        insPath = "Could not find the install location";

      set_kb_item(name:"Seamonkey/Win/Ver", value: seaVer);
      set_kb_item( name:"Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed", value:TRUE );

      cpe = build_cpe(value: seaVer, exp:"^([0-9.]+([a-z0-9]+)?)", base:"cpe:/a:mozilla:seamonkey:");
      if(isnull(cpe))
        cpe = 'cpe:/a:mozilla:seamonkey';

      register_product(cpe:cpe, location:insPath);

      log_message(data: build_detection_report(app: appName,
                                               version: seaVer,
                                               install: insPath,
                                               cpe: cpe,
                                               concluded: seaVer));
    }
  }
}
