###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_realplayer_detect_win.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# RealPlayer Application Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Update By:  Rachana Shetty <srachana@secpod.com> on 2012-12-28
# Updated to detect Older version and according to CR-57
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2014-06-26
# Updated plugin to support 32 and 64 bit
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
  script_oid("1.3.6.1.4.1.25623.1.0.800508");
  script_version("$Revision: 11279 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-02-18 15:32:11 +0100 (Wed, 18 Feb 2009)");
  script_tag(name:"qod_type", value:"registry");
  script_name("RealPlayer Application Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of RealNetworks RealPlayer.

The script logs in via smb, searches for RealPlayer in the registry and
gets the path for 'realplayer.exe' file in registry and version from
realplayer.exe file.");

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
include("host_details.inc");
include("version_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths";
}

## Presently Adobe RoboHelp 64bit application is not available
else if("x64" >< os_arch){
  key =  "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\App Paths";
}

if(!registry_key_exists(key:key)){
  exit(0);
}

foreach file (make_list("\RealPlay.exe", "\realplay.exe"))
{
  rpFile = registry_get_sz(key:key + file, item:"Path");
  if(!rpFile)
    continue;
}

if(!rpFile){
  exit(0);
}

if(file =~ "realplay.exe")
{
  oldPath = eregmatch(pattern:"(.*);", string:rpFile);
  if(oldPath && oldPath[0]){
    rpFile =  oldPath[1];
  }
}

rpVer = fetch_file_version(sysPath: rpFile, file_name:"realplay.exe");
if(isnull(rpVer))
   exit(0);

if("RealPlayer Enterprise" >< rpFile)
{
  set_kb_item(name:"RealPlayer/RealPlayer_or_Enterprise/Win/Installed", value:TRUE);
  set_kb_item(name:"RealPlayer-Enterprise/Win/Ver", value:rpVer);
  cpe = build_cpe(value:rpVer, exp:"^([0-9.]+)", base:"cpe:/a:realnetworks:realplayer:" +
                               rpVer + "::enterprise");
}
else
{
  set_kb_item(name:"RealPlayer/RealPlayer_or_Enterprise/Win/Installed", value:TRUE);
  set_kb_item(name:"RealPlayer/Win/Ver", value:rpVer);
  cpe = build_cpe(value:rpVer, exp:"^([0-9.]+)", base:"cpe:/a:realnetworks:realplayer:");
}

if(isnull(cpe))
  cpe = 'cpe:/a:realnetworks:realplayer';

register_product(cpe:cpe, location:rpFile);

log_message(data: build_detection_report(app:"RealNetworks RealPlayer" ,
                                         version: rpVer, install: rpFile, cpe:cpe, concluded:rpVer));
