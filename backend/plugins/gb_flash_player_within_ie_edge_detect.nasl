###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_flash_player_within_ie_edge_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Adobe Flash Player Within Microsoft IE And Microsoft Edge Detection
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.810611");
  script_version("$Revision: 11885 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-10 12:18:44 +0530 (Fri, 10 Mar 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Adobe Flash Player Within Microsoft IE And Microsoft Edge Detection");

  script_tag(name:"summary", value:"Detects the installed version of Adobe
  Flash within microsoft internet explorer and microsoft edge.

  The script logs in via smb, searches for file 'Flashplayerapp.exe' and gets
  version from the file.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_ms_ie_detect.nasl", "gb_microsoft_edge_detect.nasl");
  script_mandatory_keys("MS/IE_or_EDGE/Installed");
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

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

if("x86" >< os_arch)
{
  fileVer = fetch_file_version(sysPath:sysPath, file_name:"System32\Flashplayerapp.exe");
  insloc = sysPath + "\System32";
}
else if ("x64" >< os_arch)
{
  fileVer = fetch_file_version(sysPath:sysPath, file_name:"SysWOW64\Flashplayerapp.exe");
  insloc = sysPath + "\SysWOW64";
}

##Exit if 'Flashplayerapp.exe' version not available
if(!fileVer){
  exit(0);
}

##Both IE and Edge are using same flashplayer file
##Either one can be used to set version
ie = get_kb_item("MS/IE/Installed");
if(ie)
{
  set_kb_item(name:"AdobeFlashPlayer/IE/Ver", value:fileVer);
  set_kb_item( name:"AdobeFlash/IE_or_EDGE/Installed", value:TRUE );
  base_cpe = "cpe:/a:adobe:flash_player_internet_explorer";
}
else
{
  ##Both IE and Edge can be installed at same time but both uses same file
  edge = get_kb_item("MS/Edge/Installed");
  if(edge)
  {
    set_kb_item(name:"AdobeFlashPlayer/EDGE/Ver", value:fileVer);
    set_kb_item( name:"AdobeFlash/IE_or_EDGE/Installed", value:TRUE );
    base_cpe = "cpe:/a:adobe:flash_player_edge";
  }
}
cpe = build_cpe(value:fileVer, exp:"^([0-9.]+)", base:base_cpe + ":");
if(isnull(cpe)){
  cpe = base_cpe;
}

register_product(cpe:cpe, location:insloc);

log_message(data: build_detection_report(app: "Flash Player Within IE/EDGE",
                                         version: fileVer,
                                         install: insloc,
                                         cpe: cpe,
                                         concluded: fileVer));
exit(0);
