##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_win_media_player_detect_900173.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Updated By: Shakeel <bshakeel@secpod.com> on 2014-07-15
# To support 32 and 64 bit.
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900173");
  script_version("$Revision: 11279 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2008-11-11 15:58:44 +0100 (Tue, 11 Nov 2008)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Microsoft Windows Media Player Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of Windows Media Player.

The script logs in via smb, searches for Windows Media Player CLSID
in the registry, gets version and set it in the KB item.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 SecPod");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

## Key is same irrespective of architecture
  key_list = make_list("SOFTWARE\Microsoft\Active setup\Installed Components\");

if(isnull(key_list)){
  exit(0);
}

foreach key (key_list)
{
  # CLSID matches with Win Media Player versions 7 or above
  wmpVer = registry_get_sz(key:key + "{6BF52A52-394A-11d3-B153-00C04F79FAA6}",
                         item:"Version");
  if(!wmpVer)
  {
    wmpVer = registry_get_sz(key:key + "{22d6f312-b0f6-11d0-94ab-0080c74c7e95}",
                           item:"Version");
  }

  if(!wmpVer){
    exit(0);
  }

  # For replacing comma (,) with dot (.)
  wmpVer = ereg_replace(string:wmpVer, pattern:",", replace:".");

  pathKey = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\wmplayer.exe";
  if(registry_key_exists(key:pathKey))
  {
    insloc = registry_get_sz(key:pathKey, item : "Path");
    insloc = ereg_replace(string:insloc, pattern:"%", replace:"");
  }

  if(!insloc)
    insloc = "Could not find the install location from registry";

  set_kb_item(name:"Win/MediaPlayer/Ver", value:wmpVer);

  cpe = build_cpe(value:wmpVer, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:windows_media_player:");
  if(isnull(cpe))
    cpe = "cpe:/a:microsoft:windows_media_player";

  ## 64 bit apps on 64 bit platform
  if("x64" >< os_arch && "x86" >!< insloc)
  {
    set_kb_item(name:"Win/MediaPlayer64/Ver", value:wmpVer);

    cpe = build_cpe(value:wmpVer, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:windows_media_player:x64:");
    if(isnull(cpe))
      cpe = "cpe:/a:microsoft:windows_media_player:x64";
  }

  register_product(cpe:cpe, location:insloc);

  log_message(data: build_detection_report(app: "Microsoft Windows Media Player",
                                           version: wmpVer,
                                           install: insloc,
                                           cpe: cpe,
                                           concluded: wmpVer));

}
