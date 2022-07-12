###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_media_player_classic_detect.nasl 10890 2018-08-10 12:30:06Z cfischer $
#
# Gabest Media Player Classic Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Updated By: Shakeel <bshakeel@secpod.com> on 2014-05-20
# According to CR57 and to support 32 and 64 bit.
#
# Copyright:
# Copyright (C) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900947");
  script_version("$Revision: 10890 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 14:30:06 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-09-18 08:01:03 +0200 (Fri, 18 Sep 2009)");
  script_name("Gabset Media Player Classic Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"This script detects the installed version of Gabset Media Player
  Classic and sets the result in KB.

  The script logs in via smb, searches for Media Player Classic in the registry,
  gets the version from registry.");

  script_tag(name:"qod_type", value:"registry");

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
  key_list = make_list("SOFTWARE\Gabest\Media Player Classic\");
}
else if("x64" >< os_arch){
  key_list = make_list("SOFTWARE\Wow6432Node\Gabest\Media Player Classic\");
}

if(isnull(key_list)){
  exit(0);
}

foreach key(key_list){

  mpcPath = registry_get_sz(key:key, item:"ExePath");

  if(mpcPath){

    cpath_list = split(mpcPath, sep:"\", keep:FALSE);
    exeName = cpath_list[max_index(cpath_list)-1];
    mpcVer = fetch_file_version(sysPath:mpcPath - exeName, file_name:exeName);
    mpcPath = mpcPath - exeName ;

    if(!mpcVer) mpcVer = "unknown";

    if(mpcVer) {
      set_kb_item(name:"MediaPlayerClassic/Ver", value:mpcVer);

      cpe = build_cpe(value:mpcVer, exp:"^([0-9.]+)", base:"cpe:/a:rob_schultz:media_player_classic:");
      if(isnull(cpe))
        cpe = "cpe:/a:rob_schultz:media_player_classic";

      register_product(cpe:cpe, location:mpcPath);

      log_message(data:build_detection_report(app:"Gabest Media Player Classic",
                                              version:mpcVer,
                                              install:mpcPath,
                                              cpe:cpe,
                                              concluded:mpcVer));
    }
  }
}
