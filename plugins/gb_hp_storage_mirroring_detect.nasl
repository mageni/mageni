###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_storage_mirroring_detect.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# HP StorageWorks Storage Mirroring Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2014-05-27
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
  script_oid("1.3.6.1.4.1.25623.1.0.801356");
  script_version("$Revision: 11279 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2010-06-15 06:05:27 +0200 (Tue, 15 Jun 2010)");
  script_name("HP StorageWorks Storage Mirroring Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"Detects the installed version of HP StorageWorks Storage Mirroring on Windows.

  The script logs in via smb, searches for HP Storage Mirroring in the
  registry and gets the version.");

  script_tag(name:"qod_type", value:"registry");

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
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

else if("x64" >< os_arch)
{
  key_list =  make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Wow6432Node\Windows\CurrentVersion\Uninstall\");
}

foreach key( key_list ) {

  foreach item( registry_enum_keys( key:key ) )
  {
    hpsmName  = registry_get_sz(key:key + item, item:"DisplayName");

    if("HP Storage Mirroring" >< hpsmName)
    {
      hpsmVer = registry_get_sz(key:key + item, item:"DisplayVersion");

      if(hpsmVer != NULL)
      {
        insLoc = registry_get_sz(key:key + item, item:"InstallLocation");
        if(!insLoc){
          insLoc = "Could not find the install location from registry";
        }

        set_kb_item(name:"HP/SWSM/Installed", value:TRUE);

        if("64" >< os_arch && "Wow6432Node" >!< key) {
          set_kb_item(name:"HP/SWSM64/Ver", value:hpsmVer);
          register_and_report_cpe( app:hpsmName, ver:hpsmVer, concluded:hpsmVer, base:"cpe:/a:hp:storageworks_storage_mirroring:x64:", expr:"^([0-9.]+)", insloc:insLoc );
        } else {
          set_kb_item(name:"HP/SWSM/Ver", value:hpsmVer);
          register_and_report_cpe( app:hpsmName, ver:hpsmVer, concluded:hpsmVer, base:"cpe:/a:hp:storageworks_storage_mirroring:", expr:"^([0-9.]+)", insloc:insLoc );
        }
      }
    }
  }
}
