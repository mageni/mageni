###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apple_itunes_detection_win_900123.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# Apple iTunes Version Detection (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.900123");
  script_version("$Revision: 11279 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2008-10-24 15:11:55 +0200 (Fri, 24 Oct 2008)");
  script_name("Apple iTunes Version Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of
  Apple iTunes on Windows.

  The script logs in via smb, searches for Apple iTunes in the registry
  and gets the version from registry.");

  script_tag(name:"qod_type", value:"registry");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 SecPod");
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

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  ituneName = registry_get_sz(key:key + item, item:"DisplayName");
  if(ituneName =~ "^(iTunes)$")
  {
    insPath = registry_get_sz(key:key + item, item:"InstallLocation");
    if(!insPath){
      insPath = "Could not find the install Location from registry";
    }

    ituneVer = registry_get_sz(key: key + item, item:"DisplayVersion");
    if(ituneVer)
    {
      set_kb_item(name:"iTunes/Win/Installed", value:TRUE);
      set_kb_item(name:"iTunes/Win/Ver", value:ituneVer);
      register_and_report_cpe( app:ituneName, ver:ituneVer, base:"cpe:/a:apple:itunes:", expr:"^([0-9.]+)", insloc:insPath );

      if("64" >< os_arch) {
        set_kb_item(name:"iTunes/Win64/Ver", value:ituneVer);
        register_and_report_cpe( app:ituneName, ver:ituneVer, base:"cpe:/a:apple:itunes:x64:", expr:"^([0-9.]+)", insloc:insPath );
      }

    }
    exit(0);
  }
}
