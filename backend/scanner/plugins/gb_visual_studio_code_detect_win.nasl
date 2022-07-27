# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814768");
  script_version("$Revision: 14182 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 14:01:57 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-03-13 18:05:59 +0530 (Wed, 13 Mar 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Microsoft Visual Studio Code Version Detection (Windows)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"This script detects the installed version
  of Microsoft Visual Studio Code for Windows.");

  script_tag(name:"qod_type", value:"registry");
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("secpod_smb_func.inc");
include("version_func.inc");
include("cpe.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if ("x86" >< os_arch) {
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
} else if ("x64" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                       "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if (isnull(key_list)) exit(0);

foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    appName = registry_get_sz(key:key + item, item:"DisplayName");
    if("Microsoft Visual Studio Code" >< appName)
    {

      version = registry_get_sz(key:key + item, item:"DisplayVersion");
      if(!version){
        version = "Unknown";
      }

      set_kb_item(name:"microsoft_visual_studio_code/version", value:version);
      set_kb_item(name:"microsoft_visual_studio_code/installed", value:TRUE);

      location = registry_get_sz(key:key + item, item:"Inno Setup: App Path");
      if(!location){
        location = "Unable to find the install location from registry";
      }
      else {
        set_kb_item(name:"microsoft_visual_studio_code/location", value:location);
      }
      register_and_report_cpe(app:appName, ver:version, concluded:appName + " " + version,
                          base:"cpe:/a:microsoft:visual_studio_code:", expr:"^([0-9.]+)", insloc:location, regService:"smb-login", regPort:0);
      exit(0);
    }
  }
}
exit(0);
