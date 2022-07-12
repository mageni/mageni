##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phoenix_contact_automationworx_software_suite_detect_win.nasl 12654 2018-12-04 15:33:53Z mmartin $
#
# PHOENIX CONTACT AUTOMATIONWORX Software Suite Version Detection (Windows)
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH, http//www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.107344");
  script_version("$Revision: 12654 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:33:53 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-12-04 16:23:37 +0100 (Tue, 04 Dec 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("PHOENIX CONTACT AUTOMATIONWORX Software Suite Version Detection (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"This script detects the installed version
  of PHOENIX CONTACT AUTOMATIONWORX Software Suite for Windows.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");
include("secpod_smb_func.inc");
include("version_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if (!os_arch)
  exit(0);

if ("x86" >< os_arch) {
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
} else if ("x64" >< os_arch) {
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                       "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if (isnull(key_list)) exit(0);

suite_exists = FALSE;

foreach key (key_list) {
  foreach item (registry_enum_keys(key:key)) {

    appName = registry_get_sz(key:key + item, item:"DisplayName");

    if(!appName || appName !~ "AUTOMATIONWORX") continue;
    version = "unknown";
    location = "unknown";

    loc = registry_get_sz(key:key + item, item:"InstallLocation");
    if(loc) location = loc;

    vers = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(vers){
      version = vers;
      concluded += " " + vers;
    }

    set_kb_item(name:"phoenixcontact-software/automationworx_software_suite/win/detected", value:TRUE);
    set_kb_item(name:"phoenixcontact-software/automationworx_software_suite/win/ver", value:version);

    register_and_report_cpe(app:"PHOENIX CONTACT " + appName, ver:version, concluded:concluded,
    base:"cpe:/a:phoenixcontact-software:automationworx_software_suite:", expr:"^([0-9.]+)", insloc:location);
  }
    suite_exists = TRUE;
}

if(!suite_exists) exit(0);

key_list = make_list("SOFTWARE\WOW6432Node\Phoenix Contact\Software Suite\", "SOFTWARE\Phoenix Contact\Software Suite\");

foreach key(key_list) {
  foreach item(registry_enum_keys(key:key)) {
    foreach subkey(registry_enum_keys(key:key + item)) {

      appName = registry_get_sz(key:key + item + "\" + subkey, item:"ProductName");
      if(!appName) continue;
      version = "unknown";
      location = "unknown";
      match = eregmatch(string:appName, pattern:'([^0-9]+) ([0-9.]+)$');
      name = match[1];
      version = match[2];
      concluded = "PHOENIX CONTACT " + match[0];
      lower_name = tolower(name);
      name = ereg_replace(pattern:' ', string:lower_name, replace:'_');
      if(get_kb_item("phoenixcontact-software/" + name + "/win/detected") == TRUE) continue;

      set_kb_item(name:"phoenixcontact-software/" + name + "/win/detected", value:TRUE);
      set_kb_item(name:"phoenixcontact-software/" + name + "/win/ver", value:version);
      register_and_report_cpe(app:"PHOENIX CONTACT " + appName, ver:version, concluded:concluded,
      base:"cpe:/a:phoenixcontact-software:" + name + ":", expr:"^([0-9.]+)", insloc:location);
    }
  }
}

exit(0);
