# Copyright (C) 2018 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.107409");
  script_version("2022-01-12T11:19:42+0000");
  script_tag(name:"last_modification", value:"2022-01-13 11:12:56 +0000 (Thu, 13 Jan 2022)");
  script_tag(name:"creation_date", value:"2018-12-08 12:44:41 +0100 (Sat, 08 Dec 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SolarWinds Server & Application Monitor (SAM) Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"SMB login-based detection of SolarWinds Server & Application
  Monitor (SAM).");

  script_xref(name:"URL", value:"https://www.solarwinds.com/server-application-monitor");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if (!os_arch)
  exit(0);

if ("x86" >< os_arch) {
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
  location = "C:\Program Files\SolarWinds\Orion";
} else if ("x64" >< os_arch) {
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                       "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
  location = "C:\Program Files (x86)\SolarWinds\Orion";
}

if (isnull(key_list))
  exit(0);

foreach key (key_list) {
  foreach item (registry_enum_keys(key:key)) {

    app_name = registry_get_sz(key:key + item, item:"DisplayName");
    if(!app_name || app_name !~ "SolarWinds Server & Application Monitor")
      continue;

    version = "unknown";
    concluded = "Registry Key:   " + key + item + '\n';
    concluded += "DisplayName:    " + app_name;

    # nb: wrong version in "DisplayVersion"
    vers = eregmatch(string:app_name, pattern:"([0-9.]+)");
    if(vers[1])
      version = vers[1];

    set_kb_item(name:"solarwinds/sam/detected", value:TRUE);
    set_kb_item(name:"solarwinds/sam/smb-login/detected", value:TRUE);

    register_and_report_cpe(app:app_name, ver:version, concluded:concluded,
                            base:"cpe:/a:solarwinds:server_and_application_monitor:",
                            expr:"^([0-9.]+)", insloc:location, regService:"smb-login", regPort:0);

    exit(0);
  }
}

exit(0);
