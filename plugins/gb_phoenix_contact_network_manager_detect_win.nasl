##############################################################################
# OpenVAS Vulnerability Test
#
# PHOENIX CONTACT FL Network Manager Version Detection (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.107389");
  script_version("2019-05-27T09:44:11+0000");
  script_tag(name:"last_modification", value:"2019-05-27 09:44:11 +0000 (Mon, 27 May 2019)");
  script_tag(name:"creation_date", value:"2018-12-04 10:16:11 +0100 (Tue, 04 Dec 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("PHOENIX CONTACT FL Network Manager Version Detection (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"This script detects the installed version
  of PHOENIX CONTACT FL Network Manager for Windows.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");
include("secpod_smb_func.inc");
include("version_func.inc");
include("http_func.inc"); # nb: For registry_enum_values

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

foreach key (key_list) {
  foreach item (registry_enum_keys(key:key)) {

  # "FL Network Manager" without any version
    appName = registry_get_sz(key:key + item, item:"DisplayName");
    version = "unknown";
    location = "unknown";

    if(!appName || appName !~ "FL Network Manager") continue;
    # item:"DisplayVersion" contains file version which is different from Product version
    ver = eregmatch(string:appName, pattern:"([0-9.]+)" );
    if(ver[1]) version = ver[1];
    concluded = "Phoenix Contact " +appName;
    location = "unknown";

    loc = registry_get_sz(key:key + item, item:"InstallLocation");
    if(loc) location = loc;

  set_kb_item(name:"phoenixcontact/fl_network_manager/win/detected", value:TRUE);
  set_kb_item(name:"phoenixcontact/fl_network_manager/win/ver", value:version);

  register_and_report_cpe(app:"Phoenix Contact " +appName , ver:version, concluded:concluded,base:"cpe:/a:phoenixcontact-software:fl_network_manager:", expr:"^([0-9.]+)", insloc:location, regService:"smb-login", regPort:0);
  exit(0);
  }
}
exit(0);
