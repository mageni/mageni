##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dameware_remote_support_detect_win.nasl 12753 2018-12-11 08:48:01Z mmartin $
#
# DameWare Remote Support Version Detection (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.107383");
  script_version("$Revision: 12753 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-11 09:48:01 +0100 (Tue, 11 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-11-26 17:23:16 +0100 (Mon, 26 Nov 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("DameWare Remote Support Version Detection (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"This script detects the installed version
  of DameWare Remote Support for Windows.");

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

foreach key (key_list) {
  foreach item (registry_enum_keys(key:key)) {

  # "DameWare" without any version
    appName = registry_get_sz(key:key + item, item:"DisplayName");
    version = "unknown";
    location = "unknown";

    if(!appName || appName !~ "DameWare Remote Support") continue;
    version = "unknown";
    concluded = appName;
    location = "unknown";

    loc = registry_get_sz(key:key + item, item:"InstallLocation");
    if(loc) location = loc;

  # 12.0.5.6002  registry item:"DisplayVersion" has 12.0.6002.5 in it.
    version = fetch_file_version(sysPath:location, file_name:"DNTU.exe");
    concluded += " " + version;
  set_kb_item(name:"dameware/remote_support/win/detected", value:TRUE);
  set_kb_item(name:"dameware/remote_support/win/ver", value:version);

  register_and_report_cpe(app:"DameWare Remote Support" , ver:version, concluded:concluded,
                          base:"cpe:/a:dameware:remote_support:", expr:"^([0-9.]+)", insloc:location, regService:"smb-login", regPort:0);
  exit(0);
  }
}
exit(0);
