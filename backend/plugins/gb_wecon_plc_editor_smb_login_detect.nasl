# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.107561");
  script_version("2021-11-24T13:00:16+0000");
  script_tag(name:"last_modification", value:"2021-11-25 11:06:48 +0000 (Thu, 25 Nov 2021)");
  script_tag(name:"creation_date", value:"2019-02-12 14:28:04 +0100 (Tue, 12 Feb 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("WECON PLC Editor Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"SMB login-based detection of WECON PLC Editor.");

  script_xref(name:"URL", value:"http://www.we-con.com.cn/");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch)
  exit(0);

if("x86" >< os_arch) {
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
} else if("x64" >< os_arch) {
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                       "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if(isnull(key_list))
  exit(0);

foreach key(key_list) {
  foreach item(registry_enum_keys(key:key)) {

    app_name = registry_get_sz(key:key + item, item:"DisplayName");

    # e.g.: Wecon PLC Editor version 1.3.5
    # nb: The trailing space is expected to not detect Wecon PLC Editor2 (See gsf/gb_wecon_plc_editor_2_smb_login_detect.nasl).
    if(!app_name || app_name !~ "Wecon PLC Editor ")
      continue;

    concluded  = "Registry Key:   " + key + item + '\n';
    concluded += "DisplayName:    " + app_name;
    location = "unknown";
    version = "unknown";

    loc = registry_get_sz(key:key + item, item:"InstallLocation");
    if(loc)
      location = loc;

    # n.b. PLC Editor V1.3.3 U once existed but is not available anymore for testing CVE-2018-14792
    #      It is not clear what 'DisplayVersion' might have contained.
    #      To get "cpe:/a:we-con:plc_editor:1.3.3u" the following is done:
    if(ver = registry_get_sz(key:key + item, item:"DisplayVersion")) {
      lowver = tolower(ver);
      vers = ereg_replace(pattern:" ", string:lowver, replace:"");
      version = vers;
      concluded += '\nDisplayVersion: ' + vers;
    }

    set_kb_item(name:"wecon/plc_editor/detected", value:TRUE);
    set_kb_item(name:"wecon/plc_editor/smb-login/detected", value:TRUE);

    register_and_report_cpe(app:app_name, ver:version, concluded:concluded, base:"cpe:/a:we-con:plc_editor:",
                            expr:"^([0-9.u]+)", insloc:location, regService:"smb-login", regPort:0);
    exit(0);
  }
}

exit(0);