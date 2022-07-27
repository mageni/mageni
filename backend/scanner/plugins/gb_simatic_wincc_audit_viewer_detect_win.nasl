###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_simatic_wincc_audit_viewer_detect_win.nasl 13710 2019-02-16 13:37:58Z mmartin $
#
# Siemens SIMATIC WinCC/Audit Viewer Version Detection (Windows)
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
#
# Copyright:
# Copyright (c) 2019 Greenbone Networks GmbH, http//www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.107481");
  script_version("$Revision: 13710 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-16 14:37:58 +0100 (Sat, 16 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-01-26 09:49:54 +0100 (Sat, 26 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Siemens SIMATIC WinCC/Audit Viewer Version Detection (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"Detects the installed version
  of Siemens SIMATIC WinCC/Audit Viewer for Windows

  This VT is a duplicate of the existing VT 'Siemens SIMATIC WinCC/Audit Viewer Version Detection (Windows)' (OID: 1.3.6.1.4.1.25623.1.0.107574).");

  script_xref(name:"URL", value:"https://w3.siemens.com/mcms/human-machine-interface/de/visualisierungssoftware/scada-wincc/wincc-optionen/wincc-audit/Seiten/Default.aspx");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");
include("secpod_smb_func.inc");
include("version_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch)
  exit(0);

if("x86" >< os_arch) {
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
} else if("x64" >< os_arch) {
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                       "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if(isnull(key_list)) exit(0);

foreach key (key_list) {
  foreach item (registry_enum_keys(key:key)) {

    appName = registry_get_sz(key:key + item, item:"DisplayName");
    if(!appName || appName !~ "SIMATIC WinCC/Audit Viewer [0-9A-Z ]+") continue;

    concluded = appName;
    location = "unknown";

    loc = registry_get_sz(key:key + item, item:"InstallLocation");
    if(loc) location = loc;

    if(!version = registry_get_sz(key:key + item, item:"DisplayVersion"))
      version = "unknown";

    set_kb_item(name:"siemens/simatic_wincc_audit_viewer/win/detected", value:TRUE);

    register_and_report_cpe(app:"Siemens " + appName , ver:version, concluded:concluded,
                          base:"cpe:/a:siemens:simatic_wincc_audit_viewer:", expr:"^([0-9.]+)", insloc:location, regService:"smb-login", regPort:0);
    exit(0);
  }
}

exit(0);
