###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_epsviewer_detect_win.nasl 11852 2018-10-12 06:12:07Z cfischer $
#
# EPS Viewer Detection (Windows)
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.112390");
  script_version("$Revision: 11852 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 08:12:07 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-10-11 21:32:11 +0200 (Thu, 11 Oct 2018)");
  script_name("EPS Viewer Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of EPS Viewer.

  The script logs in via smb, searches for EPS Viewer in the registry and gets the version from its executable.");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");
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

if (isnull(key_list))
  exit(0);

foreach key (key_list) {

  foreach item (registry_enum_keys(key:key)) {

    name = registry_get_sz(key:key + item, item:"DisplayName");

    if("EPS Viewer" >< name) {
      version = registry_get_sz(key:key + item, item:"Version");
      path = registry_get_sz(key:key + item, item:"InstallPath");

      if(!path) {
        path = registry_get_sz(key:key + item, item:"InstallLocation");
        if(!path) {
          path = registry_get_sz(key:key + item, item:"Inno Setup: App Path");
        }
      }

      if(!version) {
        if(path) {
          version = fetch_file_version(sysPath:path, file_name:"EPSViewer.exe");
        } else {
          path = registry_get_sz(key:key, item:"UninstallString");
          if(path) {
            path = path - "unins000.exe";
            version = fetch_file_version(sysPath:path, file_name:"EPSViewer.exe");
          }
        }
      }

      if(version) {
        set_kb_item(name:"IdeaMK/EPSViewer/Win/Installed", value:TRUE);

        if(!path){
          path = 'Could not find the install path from registry';
        }

        register_and_report_cpe(app:"ideaMK EPS Viewer", ver:version, concluded:version, base:"cpe:/a:ideamk:eps_viewer:", expr:"^([0-9.]+)", insloc:path);

        exit(0);
      }
    }
  }
}