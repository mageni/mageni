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
  script_oid("1.3.6.1.4.1.25623.1.0.814354");
  script_version("2021-10-12T14:42:30+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-10-13 11:12:06 +0000 (Wed, 13 Oct 2021)");
  script_tag(name:"creation_date", value:"2018-12-06 18:01:43 +0530 (Thu, 06 Dec 2018)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Zoom Client Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"SMB login-based detection of the Zoom Client.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");
include("wmi_file.inc");
include("list_array_func.inc");

key = "Software\Microsoft\Windows\CurrentVersion\Uninstall\ZoomUMX";

zoomPath = registry_get_sz(key:key, item:"InstallLocation", type:"HKCU");
if(!zoomPath) {
  zoomPath = registry_get_sz(key:key, item:"DisplayIcon");
  zoomPath = zoomPath - "Zoom.exe";
}

if(zoomPath && "Zoom" >< zoomPath) {
  appVer = fetch_file_version(sysPath:zoomPath, file_name:"Zoom.exe");
  if(appVer) {
    version = eregmatch(string:appVer, pattern:"^([0-9.]+)");
    if(version[1])
      version = version[1];
  }
}

if(!version) {
  infos = kb_smb_wmi_connectinfo();
  if(!infos)
    exit(0);

  handle = wmi_connect(host:infos["host"], username:infos["username_wmi_smb"], password:infos["password"]);
  if(!handle)
    exit(0);

  fileList = wmi_file_fileversion(handle:handle, fileName:"zoom", fileExtn:"exe", includeHeader:FALSE);
  wmi_close(wmi_handle:handle);
  if(!fileList || !is_array(fileList))
    exit(0);

  foreach filePath(keys(fileList)) {

    zoomPath = filePath - "\zoom.exe";

    vers = fileList[filePath];
    if(vers && version = eregmatch(string:vers, pattern:"^([0-9.]{3,})")) {
      version = version[1];
      break;
    }
  }
}

if(version) {

  set_kb_item(name:"zoom/client/detected", value:TRUE);
  set_kb_item(name:"zoom/client/win/detected", value:TRUE);

  cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:zoom:zoom:");
  if(!cpe)
    cpe = "cpe:/a:zoom:zoom";

  # nb: NVD is currently using two different CPEs because Zoom has some inconsistencies in
  # their client naming. We register both just to be sure.
  cpe2 = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:zoom:meetings:");
  if(!cpe2)
    cpe2 = "cpe:/a:zoom:meetings";

  register_product(cpe:cpe, location:zoomPath, service:"smb-login", port:0);
  register_product(cpe:cpe2, location:zoomPath, service:"smb-login", port:0);

  report = build_detection_report(app:"Zoom Client",
                                  version:version,
                                  install:zoomPath,
                                  cpe:cpe,
                                  concluded:version);
  log_message(port:0, data:report);
}

exit(0);