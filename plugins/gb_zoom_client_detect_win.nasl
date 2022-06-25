###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zoom_client_detect_win.nasl 13650 2019-02-14 06:48:40Z cfischer $
#
# Zoom Client Version Detection (Windows)
#
# Authors:
# Vidita V Koushik <vidita@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation;
# either version 2 of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.814354");
  script_version("$Revision: 13650 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 07:48:40 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-12-06 18:01:43 +0530 (Thu, 06 Dec 2018)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Zoom Client Version Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of Zoom Client
  on Windows.

  The script logs in via WMI, searches for Zoom Client executables and gets the
  version from information.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");

  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  exit(0);
}

include("wmi_file.inc");
include("misc_func.inc");
include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");

infos = kb_smb_wmi_connectinfo();
if( ! infos ) exit( 0 );

handle = wmi_connect( host:infos["host"], username:infos["username_wmi_smb"], password:infos["password"] );
if( ! handle ) exit( 0 );

fileList = wmi_file_fileversion( handle:handle, fileName:"zoom", fileExtn:"exe", includeHeader:FALSE );
wmi_close( wmi_handle:handle );
if( ! fileList || ! is_array( fileList ) ) {
  exit( 0 );
}

foreach filePath( keys( fileList ))
{
  zoomPath = filePath - "\zoom.exe";

  vers = fileList[filePath];
  if( vers && version = eregmatch( string:vers, pattern:"^([0-9.]+)" ))
  {

    set_kb_item(name:"Zoom/Win/Ver", value:version[1]);

    #created cpe for this product
    cpe = build_cpe(value:version[1], exp:"^([0-9.]+)", base:"cpe:/a:zoom:client:");
    if(isnull(cpe))
      cpe = "cpe:/a:zoom:client";

    register_product(cpe: cpe, location: zoomPath, service:"smb-login", port:0);

    report =  build_detection_report(app: "Zoom Client",
                                     version: version[1],
                                     install: zoomPath,
                                     cpe: cpe,
                                     concluded: version[1]);
    log_message( port:0, data:report );
  }
}

exit(0);