###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_dng_converter_detect_win.nasl 12413 2018-11-19 11:11:31Z cfischer $
#
# Adobe DNG Converter Detection (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.809761");
  script_version("$Revision: 12413 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-19 12:11:31 +0100 (Mon, 19 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-12-15 15:01:50 +0530 (Thu, 15 Dec 2016)");
  script_name("Adobe DNG Converter Detection (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_wmi_access.nasl");
  script_mandatory_keys("WMI/access_successful");

  script_tag(name:"summary", value:"Detects the installed version of
  Adobe DNG Converter.

  The script runs a wmi query for 'Adobe DNG Converter.exe' and extracts the
  version information from query result.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");
include("misc_func.inc");
include("wmi_file.inc");

infos = kb_smb_wmi_connectinfo();
if( ! infos ) exit( 0 );

handle = wmi_connect( host:infos["host"], username:infos["username_wmi_smb"], password:infos["password"] );
if( ! handle ) exit( 0 );

# TODO: Limit to a possible known common path, e.g. "Adobe"
fileList = wmi_file_fileversion( handle:handle, fileName:"Adobe DNG Converter", fileExtn:"exe", includeHeader:FALSE );
wmi_close( wmi_handle:handle );
if( ! fileList || ! is_array( fileList ) ) {
  exit( 0 );
}

report = ""; # nb: To make openvas-nasl-lint happy...

foreach filePath( keys( fileList ) ) {

  vers = fileList[filePath];

  if( vers && version = eregmatch( string:vers, pattern:"^([0-9.]+)" ) ) {

    found = TRUE;

    set_kb_item( name:"Adobe/DNG/Converter/Win/Version", value:version[1] );

    ##Only 32-bit app is available
    ##Update CPE once available in NVD
    cpe = build_cpe( value:version[1], exp:"^([0-9.]+)", base:"cpe:/a:adobe:dng_converter:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:adobe:dng_converter";

    register_product( cpe:cpe, location:filePath );
    report += build_detection_report( app:"Adobe DNG Converter",
                                      version:version[1],
                                      install:filePath,
                                      cpe:cpe,
                                      concluded:version[1] ) + '\n\n';
  }
}

if( found ) {
  log_message( port:0, data:report );
}

exit( 0 );
