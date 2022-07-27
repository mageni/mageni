###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_flash_player_within_google_chrome_detect_win.nasl 12413 2018-11-19 11:11:31Z cfischer $
#
# Adobe Flash Player Within Google Chrome Detection (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.810612");
  script_version("$Revision: 12413 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-19 12:11:31 +0100 (Mon, 19 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-03-13 12:06:29 +0530 (Mon, 13 Mar 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Adobe Flash Player Within Google Chrome Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of Adobe
  Flash within google chrome.

  The script logs in via smb, searches for file 'pepflashplayer.dll' and gets
  version from the file.");

  script_category(ACT_GATHER_INFO);
  script_xref(name:"URL", value:"https://helpx.adobe.com/flash-player/kb/flash-player-google-chrome.html");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");

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

fileList = wmi_file_fileversion( handle:handle, dirPathLike:"%google%chrome%", fileName:"pepflashplayer", fileExtn:"dll", includeHeader:FALSE );
wmi_close( wmi_handle:handle );
if( ! fileList || ! is_array( fileList ) ) {
  exit( 0 );
}

checkduplicate = ""; # nb: To make openvas-nasl-lint happy...
checkduplicate_path = "";

foreach filePath( keys( fileList ) ) {

  vers = fileList[filePath];

  if( vers && version = eregmatch( string:vers, pattern:"^([0-9.]+)" ) ) {

    # wmi_file_fileversion returns the pepflashplayer.dll filename so we're stripping it away
    # to keep only the install location path
    location = filePath - "\pepflashplayer.dll";

    if( version[1] + ", " >< checkduplicate && location + ", " >< checkduplicate_path ) {
      continue;
    }

    # Assign the detected version value to checkduplicate so as to check in next loop iteration
    checkduplicate += version[1] + ", ";
    checkduplicate_path += location + ", ";

    set_kb_item( name:"AdobeFlashPlayer/Chrome/Win/Ver", value:version[1] );

    cpe = build_cpe( value:version[1], exp:"^([0-9.]+)", base:"cpe:/a:adobe:flash_player_chrome:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:adobe:flash_player_chrome";

    register_product( cpe:cpe, location:location );
    log_message( data:build_detection_report( app:"Flash Player Within Google Chrome",
                                              version:version[1],
                                              install:location,
                                              cpe:cpe,
                                              concluded:version[0] ) );
  }
}

exit( 0 );