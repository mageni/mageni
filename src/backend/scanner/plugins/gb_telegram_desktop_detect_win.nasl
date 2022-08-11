###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_telegram_desktop_detect_win.nasl 13664 2019-02-14 11:13:52Z cfischer $
#
# Telegram Desktop Version Detection (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.814305");
  script_version("$Revision: 13664 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 12:13:52 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-11-05 16:30:44 +0530 (Mon, 05 Nov 2018)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Telegram Desktop Version Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of Telegram
  Desktop on Windows.

  The script logs in via smb, searches for Telegram Desktop and gets the
  version from registry.");

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

fileList = wmi_file_fileversion( handle:handle, fileName:"Telegram", fileExtn:"exe", includeHeader:FALSE );
wmi_close( wmi_handle:handle );
if( ! fileList || ! is_array( fileList ) ) {
  exit( 0 );
}

foreach filePath( keys( fileList ) )
{
  location = filePath - "\telegram.exe";
  if("\tupdates\temp" >!< location)
  {
    telPath = location;
    vers = fileList[filePath];
    if( vers )
    {
      version = eregmatch( string:vers, pattern:"^([0-9.]+)");
      if(version[1])
      {
        set_kb_item(name:"Telegram/Win/Ver", value:version[1]);
        register_and_report_cpe( app:"Telegram Desktop", ver:version[1], concluded:version[0], base:"cpe:/a:telegram:tdesktop:", expr:"([0-9.]+)", insloc:location );
      }
    }
  }
}

exit(0);