# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.107630");
  script_version("2019-03-30T12:51:58+0000");
  script_tag(name:"last_modification", value:"2019-03-30 12:51:58 +0000 (Sat, 30 Mar 2019)");
  script_tag(name:"creation_date", value:"2019-03-30 13:50:35 +0100 (Sat, 30 Mar 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Gemalto Sentinel UltraPro 32bit Client Library Version Detection (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl", "gb_wmi_access.nasl", "gb_gemalto_sentinel_protection_installer_detect_win.nasl");
  script_mandatory_keys("gemalto/sentinel_protection_installer/win/detected", "WMI/access_successful", "SMB/WindowsVersion");
  script_exclude_keys("win/lsc/disable_wmi_search");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"Detects the installed version
  of Gemalto Sentinel UltraPro 32bit Client Library on Windows.");
  script_xref(name:"URL", value:"https://sentinel.gemalto.com/");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include( "host_details.inc" );
include( "smb_nt.inc" );
include( "secpod_smb_func.inc" );
include( "wmi_file.inc" );
include( "http_func.inc" );
include( "misc_func.inc" );
include( "cpe.inc" );
include( "version_func.inc" );

if( get_kb_item( "win/lsc/disable_wmi_search" ) )
  exit( 0 );

infos = kb_smb_wmi_connectinfo();
if( ! infos )
  exit( 0 );

handle = wmi_connect( host:infos["host"], username:infos["username_wmi_smb"], password:infos["password"] );
if( ! handle )
  exit( 0 );

fileList = wmi_file_file_search( handle:handle, dirPathLike:"%program files%", fileName:"ux32w", fileExtn:"dll", includeHeader:FALSE );
wmi_close( wmi_handle:handle );
if( ! fileList || ! is_array( fileList ) )
  exit( 0 );

appName = "Gemalto Sentinel UltraPro 32bit Client Library";

loc = fileList[0];
if( loc ) {
  split = split( loc, sep:"\" );
  location = ereg_replace( string:loc, pattern:split[max_index( split ) - 1], replace:'' );
}

concluded = loc;

version = fetch_file_version( sysPath:location, file_name:"ux32w.dll" );

set_kb_item( name:"gemalto/sentinel_ultrapro_32bit_client_library/win/detected", value:TRUE );

register_and_report_cpe( app:appName, ver:version, concluded:concluded,
                        base:"cpe:/a:gemalto:sentinel_ultrapro_32bit_client_library:", expr:"^([0-9.]+)", insloc:location, regService:"smb-login", regPort:0 );
exit( 0 );
