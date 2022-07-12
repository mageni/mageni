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
  script_oid("1.3.6.1.4.1.25623.1.0.113336");
  script_version("2019-04-25T11:36:15+0000");
  script_tag(name:"last_modification", value:"2019-04-25 11:36:15 +0000 (Thu, 25 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-02-14 14:38:37 +0100 (Thu, 14 Feb 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"registry");

  script_name("ManageEngine OpManager Detection (SMB)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"summary", value:"Checks registry keys of the target for signs
  of an installation of ManageEngine OpManager, and if a key is found,
  uses SMB to figure out the installed version.");

  script_xref(name:"URL", value:"https://www.manageengine.com/network-monitoring/");

  exit(0);
}

include( "host_details.inc" );
include( "smb_nt.inc" );
include( "secpod_smb_func.inc" );

if( ! os_arch = get_kb_item( "SMB/Windows/Arch" ) ) exit( 0 );

if( "x86" >< os_arch ) {
  key_list = make_list( "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" );
}
else if( "x64" >< os_arch ) {
  key_list = make_list( "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" );
}
else {
  exit( 0 );
}

foreach key( key_list ) {
  foreach item( registry_enum_keys( key: key ) ) {
    appName = registry_get_sz( key: key + "\" + item, item: "DisplayName" );
    if( appName !~ 'ManageEngine OpManager' ) continue;

    set_kb_item( name: "manageengine/opmanager/detected", value: TRUE );
    set_kb_item( name: "manageengine/opmanager/smb/detected", value: TRUE );

    location = registry_get_sz( key: key + "\" + item, item: "InstallLocation" );

    infopath = location + "\blog\opmunified.txt";
    file_content = smb_read_file( fullpath: infopath, offset: 0, count: 3000 );

    version = "unknown";
    ver = eregmatch( string: file_content, pattern: 'Build_Comment=([0-9]{1,2})([0-9])([0-9]{2,3}) ' );
    if( ! isnull( ver[1] ) ) {
      version = ver[1] + "." + ver[2] + "." + ver[3];
    }

    set_kb_item( name: "manageengine/opmanager/smb/version", value: version );
    set_kb_item( name: "manageengine/opmanager/smb/location", value: location );
    set_kb_item( name: "manageengine/opmanager/smb/concluded", value: ver[0] );

    exit( 0 );
  }
}

exit( 0 );
