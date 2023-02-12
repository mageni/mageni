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
  script_oid("1.3.6.1.4.1.25623.1.0.107618");
  script_version("2023-01-13T10:21:10+0000");
  script_tag(name:"last_modification", value:"2023-01-13 10:21:10 +0000 (Fri, 13 Jan 2023)");
  script_tag(name:"creation_date", value:"2019-03-14 09:19:14 +0100 (Thu, 14 Mar 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Trellix / McAfee Endpoint Security Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"SMB login-based detection of Trellix / McAfee Endpoint Security.");

  script_xref(name:"URL", value:"https://www.trellix.com/en-us/products/endpoint-security.html");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

os_arch = get_kb_item( "SMB/Windows/Arch" );
if( ! os_arch )
  exit( 0 );

if( "x86" >< os_arch ) {
  key_list = make_list( "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" );
} else if( "x64" >< os_arch ) {
  key_list = make_list( "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" );
}

if( isnull( key_list ) )
  exit( 0 );

foreach key( key_list ) {
  foreach item( registry_enum_keys( key:key ) ) {

    app_name = registry_get_sz( key:key + item, item:"DisplayName" );
    # McAfee Endpoint Security Platform
    if( ! app_name || app_name !~ "McAfee Endpoint Security Platform" )
      continue;

    concluded = "Registry Key:   " + key + item + '\n';
    concluded += "DisplayName:    " + app_name;
    location = "unknown";
    version = "unknown";

    if( loc = registry_get_sz( key:key + item, item:"InstallLocation" ) ) {
      location = loc;

      # "File version" needs to be fetched to get the correct version number
      path = loc + "Endpoint Security Platform";
      file = "\mfeesp.exe";

      # 10.7.0.3012
      vers = fetch_file_version( sysPath:path, file_name:file );
      if( vers ) {
        version = vers;
        concluded += '\nVersion:        ' + version + ' fetched from ' + path + file;
      }
    }

    # 10.7.0
    if( regvers = registry_get_sz( key:key + item, item:"DisplayVersion" ) )
      concluded += '\nDisplayVersion: ' + regvers;

    set_kb_item( name:"mcafee/endpoint_security/detected", value:TRUE );
    set_kb_item( name:"mcafee/endpoint_security/smb-login/detected", value:TRUE );

    register_and_report_cpe( app:"Trellix (McAfee) Endpoint Security", ver:version, concluded:concluded,
                             base:"cpe:/a:mcafee:endpoint_security:", expr:"^([0-9.]+)",
                             insloc:location, regService:"smb-login", regPort:0 );
    exit( 0 );
  }
}

exit( 0 );
