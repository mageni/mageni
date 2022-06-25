# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.800257");
  script_version("2021-03-09T13:53:53+0000");
  script_tag(name:"last_modification", value:"2021-03-11 11:26:33 +0000 (Thu, 11 Mar 2021)");
  script_tag(name:"creation_date", value:"2009-04-02 08:15:32 +0200 (Thu, 02 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"registry");

  script_name("OpenSSL Detection (Windows SMB Login)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"SMB login-based detection of OpenSSL.");

  exit(0);
}

include("host_details.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");
include("wmi_file.inc");
include("list_array_func.inc");
include("http_func.inc");
include("misc_func.inc");
include("policy_functions.inc");

port = kb_smb_transport();

if( get_kb_item( "win/lsc/disable_wmi_search" ) )
  exit( 0 );

os_arch = get_kb_item( "SMB/Windows/Arch" );
if( ! os_arch )
  exit( 0 );

if( "x86" >< os_arch ) {
  key_list = make_list( "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" );
} else if( "x64" >< os_arch ) {
  key_list = make_list( "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" );
}

if( isnull ( key_list ) )
  exit( 0 );

foreach key( key_list ) {
  foreach item( registry_enum_keys( key:key ) ) {

    app_name = registry_get_sz( key:key + item, item:"DisplayName" );

    if( ! app_name || app_name !~ "OpenSSL" )
      continue;

    concluded  = "Registry-Key:    " + key + item + '\n';
    concluded += "DisplayName:     " + app_name;
    version = "unknown";

    if( disp_vers = registry_get_sz( key:key + item, item:"DisplayVersion" ) )
      concluded += '\nDisplayVersion:  ' + disp_vers;

    infos = kb_smb_wmi_connectinfo();
    if( ! infos )
      exit( 0 );

    handle = wmi_connect( host:infos["host"], username:infos["username_wmi_smb"], password:infos["password"] );
    if( ! handle )
      exit( 0 );

    file_list = wmi_file_file_search( handle:handle, fileName:"openssl", fileExtn:"exe", includeHeader:FALSE );
    wmi_close( wmi_handle:handle );
    if( ! file_list || ! is_array( file_list ) )
      exit( 0 );

    foreach file(file_list) {
      loc = file_list[0];
      if( loc ) {
        split = split( loc, sep:"\" );
        count =  max_index( split ) - 1;
        file_name = split[count];
        location = ereg_replace( string:loc, pattern:split[max_index( split ) - 1], replace:'' );
      }

      file_vers = fetch_file_version( sysPath:location, file_name:file_name );
      if( file_vers )
        concluded += '\nFile version:    ' + file_vers + ' fetched from ' + location + file_name;
      file = location + file_name;
      cmd = "(get-item '" + file + "').VersionInfo | select ProductVersion | ft -HideTableHeaders";
      value = policy_powershell_cmd(cmd:cmd);
      if( value )
        version = value;
        concluded += '\nProduct version: ' + version + ' fetched from the executable with PowerShell';
    }

    set_kb_item(name: "openssl/detected", value: TRUE);
    set_kb_item(name: "openssl_or_gnutls/detected", value: TRUE);
    set_kb_item(name: "openssl/smb-login/detected", value: TRUE);

    set_kb_item(name: "openssl/smb-login/" + port + "/installs",
                value: "0#---#" + location + "#---#" + version + "#---#" + concluded);
  }
}

exit( 0 );
