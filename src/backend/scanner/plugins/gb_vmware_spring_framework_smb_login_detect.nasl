# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113871");
  script_version("2022-04-05T10:26:24+0000");
  script_tag(name:"last_modification", value:"2022-04-06 10:04:37 +0000 (Wed, 06 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-04-05 08:02:35 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("VMware Spring Framework Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl", "lsc_options.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_exclude_keys("win/lsc/disable_wmi_search");

  script_tag(name:"summary", value:"SMB login-based detection of the VMware Spring Framework (and
  its components).");

  script_tag(name:"vuldetect", value:"To get the product version, the script logs in via SMB and
  searches for the VMware Spring Framework JAR files on the filesystem.");

  script_tag(name:"qod_type", value:"executable_version");

  script_timeout(900); # nb: File search might take a while...

  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");
include("misc_func.inc");
include("host_details.inc");
include("version_func.inc");
include("wmi_file.inc");
include("spring_prds.inc");
include("list_array_func.inc");

if( wmi_file_is_file_search_disabled() )
  exit( 0 );

# Run powershell commands based on version
powershell_version = 'get-host | select-object version | ft -HideTableHeaders';
p_version = policy_powershell_cmd( cmd:powershell_version );
p_version = ereg_replace( string:p_version, pattern:"\s+", replace:"" );
p_version_check = version_is_less( version:p_version, test_version:"3.0" );

if( p_version_check == TRUE )
  cmd = 'Get-WMIObject -Class Win32_logicaldisk -Filter \\\"DriveType=\'3\'\\\" | select DeviceID | ft -HideTableHeaders';
else
  cmd = 'Get-CimInstance -Class Win32_logicaldisk -Filter \\\"DriveType=\'3\'\\\" | select DeviceID | ft -HideTableHeaders';

drives = policy_powershell_cmd( cmd:cmd ); # Retrieve a list of drives to search
if( ! drives )
  exit( 0 );

port = kb_smb_transport();
concluded = ""; # nb: To make openvas-nasl-lint happy...
comp_pattern = spring_framework_comp_regex();

foreach drive( split( drives, keep:FALSE ) ) {

  # nb: For some unknown reason the powershell command above might return a directory letter with
  # trailing newlines / spaces so we need to strip them off.
  drive = ereg_replace( string:drive, pattern:"\s+", replace:"" );
  if( ! drive )
    continue;

  if( p_version_check == TRUE )
    cmd = 'Get-childitem spring-*.jar -Path ' + drive + ' -recurse -Erroraction \'silentlycontinue\' | % { $_.FullName } | ft -HideTableHeaders';
  else
    cmd = 'Get-childitem ' + drive + '\\spring-*.jar -file -Recurse -OutBuffer 1000 -Erroraction \'silentlycontinue\' | % { $_.FullName } | ft -HideTableHeaders';

  files = policy_powershell_cmd( cmd:cmd );
  if( ! files )
    continue;

  foreach file( split( files, keep:FALSE ) ) {

    # Default names of files if downloaded are e.g.:
    #
    # spring-core-5.3.17.jar
    # spring-webflux-5.3.17.jar
    # spring-webflux-5.3.17.jar
    #
    # Included in e.g. Struts2:
    #
    # struts-2.3.37/lib/spring-core-3.0.5.RELEASE.jar

    # nb: This makes sure that we're only catching the files we want.
    comp = eregmatch( string:file, pattern:"\\spring-" + comp_pattern + "[-.].*\.jar$", icase:FALSE );
    if( ! comp[1] )
      continue;

    version   = "unknown";
    component = comp[1];
    comp_key  = tolower( component );

    vers = eregmatch( string:file, pattern:"\\spring-" + comp_pattern + "-([0-9.x]+)(\.RELEASE)?\.jar$", icase:FALSE );
    if( vers[2] ) {
      version = vers[2];
      concluded = vers[0];
    }

    set_kb_item( name:"vmware/spring/framework/detected", value:TRUE );
    set_kb_item( name:"vmware/spring/framework/smb-login/detected", value:TRUE );

    set_kb_item( name:"vmware/spring/framework/" + comp_key + "/detected", value:TRUE );
    set_kb_item( name:"vmware/spring/framework/" + comp_key + "/smb-login/detected", value:TRUE );

    set_kb_item( name:"vmware/spring/framework/smb-login/" + port + "/installs", value:"0#---#" + file + "#---#" + version + "#---#" + concluded + "#---#" + component );
  }
}

exit( 0 );
