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
  script_oid("1.3.6.1.4.1.25623.1.0.113884");
  script_version("2022-04-07T10:57:50+0000");
  script_tag(name:"last_modification", value:"2022-04-07 10:57:50 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-04-06 08:06:40 +0000 (Wed, 06 Apr 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("VMware Spring Boot Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl", "lsc_options.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_exclude_keys("win/lsc/disable_wmi_search");

  script_tag(name:"summary", value:"SMB login-based detection of VMware Spring Boot (and its
  components).");

  script_tag(name:"vuldetect", value:"To get the product version, the script logs in via SMB and
  searches for the VMware Spring Boot JAR files on the filesystem.");

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

if( ! drives = policy_powershell_cmd( cmd:cmd ) ) # Retrieve a list of drives to search
  exit( 0 );

if( ! comp_list = spring_boot_comp_list() )
  exit( 0 );

if( ! comp_pattern = list2or_regex( list:comp_list ) )
  exit( 0 );

port = kb_smb_transport();

# nb: regex is slightly different than the one of the Spring Framework detection because we don't
# have any fixed "core" component here.
file_pattern = "\\spring-boot-?" + comp_pattern + "?([0-9.A-Zx-]+)?\.jar$";

foreach drive( split( drives, keep:FALSE ) ) {

  # nb: For some unknown reason the powershell command above might return a directory letter with
  # trailing newlines / spaces so we need to strip them off.
  if( ! drive = ereg_replace( string:drive, pattern:"\s+", replace:"" ) )
    continue;

  if( p_version_check == TRUE )
    cmd = 'Get-childitem spring-boot*.jar -Path ' + drive + ' -recurse -Erroraction \'silentlycontinue\' | % { $_.FullName } | ft -HideTableHeaders';
  else
    cmd = 'Get-childitem ' + drive + '\\spring-boot*.jar -file -Recurse -OutBuffer 1000 -Erroraction \'silentlycontinue\' | % { $_.FullName } | ft -HideTableHeaders';

  if( ! files = policy_powershell_cmd( cmd:cmd ) )
    continue;

  foreach file( split( files, keep:FALSE ) ) {

    # Default names of files if downloaded are e.g.:
    #
    # spring-boot-2.2.13.RELEASE.jar
    # spring-boot-2.6.5.jar
    # spring-boot-starter-web-2.6.5.jar
    # spring-boot-starter-webflux-2.6.5.jar
    #

    # nb: This makes sure that we're only catching the files we want.
    if( ! eregmatch( string:file, pattern:file_pattern, icase:FALSE ) )
      continue;

    comp = eregmatch( string:file, pattern:"\\spring-boot-" + comp_pattern + "([0-9.A-Zx-]+)?\.jar$", icase:FALSE );

    # nb: We're calling the default spring-boot-2.6.5.jar file "core" component for a better/easier
    # handling in the consolidation...
    if( ! comp[1] )
      component = "core";
    else
      component = comp[1];

    version   = "unknown";
    concluded = ""; # nb: Just overwriting a possible previously defined string
    comp_key  = tolower( component );

    vers = eregmatch( string:file, pattern:"\\spring-boot-" + comp_pattern + "?-?([0-9.x]+)(\.RELEASE)?\.jar$", icase:FALSE );
    if( vers[2] ) {
      version = vers[2];
      concluded = vers[0];
    }

    set_kb_item( name:"vmware/spring/boot/detected", value:TRUE );
    set_kb_item( name:"vmware/spring/boot/smb-login/detected", value:TRUE );

    set_kb_item( name:"vmware/spring/boot/" + comp_key + "/detected", value:TRUE );
    set_kb_item( name:"vmware/spring/boot/" + comp_key + "/smb-login/detected", value:TRUE );

    set_kb_item( name:"vmware/spring/boot/smb-login/" + port + "/installs", value:"0#---#" + file + "#---#" + version + "#---#" + concluded + "#---#" + component );
  }
}

exit( 0 );
