###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_java_prdts_detect_portable_win.nasl 13953 2019-03-01 08:57:48Z cfischer $
#
# Java Portable Version Detection (Windows)
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107318");
  script_version("$Revision: 13953 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 09:57:48 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-04-25 17:33:28 +0200 (Wed, 25 Apr 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Java Portable Version Detection (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_java_prdts_detect_win.nasl", "gb_wmi_access.nasl");
  script_mandatory_keys("win/lsc/search_portable_apps", "WMI/access_successful");
  script_exclude_keys("win/lsc/disable_wmi_search");

  script_tag(name:"summary", value:"Detection of Java Portable on Windows.

  The script logs in via WMI, searches for Java executables on the filesystem
  and gets the installed version if found.

  To enable the search for this product you need to 'Enable Detection of Portable Apps on Windows'
  in the Options for Local Security Checks (OID: 1.3.6.1.4.1.25623.1.0.100509) of your scan config.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("wmi_file.inc");
include("misc_func.inc");
include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");
include("version_func.inc");

if( get_kb_item( "win/lsc/disable_wmi_search" ) )
  exit( 0 );

infos = kb_smb_wmi_connectinfo();
if( ! infos )
  exit( 0 );

handle = wmi_connect( host:infos["host"], username:infos["username_wmi_smb"], password:infos["password"] );
if( ! handle )
  exit( 0 );

fileList = wmi_file_fileversion( handle:handle, fileName:"java", fileExtn:"exe", includeHeader:FALSE );
wmi_close( wmi_handle:handle );
if( ! fileList || ! is_array( fileList ) )
  exit( 0 );

# From gb_java_prdts_detect_win.nasl to avoid a doubled detection of a registry-based installation.
detectedList = get_kb_list( "Java/Win/InstallLocations" );

foreach filePath( keys( fileList ) ) {

  # wmi_file_fileversion returns the .exe filename so we're stripping it away
  # to keep the install location registration the same way like in gb_java_prdts_detect_win.nasl
  location = filePath - "\java.exe";
  if( detectedList && in_array( search:tolower( location ), array:detectedList ) ) continue; # We already have detected this installation...

  vers = fileList[filePath];

  # Version of the java.exe file is something like 8.0.1710.11
  # so we need to catch only the first three parts of the version.
  if( vers && version = eregmatch( string:vers, pattern:"^([0-9]+\.[0-9]+\.[0-9]{1,3})" ) ) {

    set_kb_item( name:"Java/Win/InstallLocations", value:tolower( location ) );

    # For correct determination of the product we need to add "1." as leading number to the detected version number
    vers = "1." + version[1];

    set_kb_item( name:"Sun/Java/JRE/Win/Ver", value:vers );
    set_kb_item( name:"Sun/Java/JDK_or_JRE/Win/installed", value:TRUE );
    set_kb_item( name:"Sun/Java/JDK_or_JRE/Win_or_Linux/installed", value:TRUE );

    # The portableapps.com installer is putting the 32bit version in CommonFiles\Java and the 64bit into CommonFiles\Java64.
    # This is the only way to differ between 32bit and 64bit as we can't differ between 32 and 64bit based on the file information.
    if( "java64" >< location ) {

      set_kb_item( name:"Sun/Java64/JRE64/Win/Ver", value:vers );

      if( version_is_less( version:vers, test_version:"1.4.2.38" ) ||
          version_in_range( version:vers, test_version:"1.5", test_version2:"1.5.0.33" ) ||
          version_in_range( version:vers, test_version:"1.6", test_version2:"1.6.0.18" ) ){
        # nb: Before Oracles acquisition of Sun
        java_name = "Sun Java JRE 64-bit";
        cpe = "cpe:/a:sun:jre:x64:";
      } else {
        # nb: After Oracles acquisition of Sun
        java_name = "Oracle Java JRE 64-bit";
        cpe = "cpe:/a:oracle:jre:x64:";
      }
    } else {
      if( version_is_less( version:vers, test_version:"1.4.2.38" ) ||
          version_in_range( version:vers, test_version:"1.5", test_version2:"1.5.0.33" ) ||
          version_in_range( version:vers, test_version:"1.6", test_version2:"1.6.0.18" ) ) {
        # nb: Before Oracles acquisition of Sun
        java_name = "Sun Java JRE 32-bit";
        cpe = "cpe:/a:sun:jre:";
      } else {
        # nb: After Oracles acquisition of Sun
        java_name = "Oracle Java JRE 32-bit";
        cpe = "cpe:/a:oracle:jre:";
      }
    }
    register_and_report_cpe( app:java_name + " Portable", ver:vers, concluded:vers, base:cpe, expr:"^([:a-z0-9._]+)", insloc:location );
  }
}

exit( 0 );