###############################################################################
# OpenVAS Vulnerability Test
#
# Apache Tomcat Detection (Windows SMB Login)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802377");
  script_version("2021-02-16T07:19:40+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-02-16 12:02:05 +0000 (Tue, 16 Feb 2021)");
  script_tag(name:"creation_date", value:"2012-01-12 13:49:05 +0530 (Thu, 12 Jan 2012)");
  script_name("Apache Tomcat Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"SMB login-based detection of Apache Tomcat.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
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

count = 1;

foreach key( key_list ) {
  foreach item( registry_enum_keys( key:key ) ) {

    app_name = registry_get_sz( key:key + item, item:"DisplayName" );
    if( ! app_name || app_name !~ "Apache Tomcat [0-9.]+" )
      continue;

    set_kb_item( name:"apache/tomcat/detected", value:TRUE );
    set_kb_item( name:"apache/tomcat/smb/detected", value:TRUE );
    set_kb_item( name:"apache/tomcat/smb/" + count + "/detected", value:TRUE );
    set_kb_item( name:"apache/tomcat/smb/count", value:count );

    concluded  = "Registry Key:   " + key + item + '\n';
    concluded += "DisplayName:    " + app_name;
    location = "unknown";
    version = "unknown";

    if( vers = registry_get_sz( key:key + item, item:"DisplayVersion" ) ) {
      version = vers;
      concluded += '\nDisplayVersion: ' + vers;
    }

    set_kb_item( name:"apache/tomcat/smb/" + count + "/concluded", value:concluded );
    set_kb_item( name:"apache/tomcat/smb/" + count + "/version", value:version );

    loc = registry_get_sz( key:key + item, item:"UninstallString" );
    if( loc ) {
      split = split( loc, sep:"\" );
      location = ereg_replace( string:loc, pattern:split[max_index(split) - 1], replace:"" );
    }

    set_kb_item( name:"apache/tomcat/smb/" + count + "/location", value:location );
    count++;
  }
}

exit( 0 );
