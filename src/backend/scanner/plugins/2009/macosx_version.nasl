###################################################################
# OpenVAS Vulnerability Test
# $Id: macosx_version.nasl 14325 2019-03-19 13:35:02Z asteins $
#
# Mac OS X Version
#
# Developed by LSS Security Team <http://security.lss.hr>
#
# Copyright (C) 2009 LSS <http://www.lss.hr>
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
# You should have received a copy of the GNU General Public
# License along with this program. If not, see
# <http://www.gnu.org/licenses/>.
###################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102005");
  script_version("$Revision: 14325 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:35:02 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-11-17 12:37:40 +0100 (Tue, 17 Nov 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Mac OS X Version");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("Copyright (C) 2009 LSS");
  script_dependencies("os_detection.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Host/runs_unixoide");

  script_tag(name:"summary", value:"This script gets the Mac OS X version from other plugins and reports if the
  host is running an outdated/unsupported version.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

osx_name = get_kb_item( "ssh/login/osx_name" );
osx_version = get_kb_item( "ssh/login/osx_version" );
os = osx_name + " " + osx_version;
if( ! os ) os = get_kb_item( "Host/OS/ICMP" ); # TODO: Use best_os_cpe once we can detect Mac OS X more reliable
if( ! os ) exit( 0 );
if( "Mac OS X" >!< os ) exit( 0 );

# search for the digits behind the last dot
# (OS X versioning is 10.X.Y, we want the Y)
version = strstr( os, "." );
version = substr( version, "1" );
version = strstr( version, "." );
version = substr( version, "1" );
version = int( version );

if( "10.5." >< os ) {
  if( version < 7 ) {
    report = "The remote host is not running the latest Mac OS X 10.5. Please update to the latest version.";
  }
}

if( "10.4." >< os ) {
  if( version < 11 ) {
    report = "The remote host is not running the latest Mac OS X 10.4. Please update to the latest version";
  }
}

if( "10.3." >< os ) {
  report = "The remote host is running Mac OS X 10.3. As this version is no longer supported by Apple, please consider upgrading to the latest version.";
  if( "10.3.9" >!< os ) {
    report += "Moreover, if you are planning on keeping this version, at least update it to the last one released - 10.3.9";
  }
}

if( "10.2." >< os ) {
  report = "The remote host is running Mac OS X 10.2. As this version is no longer supported by Apple, please consider upgrading to the latest version.";
  if( "10.2.8" >!< os ) {
    report += "Moreover, if you are planning on keeping this version, at least update it to the last one released - 10.2.8";
  }
}

if( "10.1." >< os ) {
  report = "The remote host is running Mac OS X 10.1. As this version is no longer supported by Apple, please consider upgrading to the latest version.";
  if( "10.1.5" >!< os ) {
    report += "Moreover, if you are planning on keeping this version, at least update it to the last one released - 10.1.5";
  }
}

if( report ) {
  log_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
