###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_clamav_service_command_vuln_06_2016.nasl 13994 2019-03-05 12:23:37Z cfischer $
#
# ClamAV Service Commands Injection Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.105762");
  script_version("$Revision: 13994 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-05 13:23:37 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-06-13 14:28:48 +0200 (Mon, 13 Jun 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("ClamAV `Service Commands` Injection Vulnerability");

  script_tag(name:"summary", value:"ClamAV 0.99.2, and possibly other previous versions, allow the execution
  of clamav commands SCAN and SHUTDOWN without authentication.");

  script_tag(name:"vuldetect", value:"Send a SCAN command and check the response");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_clamav_remote_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/clamd", 3310);
  script_mandatory_keys("ClamAV/installed");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

CPE = 'cpe:/a:clamav:clamav';

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! get_app_location( port:port, cpe:CPE ) )
  exit( 0 );

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

vtstrings = get_vt_strings();

send( socket:soc, data:'SCAN /foo/bar/' + vtstrings["lowercase_rand"] + '.txt' );
recv = recv( socket:soc, length:1024 );
close( soc );

if( ! recv || "No such file or directory" >!< recv )
  exit( 0 );

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

files = traversal_files();

foreach pattern(keys(files)) {

  file = files[pattern];

  send( socket:soc, data:'SCAN /' + file );
  recv = recv( socket:soc, length:1024 );

  if( "/" + file + ": OK" >< recv ) {
    report = 'It was possible to confirm the vulnerability by sending the "SCAN /' + file + '" clamav command. Response:\n\n' + recv + '\n';
    security_message( port:port, data:report );
    close(soc);
    exit( 0 );
  }
}

close(soc);
exit( 99 );