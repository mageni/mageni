###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bonza_digital_cart_scrip_49262.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Bonza Digital Cart Script Cross Site Scripting and SQL Injection Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103273");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-09-23 10:55:34 +0200 (Fri, 23 Sep 2011)");
  script_bugtraq_id(49262);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Bonza Digital Cart Script Cross Site Scripting and SQL Injection Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49262");
  script_xref(name:"URL", value:"http://www.turnkeycentral.com/scripts/bonza-digital-cart-script/");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"summary", value:"Bonza Digital Cart Script is prone to a cross-site scripting
vulnerability and an SQL-injection vulnerability because the
application fails to sufficiently sanitize user-supplied input.

Exploiting these issues could allow an attacker to steal cookie-
based authentication credentials, compromise the application,
access or modify data, or exploit latent vulnerabilities in the
underlying database.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

foreach dir( make_list_unique( "/shop", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string(dir, '/searchresults.php?SearchTerm="><script>alert(/openvas-xss-test/)</script>&where=ItemName&ord1=ItemName&ord2=asc&search1.x=50&search1.y=14');

  if(http_vuln_check(port:port, url:url,pattern:"<script>alert\(/openvas-xss-test/\)</script></b>", check_header:TRUE)) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
