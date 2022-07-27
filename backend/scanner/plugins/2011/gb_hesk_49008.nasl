###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hesk_49008.nasl 10698 2018-08-01 07:20:28Z cfischer $
#
# HESK Multiple Cross Site Scripting Vulnerabilities
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103198");
  script_version("$Revision: 10698 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-01 09:20:28 +0200 (Wed, 01 Aug 2018) $");
  script_tag(name:"creation_date", value:"2011-08-11 14:25:35 +0200 (Thu, 11 Aug 2011)");
  script_bugtraq_id(49008);
  script_cve_id("CVE-2011-5287");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("HESK Multiple Cross Site Scripting Vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49008");
  script_xref(name:"URL", value:"http://www.hesk.com/");
  script_xref(name:"URL", value:"http://www.htbridge.ch/advisory/multiple_xss_in_hesk.html");

  script_tag(name:"summary", value:"HESK is prone to multiple cross-site scripting vulnerabilities because
  it fails to sufficiently sanitize user-supplied data.");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site. This may allow the attacker
  to steal cookie-based authentication credentials and to launch other attacks.");

  script_tag(name:"affected", value:"HESK 2.2 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"Update to HESK 2.4.1 or later.");

  script_tag(name:"qod", value:"50"); # Prone to false positives
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/hesk", "/help", "/helpdesk", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/language/en/text.php/<script>alert('openvas-xss-test');</script>";

  if( http_vuln_check( port:port, url:url, pattern:"<script>alert\('openvas-xss-test'\);</script>", check_header:TRUE ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
