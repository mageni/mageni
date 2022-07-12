###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_lotus_sametime_46471.nasl 12018 2018-10-22 13:31:29Z mmartin $
#
# IBM Lotus Sametime Server 'stconf.nsf' Cross Site Scripting Vulnerability
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

CPE = 'cpe:/a:ibm:lotus_domino';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103084");
  script_version("$Revision: 12018 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 15:31:29 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-02-22 13:26:53 +0100 (Tue, 22 Feb 2011)");
  script_bugtraq_id(46471);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2011-1038");

  script_name("IBM Lotus Sametime Server 'stconf.nsf' Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/46471");
  script_xref(name:"URL", value:"http://www-03.ibm.com/software/products/en/ibmsame");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/516563");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_lotus_domino_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("dominowww/installed");

  script_tag(name:"summary", value:"IBM Lotus Sametime Server is prone to a cross-site scripting
  vulnerability because it fails to sufficiently sanitize user-supplied data.");
  script_tag(name:"affected", value:"IBM Lotus Sametime 8.0.1 is vulnerable. Other versions may also
  be affected.");
  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site. This may allow the attacker
  to steal cookie-based authentication credentials and to launch other attacks.");

  script_tag(name:"solution", value:"Apply the patch for this vulnerability (8.0.1.0-Lotus-ST-IF-RPOH-8F7KAT),
  available from IBM Support and Downloads. See References.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) ) exit( 0 );

url = "/stconf.nsf/WebMessage?OpenView&messageString=%22;;%3E%3Cscript%3Ealert(%27openvas-xss-test%27)%3C/script%3E";

if( http_vuln_check( port:port, url:url, pattern:"<script>alert\('openvas-xss-test'\)</script>", check_header:TRUE ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
