###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netiq_access_manager_mult_vuln_12_14.nasl 14185 2019-03-14 13:43:25Z cfischer $
#
# NetIQ Access Manager XSS / CSRF / XXE Injection / Disclosure
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

CPE = "cpe:/a:netiq:access_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105149");
  script_cve_id("CVE-2014-5214", "CVE-2014-5216", "CVE-2014-5217", "CVE-2014-5215");
  script_version("$Revision: 14185 $");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("NetIQ Access Manager XSS / CSRF / XXE Injection / Disclosure");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 14:43:25 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-12-19 15:05:33 +0100 (Fri, 19 Dec 2014)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_netiq_access_manager_detect.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("netiq_access_manager/installed");

  script_xref(name:"URL", value:"https://www.novell.com/support/kb/doc.php?id=7015993");
  script_xref(name:"URL", value:"https://www.novell.com/support/kb/doc.php?id=7015994");
  script_xref(name:"URL", value:"https://www.novell.com/support/kb/doc.php?id=7015996");
  script_xref(name:"URL", value:"https://www.novell.com/support/kb/doc.php?id=7015997");
  script_xref(name:"URL", value:"https://www.novell.com/support/kb/doc.php?id=7015995");

  script_tag(name:"vuldetect", value:"Send a special crafted HTTP GET request and check the response.");

  script_tag(name:"insight", value:"An attacker without an account on the NetIQ Access Manager is be able to gain
  administrative access by combining different attack vectors. Though this host may not always be accessible from
  a public network, an attacker is still able to compromise the system when directly targeting administrative users.

  Because the NetIQ Access Manager is used for authentication, an attacker
  compromising the system can use it to gain access to other systems.");

  script_tag(name:"solution", value:"Update to 4.0 SP1 Hot Fix 3 or later.");

  script_tag(name:"summary", value:"NetIQ Access Manager suffers from cross site request forgery, external entity
  injection, information disclosure, and cross site scripting vulnerabilities.");

  script_tag(name:"affected", value:"NetIQ Access Manager version 4.0 SP1.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! get_app_location( port:port, cpe:CPE ) ) exit( 0 );

url = '/nidp/jsp/x509err.jsp?error=%3Cscript%3Ealert%28%27openvas-xss-test%27%29%3C/script%3E';
if( http_vuln_check( port:port, url:url, pattern:"<script>alert\('openvas-xss-test'\)</script>", extra_check:"HTTP/1.. 200" ) ) {
  report = report_vuln_url( port:port, url:url);
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );