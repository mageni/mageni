###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_owncloud_53145.nasl 11435 2018-09-17 13:44:25Z cfischer $
#
# ownCloud Multiple Input Validation Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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

CPE = "cpe:/a:owncloud:owncloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103473");
  script_version("$Revision: 11435 $");
  script_bugtraq_id(53145);
  script_cve_id("CVE-2012-2269", "CVE-2012-2270", "CVE-2012-2397", "CVE-2012-2398");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-17 15:44:25 +0200 (Mon, 17 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-04-19 12:17:59 +0200 (Thu, 19 Apr 2012)");
  script_name("ownCloud Multiple Input Validation Vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_owncloud_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("owncloud/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53145");
  script_xref(name:"URL", value:"http://owncloud.org/");
  script_xref(name:"URL", value:"http://www.tele-consulting.com/advisories/TC-SA-2012-01.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/522397");

  script_tag(name:"summary", value:"ownCloud is prone to a URI open-redirection vulnerability,
  multiple cross-site scripting vulnerabilities and multiple HTML-injection vulnerabilities
  because it fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker could leverage the cross-site scripting issues to execute
  arbitrary script code in the browser of an unsuspecting user in the context of the affected site.
  This may let the attacker steal cookie-based authentication credentials and launch other attacks.

  Attacker-supplied HTML and script code would run in the context of the affected browser, potentially
  allowing the attacker to steal cookie-based authentication credentials or control how the site is
  rendered to the user. Other attacks are also possible.

  Successful exploits may redirect a user to a potentially malicious site. This may aid in phishing attacks.");

  script_tag(name:"affected", value:"ownCloud 3.0.0 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"Updates are available. Please see the reference for more details.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!dir = get_app_location(cpe:CPE, port:port)) exit(0);
if(dir == "/") dir = "";
url = string(dir, '/index.php?redirect_url=1"><script>alert(/xss-test/)</script><l="');

if(http_vuln_check(port:port, url:url,pattern:"<script>alert\(/xss-test/\)</script>", check_header:TRUE, extra_check:"Powered by ownCloud")) {
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
