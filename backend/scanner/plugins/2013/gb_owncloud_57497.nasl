###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_owncloud_57497.nasl 10821 2018-08-07 14:52:02Z cfischer $
#
# ownCloud Multiple Security Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103645");
  script_bugtraq_id(57497);
  script_cve_id("CVE-2013-0201", "CVE-2013-0202", "CVE-2013-0203", "CVE-2013-0204");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:P/A:P");
  script_version("$Revision: 10821 $");
  script_name("ownCloud Multiple Security Vulnerabilities");
  script_tag(name:"last_modification", value:"$Date: 2018-08-07 16:52:02 +0200 (Tue, 07 Aug 2018) $");
  script_tag(name:"creation_date", value:"2013-01-24 11:21:02 +0100 (Thu, 24 Jan 2013)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_owncloud_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("owncloud/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57497");
  script_xref(name:"URL", value:"http://owncloud.org/");

  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for more
  information.");

  script_tag(name:"summary", value:"ownCloud is prone to an arbitrary-code execution vulnerability,
  multiple HTML-injection vulnerabilities and multiple cross-site scripting vulnerabilities because
  it fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"Successful exploits will allow attacker-supplied HTML and script
  code to run in the context of the affected browser, potentially allowing the attacker to steal
  cookie-based authentication credentials or control how the site is rendered to the user and to
  execute arbitrary code in the context of the web server. Other attacks are also possible.");

  script_tag(name:"affected", value:"ownCloud 4.0.10 and prior ownCloud 4.5.5 and prior.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!dir = get_app_location(cpe:CPE, port:port))exit(0);
if(dir == "/") dir = "";
url = dir + '/core/lostpassword/templates/resetpassword.php?l="><script>alert(/openvas-xss-test/)</script>&_=1';

if(http_vuln_check(port:port, url:url,pattern:"<script>alert\(/openvas-xss-test/\)</script>", check_header:TRUE)) {
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
