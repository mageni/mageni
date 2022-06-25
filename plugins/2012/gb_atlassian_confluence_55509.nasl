###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_atlassian_confluence_55509.nasl 11435 2018-09-17 13:44:25Z cfischer $
#
# Atlassian Confluence Error Page Cross Site Scripting Vulnerability
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

CPE = "cpe:/a:atlassian:confluence";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103569");
  script_bugtraq_id(55509);
  script_version("$Revision: 11435 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Atlassian Confluence Error Page Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55509");
  script_xref(name:"URL", value:"http://www.atlassian.com/software/confluence/");

  script_tag(name:"last_modification", value:"$Date: 2018-09-17 15:44:25 +0200 (Mon, 17 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-09-18 11:53:40 +0200 (Tue, 18 Sep 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_tag(name:"solution_type", value:"VendorFix");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_atlassian_confluence_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("atlassian_confluence/installed");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"Atlassian Confluence is prone to a cross-site scripting vulnerability
  because it fails to sufficiently sanitize user-supplied data.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site. This may allow the attacker
  to steal cookie-based authentication credentials and to launch other attacks.");

  script_tag(name:"affected", value:"Atlassian Confluence versions prior to 4.1.9 are vulnerable.");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("url_func.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!dir = get_app_location(cpe:CPE, port:port))exit(0);

js = urlencode(str:'<IFRAME SRC="javascript:alert(/xss-test/)">',unreserved:':=/');

url = dir + '/pages/includes/status-list-mo' + js + '.vm';

if(http_vuln_check(port:port, url:url,pattern:'<IFRAME SRC="javascript:alert\\(/xss-test/\\)">',check_header:TRUE)) {
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
