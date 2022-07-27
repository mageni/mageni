###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_interleave_46771.nasl 13994 2019-03-05 12:23:37Z cfischer $
#
# Interleave 'basicstats.php' Multiple Cross Site Scripting Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.103112");
  script_version("$Revision: 13994 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-05 13:23:37 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-03-08 14:02:18 +0100 (Tue, 08 Mar 2011)");
  script_bugtraq_id(46771);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Interleave 'basicstats.php' Multiple Cross Site Scripting Vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_interleave_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("interleave/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46771");
  script_xref(name:"URL", value:"http://www.interleave.nl/");

  script_tag(name:"summary", value:"Interleave is prone to multiple cross-site scripting vulnerabilities
  because it fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site. This may let the attacker steal
  cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"Interleave 5.5.0.2 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
  to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

CPE = "cpe:/a:atomos:interleave";

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/") dir = "";

url = string(dir,"/basicstats.php?AjaxHandler=0&e=1&eid=2&id=3&recordid=4&templateid=5&fileid=6&tid=7&username=8&password=9&repository=10<script>alert(/vt-xss-test/)<%2fscript>&GetCSS=11&GetjQueryUiPlacementJS=12&ShowEntityList=13&ShowTable=14&nonavbar=15&tab=16&CT=17 ");

if(http_vuln_check(port:port, url:url, pattern:"<script>alert\(/vt-xss-test/\)</script>", check_header:TRUE)) {
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);