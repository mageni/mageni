###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moodle_46085.nasl 12104 2018-10-25 16:22:27Z asteins $
#
# Moodle 'PHPCOVERAGE_HOME' Cross Site Scripting Vulnerability
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


if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103056");
  script_version("$Revision: 12104 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 18:22:27 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-02-02 13:26:27 +0100 (Wed, 02 Feb 2011)");
  script_bugtraq_id(46085);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Moodle 'PHPCOVERAGE_HOME' Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/46085");
  script_xref(name:"URL", value:"http://www.moodle.org");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("moodle/detected");
  script_tag(name:"summary", value:"Moodle is prone to a cross-site scripting vulnerability because it
  fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"Exploiting this vulnerability may allow an attacker to perform cross-
  site scripting attacks on unsuspecting users in the context of the
  affected website. As a result, the attacker may be able to steal cookie-
  based authentication credentials and to launch other attacks.");

  script_tag(name:"affected", value:"Versions prior to Moodle 2.0.1 are vulnerable.");
  script_tag(name:"solution", value:"Upgrade to the latest version.");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

CPE = "cpe:/a:moodle:moodle";

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!dir = get_app_location(cpe:CPE, port:port)) exit(0);

if(dir == "/") dir = "";

url = string(dir,"/lib/spikephpcoverage/src/phpcoverage.remote.top.inc.php?PHPCOVERAGE_HOME=<script>alert(document.cookie)</script>");

if(http_vuln_check(port:port, url:url, pattern:"<script>alert\(document.cookie\)</script>", check_header:TRUE, extra_check:make_list("ERROR: Could not locate PHPCOVERAGE_HOME"))) {
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
