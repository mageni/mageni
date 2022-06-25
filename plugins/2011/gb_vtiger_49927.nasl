###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vtiger_49927.nasl 12926 2019-01-03 03:38:48Z ckuersteiner $
#
# vtiger CRM Multiple Cross Site Scripting Vulnerabilities
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

CPE = "cpe:/a:vtiger:vtiger_crm";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103290");
  script_version("$Revision: 12926 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-03 04:38:48 +0100 (Thu, 03 Jan 2019) $");
  script_tag(name:"creation_date", value:"2011-10-06 13:32:57 +0200 (Thu, 06 Oct 2011)");
  script_cve_id("CVE-2011-4670");
  script_bugtraq_id(49927);

  script_name("vtiger CRM Multiple Cross Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49927");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2011/Oct/154");

  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_vtiger_crm_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("vtiger/detected");

  script_tag(name:"summary", value:"vtiger CRM is prone to multiple cross-site scripting vulnerabilities
because it fails to properly sanitize user-supplied input.

An attacker may leverage these issues to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may allow the attacker to steal cookie-based authentication
credentials and to launch other attacks.

vtiger CRM 5.2.1 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!dir = get_app_location(cpe:CPE, port:port))exit(0);

if (dir == "/")
  dir = "";

url = dir + '/phprint.php?module=Home&action=--><script>alert(/openvas-xss-test/)</script>&parenttab=MyHomePage"><script>alert(/openvas-xss-test/)</script>&jt=';

if (http_vuln_check(port:port, url:url, pattern:"<script>alert\(/openvas-xss-test/\)</script>",
                    check_header:TRUE)) {
  report = report_vuln_url(port: port, url: url);
  security_message(port:port, data: report);
  exit(0);
}

exit(99);
