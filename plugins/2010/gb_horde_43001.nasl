###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_horde_43001.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# Horde Application Framework 'icon_browser.php' Cross-Site Scripting Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

CPE = 'cpe:/a:horde:horde_groupware';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100787");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-09-07 15:26:31 +0200 (Tue, 07 Sep 2010)");
  script_cve_id("CVE-2010-3077", "CVE-2010-3694");
  script_bugtraq_id(43001);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Horde Application Framework 'icon_browser.php' Cross-Site Scripting Vulnerability");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("horde_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("horde/installed");

  script_tag(name:"solution", value:"The vendor has patched this issue in the latest GIT repository. Contact the
  vendor for more information.");

  script_tag(name:"summary", value:"Horde Framework is prone to a cross-site scripting vulnerability because it
  fails to sufficiently sanitize user-supplied data.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script code in the
  browser of an unsuspecting user in the context of the affected site. This may help the attacker steal cookie-based
  authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"This issue affects versions prior to and including Horde 3.3.8.

  Note that additional products that use the Horde framework may also be vulnerable.");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/43001");
  script_xref(name:"URL", value:"http://git.horde.org/diff.php/horde/util/icon_browser.php?rt=horde-git&r1=a978a35c3e95e784253508fd4333d2fbb64830b6&r2=9342addbd2b95f184f230773daa4faf5ef6d65e9");
  script_xref(name:"URL", value:"http://www.horde.org");
  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
include("url_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

ex = string("<body onload=alert('vt-xss-test')>");

url = dir + "/util/icon_browser.php?subdir=" + urlencode(str:ex) + "&app=horde";

if (http_vuln_check(port:port, url:url, pattern:"<body onload=alert\('vt-xss-test'\)>. not found",
                    extra_check:"Subdirectory", check_header:TRUE)) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);