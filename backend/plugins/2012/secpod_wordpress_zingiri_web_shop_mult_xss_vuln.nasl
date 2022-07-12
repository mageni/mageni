##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wordpress_zingiri_web_shop_mult_xss_vuln.nasl 11888 2018-10-12 15:27:49Z cfischer $
#
# WordPress Zingiri Web Shop Plugin Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902831");
  script_version("$Revision: 11888 $");
  script_cve_id("CVE-2012-6506");
  script_bugtraq_id(53278);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-04-21 11:02:32 +0200 (Fr, 21 Apr 2017)$");
  script_tag(name:"creation_date", value:"2012-04-27 14:14:14 +0530 (Fri, 27 Apr 2012)");
  script_name("WordPress Zingiri Web Shop Plugin Multiple Cross Site Scripting Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright(c)2012 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  script_xref(name:"URL", value:"http://1337day.com/exploits/18135");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18787");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/112216/WordPress-Zingiri-Web-Shop-2.4.0-Cross-Site-Scripting.html");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.");

  script_tag(name:"affected", value:"WordPress Zingiri Web Shop Plugin Version 2.4.0 and prior");

  script_tag(name:"insight", value:"Multiple flaws are due to improper validation of user-supplied input
  passed to 'page' and 'notes' parameters, which allows attackers to execute
  arbitrary HTML and script code in a user's browser session in the context
  of an affected site.");

  script_tag(name:"solution", value:"Upgrade to WordPress Zingiri Web Shop Plugin 2.4.1 or later.");

  script_tag(name:"summary", value:"This host is running WordPress Zingiri Web Shop Plugin and is prone
  to multiple cross site scripting vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/zingiri-web-shop/");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!dir = get_app_location(cpe:CPE, port:port)) exit(0);

if(dir == "/") dir = "";
url = dir + '/?page="><script>alert(document.cookie)</script>';

if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:"<script>alert\(document\.cookie\)</script>", extra_check:"Zingiri Web Shop")){
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);