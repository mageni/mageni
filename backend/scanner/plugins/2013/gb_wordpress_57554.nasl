###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_57554.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# WordPress Pingback Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
CPE = "cpe:/a:wordpress:wordpress";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103660");
  script_bugtraq_id(57554);
  script_cve_id("CVE-2013-0235");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_version("$Revision: 11865 $");

  script_name("WordPress Pingback Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57554");
  script_xref(name:"URL", value:"http://www.acunetix.com/blog/web-security-zone/wordpress-pingback-vulnerability/");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-02-07 10:52:18 +0100 (Thu, 07 Feb 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");
  script_tag(name:"solution", value:"Updates are available. Please see the references for more details.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"WordPress is prone to an information-disclosure vulnerability and
multiple HTML-injection vulnerabilities.

Successful exploits will allow attacker-supplied HTML and script code
to run in the context of the affected browser, potentially allowing
the attacker to steal cookie-based authentication credentials, control
how the site is rendered to the user, and disclose or modify sensitive
information. Other attacks are also possible.

WordPress versions prior to 3.5.1 are vulnerable.");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!dir = get_app_location(cpe:CPE, port:port))exit(0);

host = http_host_name(port:port);

function _check(c) {

  xml = string('<?xml version="1.0" encoding="utf-8"?>',"\r\n",
               "<methodCall>\r\n",
               "<methodName>pingback.ping</methodName>\r\n",
               "<params>\r\n",
               "<param><value><string>http://",c,"</string></value></param>\r\n",
               "<param><value><string>http://",host,dir,"?p=1</string></value></param>\r\n",
               "</params>\r\n",
               "</methodCall>\r\n");

  len = strlen(xml);

  req = string("POST ",dir,"/xmlrpc.php HTTP/1.1\r\n",
               "Host: ", host,"\r\n",
               "Connection: Close\r\n",
               "Accept-Language: en\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ",len,"\r\n",
               "\r\n",
               xml);

  result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

  value = eregmatch(pattern:"<value><string>([^<]+)</string></value>", string: result);
  if(!isnull(value[1])) return value[1];

  return FALSE;

}

url = dir + '/xmlrpc.php';

if(!http_vuln_check(port:port, url:url, pattern:"XML-RPC server accepts POST requests only"))exit(0);

if(!ret1 = _check(c:"i-dont-exist"))exit(0);

if("The source URL does not exist" >< ret1) {

  tests = make_list('localhost:22', 'localhost:25', get_host_name() + ':' + port);
  foreach test (tests) {

    ret = _check(c:test);

    if("The source URL does not contain a link to the target URL" >< ret || "We cannot find a title on that page" >< ret) {

      security_message(port:port);
      exit(0);

    }
  }

}

exit(99);

