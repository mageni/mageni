# OpenVAS Vulnerability Test
# Description: Novell NetWare HTTP POST Perl Code Execution Vulnerability
#
# Authors:
# visigoth <visigoth@securitycentric.com>
#
# Copyright:
# Copyright (C) 2002 visigoth
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11158");
  script_version("2019-05-11T15:07:16+0000");
  script_tag(name:"last_modification", value:"2019-05-11 15:07:16 +0000 (Sat, 11 May 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(5520, 5521, 5522);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2002-1436", "CVE-2002-1437", "CVE-2002-1438");
  script_name("Novell NetWare HTTP POST Perl Code Execution Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 visigoth");
  script_family("Netware");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 2200);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Install 5.x SP5 or 6.0 SP2.

  Additionally, the enterprise manager web interface may be used to
  unmap the /perl handler entirely. If it is not being used, minimizing
  this service would be appropriate.");

  script_tag(name:"summary", value:"Novell Netware contains multiple default web server installations.

  The Netware Enterprise Web Server (Netscape/IPlanet) has a perl handler which will run arbitrary
  code given to in a POST request version 5.x (through SP4) and 6.x (through SP1) are effected.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

host = http_host_name(port:port);
url = "/perl";
req = string("POST ", url, " HTTP/1.1\r\n",
             "Content-Type: application/octet-stream\r\n",
             "Host: ", host, "\r\n",
             "Content-Length: ");
perl_code = 'print("Content-Type: text/plain\\r\\n\\r\\n", "VT-Test=", 42+42);';

length = strlen(perl_code);
data = string(req, length ,"\r\n\r\n", perl_code);
rcv = http_keepalive_send_recv(port:port, data:data);
if(!rcv)
  exit(0);

if("VT-Test=84" >< rcv) {
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);