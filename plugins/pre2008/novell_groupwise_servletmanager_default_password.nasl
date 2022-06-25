# OpenVAS Vulnerability Test
# Description: Novell Groupwise Servlet Manager default password
#
# Authors:
# David Kyger <david_kyger@symantec.com>
#
# Copyright:
# Copyright (C) 2004 David Kyger
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
  script_oid("1.3.6.1.4.1.25623.1.0.12122");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(3697);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2001-1195");
  script_name("Novell Groupwise Servlet Manager default password");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2004 David Kyger");
  script_family("Netware");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3697");

  script_tag(name:"solution", value:"Change the default password

  Edit SYS:\JAVA\SERVLETS\SERVLET.PROPERTIES

  change the username and password in this section:

  servlet.ServletManager.initArgs=datamethod=POST, user=servlet, password=manager, bgcolor");

  script_tag(name:"summary", value:"The Novell Groupwise servlet server is configured with the default password.");

  script_tag(name:"impact", value:"As a result, users could be denied access to mail and other servlet
  based resources.");

  script_tag(name:"insight", value:"To test this finding:

  https://example.com/servlet/ServletManager/

  enter 'servlet' for the user and 'manager' for the password.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:443);

url = "/servlet/ServletManager";
req = http_get_req(port:port, url:url, add_headers:make_array("Authorization", "Basic c2VydmxldDptYW5hZ2Vy"));
buf = http_keepalive_send_recv(port:port, data:req);
if(!buf)
  exit(0);

if("ServletManager" >< buf && "Servlet information" >< buf) {
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);