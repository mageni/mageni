# OpenVAS Vulnerability Test
# Description: RemotelyAnywhere Cross Site Scripting
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2003 Noam Rathaus
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
  script_oid("1.3.6.1.4.1.25623.1.0.11950");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(9202);
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_name("RemotelyAnywhere Cross Site Scripting");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("RemotelyAnywhere/banner");
  script_require_ports("Services/www", 2000, 2001);

  script_tag(name:"solution", value:"Upgrade to the newest version of this software.");

  script_tag(name:"summary", value:"The remote RemotelyAnywhere web interface is vulnerable to a cross site
  scripting issue.");

  script_tag(name:"impact", value:"A vulnerability in RemotelyAnywhere's web interface allows a remote
  attacker to inject malicious text into the login screen, this can be used by an attacker to make the
  user do things he would otherwise not do (for example, change his password after a successful login to
  some string provided by the malicious text).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:2001);
banner = get_http_banner(port : port);
if(!banner || !ereg(pattern:"Server: *RemotelyAnywhere", string:banner))
  exit(0);

url = "/default.html?logout=asdf&reason=Please%20set%20your%20password%20to%20ABC123%20after%20login";
req = http_get(item:url, port:port);
res = http_keepalive_send_recv(data:req, port:port, bodyonly:TRUE);
if(!res)
  exit(0);

if("Please set your password to ABC123 after login" >< res) {
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);