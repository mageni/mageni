###############################################################################
# OpenVAS Vulnerability Test
#
# Connect back to SOCKS5 server
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.17156");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_name("Connect back to SOCKS5 server");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2005 Michel Arboi");
  script_family("Denial of Service");
  script_dependencies("socks.nasl");
  script_require_ports("Services/socks5", 1080);
  script_mandatory_keys("socks5/detected");

  script_tag(name:"summary", value:"It was possible to connect to the SOCKS5 server
  through itself.");

  script_tag(name:"impact", value:"This allow anybody to saturate the proxy CPU, memory or
  file descriptors.");

  script_tag(name:"solution", value:"Reconfigure your proxy so that it refuses connections to itself.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("misc_func.inc");

port = get_port_for_service(default:1080, proto:"socks5");

s = open_sock_tcp(port);
if(!s)
  exit(0);

req5 = raw_string(5, 3, 0, 1, 2);
send(socket:s, data:req5);
data = recv(socket:s, length:2);

p2 = port % 256;
p1 = port / 256;
a = split(get_host_ip(), sep:'.');

cmd =
raw_string(5, 1, 0, 1, int(a[0]), int(a[1]), int(a[2]), int(a[3]), p1, p2);

for (i = 3; i >= 0; i--) {
  send(socket:s, data:cmd);
  data = recv(socket:s, length:10, min:10);
  if(strlen(data) != 10 || ord(data[0]) != 5 || ord(data[1]) != 0)
    break;
}

close(s);
if(i < 0) {
  security_message(port:port);
  exit(0);
}

exit(99);