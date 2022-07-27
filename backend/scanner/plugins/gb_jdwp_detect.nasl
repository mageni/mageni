# Copyright (C) 2020 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143507");
  script_version("2020-02-20T07:23:20+0000");
  script_tag(name:"last_modification", value:"2020-02-20 07:23:20 +0000 (Thu, 20 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-12 06:40:55 +0000 (Wed, 12 Feb 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Java Debug Wire Protocol (JDWP) Service Detection");

  script_tag(name:"summary", value:"A Java Debug Wire Protocol (JDWP) service is running at this host.

  The Java Debug Wire Protocol (JDWP) is the protocol used for communication between a debugger and the Java
  virtual machine (VM) which it debugs.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service1.nasl", "find_service2.nasl", "find_service3.nasl", "find_service4.nasl",
                      "find_service5.nasl", "find_service6.nasl", "nessus_detect.nasl"); # nessus_detect.nasl to avoid double check for echo tests.
  script_require_ports("Services/jdwp", 8000);

  exit(0);
}

include("dump.inc");
include("host_details.inc");
include("misc_func.inc");

# https://docs.oracle.com/javase/8/docs/technotes/guides/jpda/jdwp-spec.html
# https://docs.oracle.com/javase/7/docs/platform/jpda/jdwp/jdwp-protocol.html

port = get_port_for_service(default: 8000, proto: "jdwp");

# nb: Set by nessus_detect.nasl if we have hit a service which echos everything back
if (get_kb_item("generic_echo_test/" + port + "/failed"))
  exit(0);

# nb: Set by nessus_detect.nasl as well. We don't need to do the same test multiple times...
if (!get_kb_item("generic_echo_test/" + port + "/tested")) {
  soc = open_sock_tcp(port);
  if (!soc)
    exit(0);

  send(socket: soc, data: "TestThis\r\n");
  r = recv_line(socket: soc, length: 10);
  close(soc);
  # We don't want to be fooled by echo & the likes
  if ("TestThis" >< r) {
    set_kb_item(name: "generic_echo_test/" + port + "/failed", value: TRUE);
    exit(0);
  }
}

sock = open_sock_tcp(port);
if (!sock)
  exit(0);

msg = "JDWP-Handshake";
send(socket:sock, data: msg);
recv = recv(socket: sock, length: 512);

if (recv != msg) {
  close(soc);
  exit(0);
}

set_kb_item(name: "jdwp/detected", value: TRUE);

register_service(port: port, proto: "jdwp");

data = raw_string(0x00, 0x00, 0x00, 0x0b, # length
                  0x00, 0x00, 0x00, 0x01, # id
                  0x00,                   # flags
                  0x01,                   # command set (VirtualMachine Command Set (1))
                  0x01);                  # command (Version command)
send(socket:sock, data: data);
recv = recv(socket: sock, length: 1024);

close(soc);

if (recv && strlen(recv) > 16) {
  recv = substr(recv, 15); # header + 4 bytes for 1st data length
  recv = bin2string(ddata: recv, noprint_replacement: " ");
  info = recv;
}

report = "A Java Debug Wired Protocol (JDWP) service is running at this port.";

if (info)
  report += '\n\nThe following information could be extracted:\n\n' + info;

log_message(port: port, data: report);

exit(0);

