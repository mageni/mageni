# Copyright (C) 2019 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143230");
  script_version("2019-12-05T09:50:53+0000");
  script_tag(name:"last_modification", value:"2019-12-05 09:50:53 +0000 (Thu, 05 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-12-05 09:10:43 +0000 (Thu, 05 Dec 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2019-19492");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("FreeSWITCH mod_event_socket Default Password Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_freeswitch_mod_event_socket_service_detect.nasl");
  script_require_ports("Services/mod_event_socket", 8021);

  script_tag(name:"summary", value:"FreeSWITCH mod_event_socket has a default password set.");

  script_tag(name:"impact", value:"An attacker can use this password to e.g. execute commands via the sytstem
  api to compromise the host.");

  script_tag(name:"vuldetect", value:"Tries to authenticate and checks the response.");

  script_tag(name:"solution", value:"Change the default password in event_socket.conf.xml.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/47698");

  exit(0);
}

include("misc_func.inc");

port = get_port_for_service(default: 8021, proto: "mod_event_socket");

soc = open_sock_tcp(port);
if (!soc)
  exit(0);

password = "ClueCon";
data = "auth " + password + '\n\n';

recv = recv(socket: soc, length: 512);
if (recv !~ "^Content-Type: auth/request") {
  close(soc);
  exit(99);
}

send(socket: soc, data: data);
recv = recv(socket: soc, length: 512);
close(soc);

if ("Content-Type: command/reply" >!< recv)
  exit(0);

if ("Reply-Text: +OK accepted" >< recv) {
  report = "It was possible to authenticate with the default password '" + password + "'.";
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
