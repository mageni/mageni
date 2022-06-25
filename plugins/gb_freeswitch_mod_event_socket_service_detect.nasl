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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143229");
  script_version("2019-12-06T09:54:56+0000");
  script_tag(name:"last_modification", value:"2019-12-06 09:54:56 +0000 (Fri, 06 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-12-05 08:18:24 +0000 (Thu, 05 Dec 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("FreeSWITCH mod_event_socket Service Detection");

  script_tag(name:"summary", value:"A FreeSWITCH mod_event_socket service is running at this host.

  mod_event_socket is a TCP-based interface to control FreeSWITCH.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 8021);

  script_xref(name:"URL", value:"https://freeswitch.org/confluence/display/FREESWITCH/mod_event_socket");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

port = get_unknown_port(default: 8021);

soc = open_sock_tcp(port);
if (!soc)
  exit(0);

recv = recv(socket: soc, length: 512);
close(soc);

if (recv =~ "^Content-Type: auth/request" || recv =~ "^Content-Type: text/rude-rejection") {
  set_kb_item(name: "freeswitch/detected", value: TRUE);
  set_kb_item(name: "freeswitch/mod_event_socket/port", value: port);

  register_service(port: port, ipproto: "tcp", proto: "mod_event_socket");

  report = 'A FreeSWITCH mod_event_socket is running at this port.\n\nServer Response:\n\n' + recv;
  log_message(port: port, data: report);

  exit(0);
}

exit(0);
