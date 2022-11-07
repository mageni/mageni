# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.148849");
  script_version("2022-11-03T10:20:15+0000");
  script_tag(name:"last_modification", value:"2022-11-03 10:20:15 +0000 (Thu, 03 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-11-02 14:27:36 +0000 (Wed, 02 Nov 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Erlang Port Mapper Daemon (epmd) Detection");

  script_tag(name:"summary", value:"Detection of Erlang Port Mapper Daemon (epmd).");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 4369);

  script_xref(name:"URL", value:"https://www.erlang.org/doc/man/epmd.html");

  exit(0);
}

include("dump.inc");
include("host_details.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = unknownservice_get_port(default: 4369);

soc = open_sock_tcp(port);
if (!soc)
  exit(0);

query = raw_string(0x00, 0x01, 0x6e);  # NAMES_REQ

send(socket: soc, data: query);
recv = recv(socket: soc, length: 512);

close(soc);

if (strlen(recv) < 4 || hexstr(substr(recv, 0, 3)) != "00001111")
  exit(0);

data = bin2string(ddata: substr(recv, 4), noprint_replacement: '\n');

if (egrep(pattern: "name.*at port", string: data)) {
  extra = '\n\nThe following port mapping was received:\n\n' + chomp(data);
  set_kb_item(name: "epmd/" + port + "/port_mapping", value: chomp(data));
}

set_kb_item(name: "epmd/detected", value: TRUE);
set_kb_item(name: "epmd/" + port + "/detected", value: TRUE);
service_register(port: port, proto: "epmd");

log_message(data: 'An Erlang Port Mapper Daemon (epmd) is running at this port.' + extra, port: port);

exit(0);
