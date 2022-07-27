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
  script_oid("1.3.6.1.4.1.25623.1.0.143177");
  script_version("2019-11-26T05:57:42+0000");
  script_tag(name:"last_modification", value:"2019-11-26 05:57:42 +0000 (Tue, 26 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-11-26 04:42:17 +0000 (Tue, 26 Nov 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Apache ZooKeeper Detection");

  script_tag(name:"summary", value:"Detection of Apache ZooKeeper.

  The script sends a connection request to the server and attempts to detect Apache ZooKeeper and extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 2181);

  script_xref(name:"URL", value:"https://zookeeper.apache.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("misc_func.inc");

port = get_unknown_port(default: 2181);

sock = open_sock_tcp(port);
if (!sock)
  exit(0);

send(socket: sock, data: "stat");
recv = recv(socket: sock, length: 2048);
close(sock);

# Zookeeper version: 3.4.14-4c25d480e66aadd371de8bd2fd8da255ac140bcf, built on 03/06/2019 16:18 GMT
# Clients:
#  /127.0.0.1:56814[1](queued=0,recved=1119291,sent=1119295)
#
# Latency min/avg/max: 0/0/23
# Received: 1119410
# Sent: 1119413
# Connections: 2
# Outstanding: 0
# Zxid: 0xca
# Mode: standalone
# Node count: 156
if ("Zookeeper version" >!< recv)
  exit(0);

version = "unknown";

vers = eregmatch(pattern: "Zookeeper version: ([0-9.]+)", string: recv);
if (!isnull(vers[1]))
  version = vers[1];

set_kb_item(name: "apache/zookeeper/detected", value: TRUE);

cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:apache:zookeeper:");
if (!cpe)
  cpe = "cpe:/a:apache:zookeeper";

register_service(port: port, ipproto: "tcp", proto: "zookeeper");
register_product(cpe: cpe, location: "/", port: port, service: "zookeeper");

extra = '\nFull server response:\n\n' + recv;

log_message(data: build_detection_report(app: "Apache ZooKeeper", version: version, install: "/", cpe: cpe,
                                         concluded: vers[0], extra: extra),
            port: port);

exit(0);
