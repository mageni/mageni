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
  script_oid("1.3.6.1.4.1.25623.1.0.143207");
  script_version("2019-12-03T03:57:00+0000");
  script_tag(name:"last_modification", value:"2019-12-03 03:57:00 +0000 (Tue, 03 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-12-02 10:02:20 +0000 (Mon, 02 Dec 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Java JMX Insecure Configuration Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_rmi_registry_detect.nasl");
  script_require_ports("Services/rmi_registry", 1099);

  script_tag(name:"summary", value:"The Java JMX interface is configured in an insecure way by allowing
  unauthenticated attackers to load classes from any remote URL.");

  script_tag(name:"vuldetect", value:"Sends crafted RMI requests and checks the responses.");

  script_tag(name:"solution", value:"Enable password authentication and/or SSL client certificate authentication
  for the JMX agent.");

  script_xref(name:"URL", value:"https://mogwailabs.de/blog/2019/04/attacking-rmi-based-jmx-services/");
  script_xref(name:"URL", value:"https://www.optiv.com/blog/exploiting-jmx-rmi");
  script_xref(name:"URL", value:"https://www.rapid7.com/db/modules/exploit/multi/misc/java_jmx_server");

  exit(0);
}

include("byte_func.inc");
include("host_details.inc");
include("misc_func.inc");

function rmi_connect(socket) {
  local_var socket, req, recv;

  req = 'JRMI' + raw_string(0x00, 0x02, 0x4b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
  send(socket: socket, data: req);
  recv = recv(socket: socket, length: 128, min: 7);

  if (hexstr(recv[0]) != '4e' || (getword(blob: recv, pos: 1) + 7) != strlen(recv))
    return FALSE;
  else
    return TRUE;
}

function rmi_parse_res(data) {
  local_var data, port, obj_id, result, class, rmi_classes, class_found;

  result = make_array();

  rmi_classes = make_list("javax.management.remote.rmi.RMIConnectionImpl",
                          "javax.management.remote.rmi.RMIConnectionImpl_Stub",
                          "javax.management.remote.rmi.RMIConnector",
                          "javax.management.remote.rmi.RMIConnectorServer",
                          "javax.management.remote.rmi.RMIIIOPServerImpl",
                          "javax.management.remote.rmi.RMIJRMPServerImpl",
                          "javax.management.remote.rmi.RMIServerImpl",
                          "javax.management.remote.rmi.RMIServerImpl_Stub",
                          "javax.management.remote.rmi.RMIConnection",
                          "javax.management.remote.rmi.RMIServer");

  if ("javax.management.remote.rmi" >!< data || "UnicastRef" >!< data)
    return NULL;

  foreach class (rmi_classes) {
    if (raw_string(class, 0x00) >< data) {
      class_found = TRUE;
      break;
    }
  }

  if (!class_found)
    return NULL;

  data = strstr(data, "UnicastRef");
  if (strlen(data) < 37)
    return NULL;

  pos = 10;
  if ("UnicastRef2" >< data)
    pos += 2;

  len = getword(blob: data, pos: pos);
  pos += len + 4;

  port = getword(blob: data, pos: pos);
  pos += 2;
  obj_id = substr(data, pos, pos + 21);
  result["port"] = port;
  result["obj_id"] = obj_id;

  return result;
}

port = get_port_for_service(default: 1099, proto: "rmi_registry");

soc = open_sock_tcp(port);
if (!soc)
  exit(0);

if (!rmi_connect(socket: soc)) {
  close(soc);
  exit(0);
}

# Lookup for jmxrmi
lookup = raw_string(0x50, 0xac, 0xed, 0x00, 0x05, 0x77, 0x22, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x02, 0x44, 0x15, 0x4d, 0xc9, 0xd4, 0xe6, 0x3b,
                    0xdf, 0x74, 0x00, 0x06, 0x6a, 0x6d, 0x78, 0x72, 0x6d, 0x69);

send(socket: soc, data: lookup);
recv = recv(socket: soc, length: 4096, min: 2);

close(soc);

# Parse for the endpoint (RMI port, Object ID)
info = rmi_parse_res(data: recv);
if (isnull(info))
  exit(0);

rmi_port = info["port"];
obj_id = info["obj_id"];

soc = open_sock_tcp(rmi_port);
if (!soc)
  exit(0);

if (!rmi_connect(socket: soc)) {
  close(soc);
  exit(0);
}

data = raw_string(obj_id, 0xff, 0xff, 0xff, 0xff, 0xf0, 0xe0, 0x74, 0xea, 0xad, 0x0c, 0xae, 0xa8);
req = raw_string(0x50, 0xac, 0xed, 0x00, 0x05, 0x77, mkbyte(strlen(data)), data, 0x70);

send(socket: soc, data: req);
recv = recv(socket: soc, length: 8192, min: 2);

close(soc);

if ("javax.management.remote.rmi.RMIConnectionImpl_Stub" >< recv && "Exception" >!< recv) {
  report = "It was possible to call 'javax.management.remote.rmi.RMIServer.newClient' on the RMI port " + rmi_port +
           "/tcp without providing any credentials.";
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
