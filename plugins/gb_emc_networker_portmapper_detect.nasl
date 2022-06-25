# Copyright (C) 2011 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103123");
  script_version("2021-11-24T11:16:33+0000");
  script_tag(name:"last_modification", value:"2021-11-25 11:06:48 +0000 (Thu, 25 Nov 2021)");
  script_tag(name:"creation_date", value:"2011-03-23 13:28:27 +0100 (Wed, 23 Mar 2011)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Dell EMC NetWorker Detection (PortMapper)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports(7938);

  script_tag(name:"summary", value:"PortMapper based detection of Dell EMC NetWorker.");

  exit(0);
}

include("port_service_func.inc");
include("host_details.inc");

port = 7938;
if (!get_port_state(port))
  exit(0);

soc = open_sock_tcp(port);
if (!soc)
  exit(0);

req = raw_string(0x80, 0, 0, 0x38, rand() % 256, rand() % 256, rand() % 256, rand() % 256, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x86, 0xA0, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03,
                 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x01, 0x05, 0xf3, 0xe1, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00);

send(socket: soc, data: req);
buf = recv(socket: soc, length: 32);
close(soc);

if (strlen(buf) != 32 || ord(buf[0]) != 128)
  exit(0);

if (hexstr(buf) =~ "^8000001c") {

  set_kb_item(name: "emc/networker/detected", value: TRUE);
  set_kb_item(name: "emc/networker/portmapper/detected", value: TRUE);

  version = "unknown";
  cpe1 = "cpe:/a:dell:emc_networker";
  cpe2 = "cpe:/a:emc:networker";
  register_product(cpe: cpe1, location: "/", port: port, service: "emc_networker_portmapper");
  register_product(cpe: cpe2, location: "/", port: port, service: "emc_networker_portmapper");

  service_register(port: port, proto: "emc_networker_portmapper");

  log_message(data: build_detection_report(app: "Dell EMC NetWorker", version: version, install: "/",
                                           cpe: cpe1),
              port: port);

}

exit(0);