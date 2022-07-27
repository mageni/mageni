###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ethernetip_detect.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# EtherNet/IP Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.106850");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-06-09 12:24:29 +0700 (Fri, 09 Jun 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("EtherNet/IP Detection");

  script_tag(name:"summary", value:"A EtherNet/IP Service is running at this host.

EtherNet/IP is an industrial network protocol that adapts the Common Industrial Protocol to standard Ethernet.
It is widely used in a range industries including factory, hybrid and process to manage the connection between
various automation devices such as robots, PLCs, sensors, CNCs and other industrial machines.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports(44818);
  script_require_udp_ports(44818);

  exit(0);
}

include("host_details.inc");
include("byte_func.inc");
include("ethernetip.inc");
include("misc_func.inc");

function queryEthernetIP(proto, soc) {
  query = raw_string(0x63, 0x00,                    # ENCAP_CMD_LISTIDENTITY
                     0x00, 0x00,                    # encap length
                     0x00, 0x00, 0x00, 0x00,        # session id
                     0x00, 0x00, 0x00, 0x00,        # status code
                     0x00, 0x00, 0x00, 0x00,        # context information (could be random)
                     0xc1, 0xde, 0xbe, 0xd1,
                     0x00, 0x00, 0x00, 0x00);       # option flags

  send(socket: soc, data: query);
  recv = recv(socket: soc, length: 1024);

  # Error checking (command and TYPE_ID_LIST_IDENT_RESPONSE)
  if (strlen(recv) < 63 || hexstr(recv[0]) != 63 || hexstr(recv[26]) != "0c")
    exit(0);

  set_kb_item(name: "ethernetip/detected", value: TRUE);

  set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

  ip = ord(recv[36]) + '.' + ord(recv[37]) + '.' + ord(recv[38]) + '.' + ord(recv[39]);
  vendor_id = getword(blob: recv, pos: 48);
  vendor = ethip_get_vendor_name(code: vendor_id);
  set_kb_item(name: "ethernetip/vendor", value: vendor);
  dev_type_id = getword(blob: recv, pos: 50);
  dev_type = ethip_get_device_type(code: dev_type_id);
  prod_code = getword(blob: recv, pos: 52);
  revision = ord(recv[54]) + '.' + ord(recv[55]);
  set_kb_item(name: "ethernetip/revision", value: revision);
  serialno = getdword(blob: recv, pos: 58);
  prod_len = ord(recv[62]);
  product_name = substr(recv, 63, 62 + prod_len);
  set_kb_item(name: "ethernetip/product_name", value: product_name);

  register_service(port: port, ipproto: proto, proto: "ethernetip");

  report = 'A EtherNet/IP service is running at this port.\n\nThe following information was extracted:\n\n' +
           "Product Name:            " + product_name + '\n' +
           "Product Code:            " + prod_code + '\n' +
           "Vendor:                  " + vendor + '\n' +
           "Device Type:             " + dev_type + '\n' +
           "Revision:                " + revision + '\n' +
           "Serial Number:           " + serialno + '\n' +
           "IP:                      " + ip + '\n';

  log_message(data: report, port: port, proto: proto);

  return;
}

port = 44818;

if (get_port_state(port)) {
  soc = open_sock_tcp(port);

  if (soc) {
    queryEthernetIP(proto: "tcp", soc: soc);
    close(soc);
  }
}

if (get_udp_port_state(port)) {
  soc = open_sock_udp(port);

  if (soc) {
    queryEthernetIP(proto: "udp", soc: soc);
    close(soc);
  }
}

exit(0);