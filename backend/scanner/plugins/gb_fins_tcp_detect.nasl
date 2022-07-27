###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fins_tcp_detect.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# Factory Interface Network Service (FINS) Detection (TCP)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.140512");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-11-20 16:46:39 +0700 (Mon, 20 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Factory Interface Network Service (FINS) Detection (TCP)");

  script_tag(name:"summary", value:"A Factory Interface Network Service (FINS) over TCP is running at this host.

Factory Interface Network Service, is a network protocol used by Omron PLCs. The FINS communications service was
developed by Omron to provide a consistent way for PLCs and computers on various networks to communicate.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports(9600);

  script_xref(name:"URL", value:"http://www.omron.com/");

  exit(0);
}

include("host_details.inc");
include("dump.inc");
include("misc_func.inc");

# based on https://github.com/digitalbond/Redpoint/blob/master/omrontcp-info.nse

port = 9600;

if (!get_port_state(port))
  exit(0);

soc = open_sock_tcp(port);
if (!soc)
  exit(0);

# request address command
req_addr = raw_string(0x46, 0x49, 0x4e, 0x53, 0x00, 0x00, 0x00, 0x0c,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00);

# Parts for the read controller data command
ctrl_data_read1 = raw_string(0x46, 0x49, 0x4e, 0x53, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00,
                            0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x02, 0x00);
ctrl_data_read2 = raw_string( 0x00, 0x00, 0x00, 0xef, 0x05, 0x05, 0x01, 0x00);

# request an address
send(socket: soc, data: req_addr);
recv = recv(socket: soc, length: 512);

if (!recv || recv !~ "^FINS" || strlen(recv) < 24) {
  close(soc);
  exit(0);
}

addr = recv[23];
ctrl_data_read = ctrl_data_read1 + addr + ctrl_data_read2;

# request the controller data
send(socket: soc, data: ctrl_data_read);
recv = recv(socket: soc, length: 512);
close(soc);

if (recv && recv =~ "^FINS" && strlen(recv) >= 65) {
  # Some more information could be extracted (memory card type, program area size, etc) but this doesn't really
  # add some valuable info for vulnerability scanning.
  model = bin2string(ddata: substr(recv, 30, 59), noprint_replacement: '');
  set_kb_item(name: "fins/model", value: model);
  version = bin2string(ddata: substr(recv, 60, 64), noprint_replacement: '');
  set_kb_item(name: "fins/version", value: version);
}

set_kb_item(name: "fins/detected", value: TRUE);

register_service(port: port, proto: "fins", ipproto: "tcp");

report = "A FINS service is running at this port.\n";

if (model || version) {
  report += "\nThe following information was extracted:\n\n" +
            "Controller Model:      " + model + "\n" +
            "Controller Version:    " + version + "\n";
}

log_message(port: port, data: report);

exit(0);