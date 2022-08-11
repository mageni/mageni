###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_proconos_detect.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# ProConOS Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.140498");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-11-13 10:14:34 +0700 (Mon, 13 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ProConOS Detection");

  script_tag(name:"summary", value:"A ProConOS Service is running at this host.

ProConOS is a high performance PLC run time engine designed for both embedded and PC based control applications.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports(20547);

  script_xref(name:"URL", value:"https://www.plantautomation.com/doc/proconos-0001");

  exit(0);
}

include("host_details.inc");
include("dump.inc");
include("misc_func.inc");

port = 20547;

if (!get_port_state(port))
  exit(0);

soc = open_sock_tcp(port);
if (!soc)
  exit(0);

# info query (see https://github.com/digitalbond/Redpoint/blob/master/proconos-info.nse)
query = raw_string(0xcc, 0x01, 0x00, 0x0b, 0x40, 0x02, 0x00, 0x00, 0x47, 0xee);
send(socket: soc, data: query);
recv = recv(socket: soc, length: 1024);
close(soc);

if (hexstr(substr(recv, 0, 1)) != "cc01")
  exit(0);

# Ladder Logic Runtime
# e.g. ProConOS V4.1.0267 Jul 31 2012
llr = bin2string(ddata: substr(recv, 12, 43), noprint_replacement: '');
set_kb_item(name: "proconos/llr", value: llr);

# PLC Type
# e.g Bristol: CWM V05:50:00 07/31
type = bin2string(ddata: substr(recv, 44, 75), noprint_replacement: '');
set_kb_item(name: "proconos/type", value: type);

# Project Name
# e.g. 28Commercia
prj_name = bin2string(ddata: substr(recv, 76, 87), noprint_replacement: '');

# Boot Project
# e.g. 28Commercia
boot_prj = bin2string(ddata: substr(recv, 88, 99), noprint_replacement: '');

# Project Source Code
# e.g. Exist
src = bin2string(ddata: substr(recv, 100, 105), noprint_replacement: '');

set_kb_item(name: "proconos/detected", value: TRUE);

register_service( port: port, proto: "proconos");

report = 'A ProConOS service is running at this port.\n\nThe following information was extracted:\n\n' +
         "Ladder Logic Runtime:  " + llr + '\n' +
         "PLC Type:              " + type + '\n' +
         "Project Name:          " + prj_name + '\n' +
         "Boot Project:          " + boot_prj + '\n' +
         "Project Source Code:   " + src + '\n';

log_message(port: port, data: report);

exit(0);
