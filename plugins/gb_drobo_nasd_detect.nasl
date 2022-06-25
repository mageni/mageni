# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.142077");
  script_version("$Revision: 14009 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-06 09:10:00 +0100 (Wed, 06 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-03-06 10:14:54 +0700 (Wed, 06 Mar 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Drobo NASd Detection");

  script_tag(name:"summary", value:"Detection of Drobo NASd.

The script sends a connection request to the server and attempts to detect Drobo NASd.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 5000);

  exit(0);
}

include("dump.inc");
include("host_details.inc");
include("misc_func.inc");

port = get_unknown_port(default: 5000);

soc = open_sock_tcp(port);
if (!soc)
  exit(0);

res = recv(socket: soc, length: 9096);
if (!res)
  exit(0);
res = bin2string(ddata: res, noprint_replacement: "");

if ('<ESATMUpdate>' >< res && "DRINASD" >< res) {
  set_kb_item(name: "drobo/nas/detected", value: TRUE);
  set_kb_item(name: "drobo/nasd/detected", value: TRUE);
  set_kb_item(name: "drobo/nasd/port", value: port);

  # <mModel>Drobo 5N</mModel>
  model = eregmatch(pattern: "<mModel>([^<]+)", string: res);
  if (!isnull(model[1]))
    set_kb_item(name: "drobo/nasd/model", value: model[1]);
  # <mVersion>3.5.13 [8.99.91806]</mVersion>
  version = eregmatch(pattern: "<mVersion>([^<]+)", string: res);
  if (!isnull(version[1])) {
    version = str_replace(string: version[1], find: " ", replace: "");
    version = str_replace(string: version, find: "[", replace: ".");
    version = str_replace(string: version, find: "]", replace: "");
    version = str_replace(string: version, find: "-", replace: ".");
    set_kb_item(name: "drobo/nasd/fw_version", value: version);
  }
  # <mESAID>drb131001a00527</mESAID>
  esaid = eregmatch(pattern: "<mESAID>([^<]+)", string: res);
  if (!isnull(esaid[1]))
    set_kb_item(name: "drobo/nasd/esaid", value: esaid[1]);

  register_service(port: port, proto: "drobo-nasd");
}

exit(0);
