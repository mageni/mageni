###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moxa_miineport_telnet_detect.nasl 13624 2019-02-13 10:02:56Z cfischer $
#
# Moxa MiiNePort Detection (Telnet)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.106467");
  script_version("$Revision: 13624 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-13 11:02:56 +0100 (Wed, 13 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-12-12 11:02:51 +0700 (Mon, 12 Dec 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Moxa MiiNePort Detection (Telnet)");

  script_tag(name:"summary", value:"Detection of Moxa MiiNePort devices.

  The script sends a telnet connection request to the device and attempts to detect the presence of Moxa MiiNePort\and to extract its version.");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/moxa/miineport/detected");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("telnet_func.inc");

port = get_telnet_port(default: 23);
banner = get_telnet_banner(port: port);
if (!banner || banner !~ "Model name\s*:\s*MiiNePort ")
  exit(0);

version = "unknown";
build = "unknown";

vers = eregmatch(pattern: 'Firmware version\\s*:\\s*([0-9.]+) Build ([0-9]+[^ \r\n])', string: banner);
if (!isnull(vers[1])) {
  version = vers[1];
  set_kb_item(name: "moxa/miineport/version", value: version);
}

if (!isnull(vers[2])) {
  build = vers[2];
  set_kb_item(name: "moxa/miineport/build", value: build);
}

mod = eregmatch(pattern: 'Model name\\s*:\\s*MiiNePort ([^ \r\n]+)', string: banner);
if (!isnull(mod[1])) {
  model = mod[1];
  set_kb_item(name: "moxa/miineport/model", value: model);
}

set_kb_item(name: "moxa/miineport/detected", value: TRUE);

cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:moxa:miineport:");
if (!cpe)
  cpe = 'cpe:/a:moxa:miineport';

register_product(cpe: cpe, location: port + "/tcp", port: port, service: 'telnet');

log_message(data: build_detection_report(app: "Moxa MiiNePort " + model, version: version, install: port + '/tcp',
                                         cpe: cpe, concluded: vers[0], extra: "Build: " + build),
            port: port);

exit(0);