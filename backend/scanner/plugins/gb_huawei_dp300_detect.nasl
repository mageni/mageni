###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_huawei_dp300_detect.nasl 14045 2019-03-08 07:18:46Z cfischer $
#
# Huawei DP300 Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.141253");
  script_version("$Revision: 14045 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 08:18:46 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-07-02 09:32:17 +0200 (Mon, 02 Jul 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Huawei DP300 Detection");

  script_tag(name:"summary", value:"Detection of Huawei DP300.

  The script sends a connection request to the server and attempts to detect Huawei DP300 and to extract its
  version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 5000);
  script_mandatory_keys("telnet/huawei/dp300/detected");

  script_xref(name:"URL", value:"https://e.huawei.com/en/products/cloud-communications/telepresence-video-conferencing/personal-systems/dp300");

  exit(0);
}

include("cpe.inc");
include("dump.inc");
include("host_details.inc");
include("misc_func.inc");
include("telnet_func.inc");

port = get_telnet_port(default: 5000);
banner = get_telnet_banner(port: port);
if (!banner)
  exit(0);

if ("Huawei DP300" >< banner) {
  version = "unknown";

  banner = bin2string(ddata: banner, noprint_replacement: ' ');

  # dddd?H.....R...\u000cHuawei DP300...> DP300 V500R002C00SPC200 Release 2.0.200  Mar 28 2016 00:55:41dddd?L.....\u000bDH_ALGORITH
  vers = eregmatch(pattern: "DP300 (V[^ ]+)", string: banner);
  if (!isnull(vers[1]))
    version = vers[1];

  rel = eregmatch(pattern: "Release ([0-9.]+)", string: banner);
  if (!isnull(rel[1])) {
    set_kb_item(name: "huawei_dp300/release", value: rel[1]);
    extra = "Release:   " + rel[1];
  }

  set_kb_item(name: "huawei_dp300/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^(V[0-9A-Z]+)", base: "cpe:/h:huawei:dp300:");
  if (!cpe)
    cpe = 'cpe:/h:huawei:dp300';

  register_product(cpe: cpe, location: port + '/tcp', port: port, service: "telnet");

  log_message(data: build_detection_report(app: "Huawei DP300", version: version, install: port + '/tcp',
                                           cpe: cpe, concluded: vers[0], extra: extra),
              port: port);
}

exit(0);