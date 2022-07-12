###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_huawei_ibmc_upnp_detect.nasl 10902 2018-08-10 14:20:55Z cfischer $
#
# Huawei iBMC Detection (UPnP)
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
  script_oid("1.3.6.1.4.1.25623.1.0.141141");
  script_version("$Revision: 10902 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 16:20:55 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-06-06 08:31:40 +0700 (Wed, 06 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Huawei iBMC Detection (UPnP)");

  script_tag(name:"summary", value:"Detection of Huawei iBMC over UPnP.

The script sends a UPnP request to the server and attempts to detect Huawei iBMC and to extract it's
version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_upnp_detect.nasl");
  script_require_udp_ports("Services/udp/upnp", 1900);
  script_mandatory_keys("upnp/identified");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

port = get_kb_item("Services/udp/upnp");
if (!port)
  port = 1900;

if (!get_udp_port_state(port))
  exit(0);

if (!banner = get_kb_item("upnp/" + port + "/banner"))
  exit(0);

if (" iBMC/" >!< banner)
  exit(0);

version = "unknown";

# SERVER: UPnP/2.0 iBMC/2.96 ProductName/2288H SN/
vers = eregmatch(pattern: "iBMC/([0-9.]+)", string: banner);
if (!isnull(vers[1]))
  version = vers[1];

mod = eregmatch(pattern: "ProductName/([^/]+)", string: banner);
if (!isnull(mod[1])) {
  model = mod[1];
  mod_rep = " on Server Model " + model;
  replace_kb_item(name: "huawei_server/model", value: model);
}

set_kb_item(name: "huawei_ibmc/detected", value: TRUE);

cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/o:huawei:ibmc_firmware:");
if (!cpe)
  cpe = 'cpe:/o:huawei:ibmc_firmware';

register_product(cpe: cpe, location: port + "/udp", port: port, proto: "udp");

log_message(data: build_detection_report(app: "Huawei iBMC" + mod_rep, version: version, install: port + "/udp",
                                         cpe: cpe),
            port: port, proto: "udp");

exit(0);
