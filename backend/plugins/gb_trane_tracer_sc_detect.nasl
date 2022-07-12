###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_trane_tracer_sc_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Trane Tracer SC Devices Detection
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106272");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-09-20 16:39:00 +0700 (Tue, 20 Sep 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Trane Tracer SC Devices Detection");

  script_tag(name:"summary", value:"Detection of Trane Tracer SC Devices

Tries to detect Trane Tracer SC devices over the BACnet protocol.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_bacnet_detect.nasl");
  script_mandatory_keys("bacnet/vendor", "bacnet/model_name");

  script_xref(name:"URL", value:"https://www.trane.com/commercial/north-america/us/en/controls/building-Management/tracer-sc.html");


  exit(0);
}

include("cpe.inc");
include("host_details.inc");

vendor = get_kb_item("bacnet/vendor");
if (!vendor || "Trane" >!< vendor)
  exit(0);

model = get_kb_item("bacnet/model_name");
if (!model || model !~ "Tracer SC")
  exit(0);

sw_version = "unknown";

version = get_kb_item("bacnet/application_sw");
ver = eregmatch(pattern: "v([0-9.]+)", string: version);
if (!isnull(ver[1])) {
  sw_version = ver[1];
  set_kb_item(name: "trane_tracer/sw_version", value: sw_version);
}

set_kb_item(name: "trane_tracer/detected", value: TRUE);

cpe = build_cpe(value: sw_version, exp: "^([0-9.]+)", base: "cpe:/a:trane:tracer_sc:");
if (!cpe)
  cpe = 'cpe:/a:trane:tracer_sc';

register_product(cpe: cpe, port: 47808, service: "bacnet", proto: "udp");

log_message(data: build_detection_report(app: "Trane Tracer SC", version: sw_version, install: "47808/udp",
                                         cpe: cpe, concluded: version),
            port: 47808, proto: "udp");

exit(0);
