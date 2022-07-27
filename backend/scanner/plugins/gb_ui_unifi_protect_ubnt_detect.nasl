# Copyright (C) 2020 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144406");
  script_version("2020-08-18T05:45:11+0000");
  script_tag(name:"last_modification", value:"2020-08-18 10:12:19 +0000 (Tue, 18 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-18 04:18:42 +0000 (Tue, 18 Aug 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("UniFi Protect Detection (UBNT)");

  script_tag(name:"summary", value:"UBNT (Ubiquiti Networks discovery protocol) based detection of Unifi Protect.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_ubnt_discovery_protocol_detect.nasl");
  script_mandatory_keys("ubnt_discovery_proto/firmware");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("misc_func.inc");

port = get_port_for_service(nodefault: TRUE, ipproto: "udp", proto: "ubnt_discovery");

if (!fw = get_kb_item("ubnt_discovery_proto/firmware"))
  exit(0);

# unifi-protect.arm64.v1.13.2.0.0.0
if (fw !~ "unifi-protect")
  exit(0);

version = "unknown";

set_kb_item(name: "ui/unifi_protect/detected", value: TRUE);

vers = eregmatch(pattern: "unifi-protect\.[^.]+\.v([0-9.]+)", string: fw);
if (!isnull(vers[1]))
  version = vers[1];

cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:ui:unifi_protect:");
if (!cpe)
  cpe = "cpe:/a:ui:unifi_protect";

register_product(cpe: cpe, location: "/", port: port, service: "ubnt_discovery");

log_message(data: build_detection_report(app: "UniFi Protect", version: version, install: "/", cpe: cpe,
                                         concluded: fw),
            port: port, proto: "udp");

exit(0);
