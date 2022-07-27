###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_quest_kace_sma_detect.nasl 10911 2018-08-10 15:16:34Z cfischer $
#
# Quest KACE Systems Management Applicance (SMA) Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.141135");
  script_version("$Revision: 10911 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:16:34 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-06-01 10:51:22 +0700 (Fri, 01 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Quest KACE Systems Management Applicance (SMA) Detection");

  script_tag(name:"summary", value:"Detection of Quest KACE Systems Management Applicance (SMA).

The script sends a connection request to the server and attempts to detect Quest KACE Systems Management
Applicance (SMA) and to extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("KACE-Appliance/banner");
  script_require_ports("Services/www", 80, 443);

  script_xref(name:"URL", value:"https://www.quest.com/kace/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");


port = get_http_port(default: 443);

banner = get_http_banner(port: port);

if (banner !~ "X-(Dell)?KACE-Appliance")
  exit(0);

mod = eregmatch(pattern: "X-(Dell)?KACE-Appliance: ((k|K)[0-9]+)", string: banner);
if (!isnull(mod[2])) {
  model = mod[2];
  set_kb_item(name: "quest_kace_sma/model", value: model);
}

vers = eregmatch(pattern: "X-(Dell)?KACE-Version: ([0-9.]+)", string: banner);
if (!isnull(vers[2]))
  version = vers[2];

set_kb_item(name: "quest_kace_sma/detected", value: TRUE);

cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:quest:kace_systems_management_appliance:");
if (!cpe)
  cpe = 'cpe:/a:quest:kace_systems_management_appliance';

register_product(cpe: cpe, location: "/", port: port, service: "www");

log_message(data: build_detection_report(app: "Quest KACE Systems Management Appliance " + model, version: version,
                                         install: "/", cpe: cpe, concluded: vers[0]),
            port: port);

exit(0);
