# Copyright (C) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.902061");
  script_version("2022-03-02T09:47:18+0000");
  script_tag(name:"last_modification", value:"2022-03-02 11:03:54 +0000 (Wed, 02 Mar 2022)");
  script_tag(name:"creation_date", value:"2010-06-01 15:40:11 +0200 (Tue, 01 Jun 2010)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("DataTrack System Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 81);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of DataTrack System.");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 81);

res = http_get_cache(port: port, item: "/");

if (!concluded = egrep(string: res, pattern: "(>DataTrack Web Client<|^Server\s*:\s*MagnoWare)", icase: TRUE))
  exit(0);

version = "unknown";

vers = eregmatch(pattern: "Server\s*:\s*MagnoWare/([0-9.]+)", string: res, icase: TRUE);
if (!isnull(vers[1]))
  version = vers[1];

set_kb_item(name: "datatrack_system/detected", value: TRUE);
set_kb_item(name: "datatrack_system/http/detected", value: TRUE);

cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:magnoware:datatrack_system:");
if (!cpe)
  cpe = "cpe:/a:magnoware:datatrack_system";

register_product(cpe: cpe, location: "/", port: port, service: "www");

log_message(data: build_detection_report(app: "DataTrack System", version: version, install: "/",
                                         cpe: cpe, concluded: concluded),
            port: port);

exit(0);
