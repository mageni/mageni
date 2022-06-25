###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_open_audit_detect.nasl 11499 2018-09-20 10:38:00Z ckuersteiner $
#
# Opmantek Open-AudIT Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.141024");
  script_version("$Revision: 11499 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-20 12:38:00 +0200 (Thu, 20 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-04-25 14:59:28 +0700 (Wed, 25 Apr 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Opmantek Open-AudIT Detection");

  script_tag(name:"summary", value:"Detection of Opmantek Open-AudIT.

The script sends a connection request to the server and attempts to detect Opmantek Open-AudIT and to extract its
version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443, 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://opmantek.com/network-discovery-inventory-software/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

url = '/omk/oae/login';

res = http_get_cache(port: port, item: url);

if ("<title>Opmantek</title>" >< res && res =~"Open-AudIT (Community|Enterprise|Professional)?") {
  version = "unknown";

  vers = eregmatch(pattern: "Open-AudIT( Community| Enterprise| Professional)? ([0-9.]+)", string: res);
  if (!isnull(vers[2])) {
    version = vers[2];
    concUrl = url;
  }

  set_kb_item(name: "open-audit/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:opmantek:open-audit:");
  if (!cpe)
    cpe = 'cpe:/a:opmantek:open-audit';

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "Opmantec Open-AudIT", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0], concludedUrl: concUrl),
              port: port);
  exit(0);
}

exit(0);
