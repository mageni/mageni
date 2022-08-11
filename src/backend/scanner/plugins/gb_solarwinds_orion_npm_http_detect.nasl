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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100940");
  script_version("2021-05-26T09:57:42+0000");
  script_tag(name:"last_modification", value:"2021-05-27 10:33:26 +0000 (Thu, 27 May 2021)");
  script_tag(name:"creation_date", value:"2010-12-09 13:44:03 +0100 (Thu, 09 Dec 2010)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SolarWinds Orion Network Performance Monitor (NPM) Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8787);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of the SolarWinds Orion Network Performance
  Monitor (NPM).");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default: 8787);

if (!http_can_host_asp(port: port))
  exit(0);

dir = "/Orion";
url = string(dir, "/Login.aspx");
buf = http_get_cache(item: url, port: port);
if (!buf)
  exit(0);

# nb: The first three patterns are a generic one for the Orion Platform so a separate pattern
# had to be added to avoid identify systems running the Orion Platform but not the NPM.
if (("SolarWinds Platform" >< buf || "SolarWinds Orion" >< buf || "Orion Platform" >< buf) &&
    buf =~ "(NPM|Network Performance Monitor)") {

  version = "unknown";

  vers = eregmatch(string: buf, pattern: "(NPM|Network Performance Monitor) v?(([0-9.]+).?([A-Z0-9]+))",
                   icase: TRUE);

  if (!isnull(vers[2])) {
    set_kb_item(name: "solarwinds/orion/npm/http/" + port + "/version", value: vers[2]);
    set_kb_item(name: "solarwinds/orion/npm/http/" + port + "/concluded", value: vers[0]);
  } else {
    # Orion Platform, IPAM, NCM, NPM, DPAIM, NTA, VMAN, UDT, SAM, Toolset: 2020.2.4
    vers = eregmatch(string: buf, pattern: "NPM[^:]+: ([0-9.]+)");
    if (!isnull(vers[1])) {
      set_kb_item(name: "solarwinds/orion/npm/http/" + port + "/version", value: vers[1]);
      set_kb_item(name: "solarwinds/orion/npm/http/" + port + "/concluded", value: vers[0]);
    }
  }

  set_kb_item(name: "solarwinds/orion/npm/detected", value: TRUE);
  set_kb_item(name: "solarwinds/orion/npm/http/port", value: port);
  set_kb_item(name: "solarwinds/orion/npm/http/" + port + "/location", value: dir);
}

exit(0);