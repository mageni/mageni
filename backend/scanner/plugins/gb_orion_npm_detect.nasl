###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_orion_npm_detect.nasl 13748 2019-02-19 04:10:22Z ckuersteiner $
#
# SolarWinds Orion Network Performance Monitor Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Updated by : Antu Sanadi <santu@secpod.com> on 2011-09-15
#  Updated to detect for the sp versions
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.100940");
  script_version("$Revision: 13748 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-19 05:10:22 +0100 (Tue, 19 Feb 2019) $");
  script_tag(name:"creation_date", value:"2010-12-09 13:44:03 +0100 (Thu, 09 Dec 2010)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SolarWinds Orion Network Performance Monitor Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8787);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Checks for the presence of SolarWinds Orion Network Performance Monitor.");

  script_xref(name:"URL", value:"http://www.solarwinds.com/products/orion/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port(default:8787);

if (!can_host_asp(port:port))
  exit(0);

dir = "/Orion";
url = string(dir, "/Login.aspx");
buf = http_get_cache(item:url, port:port);

if (buf == NULL)
  exit(0);

if ("SolarWinds Platform" >< buf || "SolarWinds Orion" >< buf || "Orion Platform" >< buf) {
  version = "unknown";

  vers = eregmatch(string: buf, pattern: "(NPM|Network Performance Monitor) (v)?(([0-9.]+).?([A-Z0-9]+))",
                   icase:TRUE);

  if (!isnull(vers[3])) {
    set_kb_item(name: "solarwinds/orion/npm/http/" + port + "/version", value: vers[3]);
    set_kb_item(name: "solarwinds/orion/npm/http/" + port + "/concluded", value: vers[0]);
  }

  set_kb_item(name: "solarwinds/orion/npm/detected", value: TRUE);
  set_kb_item(name: "solarwinds/orion/npm/http/port", value: port);
  set_kb_item(name: "solarwinds/orion/npm/http/" + port + "/location", value: dir);
}

exit(0);
