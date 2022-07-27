###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_trango_devices_detect.nasl 10911 2018-08-10 15:16:34Z cfischer $
#
# Trango Systems Devices Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.106387");
  script_version("$Revision: 10911 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:16:34 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-11-14 16:34:55 +0700 (Mon, 14 Nov 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Trango Systems Devices Detection");

  script_tag(name:"summary", value:"Detection of Trango Systems Devices

  The script sends a connection request to the server and attempts to detect the presence of Trango Systems
Devices and to extract its version.");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.trangosys.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

res = http_get_cache(port: port, item: "/");

if ("WWW-Authenticate: Basic realm=" >< res && res =~ "(TrangoLINK|(Apex Lynx)|(Giga Lynx)|(Giga Orion)|(StrataLink))") {
  version = "unknown";

  mod = eregmatch(pattern: "TrangoLINK(-| )([a-zA-Z]+)", string: res);
  if (!isnull(mod[2]))
    model = mod[2];
  else if (res =~ "Apex Lynx")
    model = "Apex Lynx";
  else if (res =~ "Giga Lynx")
    model = "Giga Lynx";
  else if (res =~ "Giga Orion")
    model = "Giga Orion";
  else if (res =~ "StrataLink")
    model = "StrataLink";
  else
    exit(0);

  vers = eregmatch(pattern: model + "( [0-9]+)? v([0-9.]+)", string: res);
  if (!isnull(vers[2])) {
    version = vers[2];
    set_kb_item(name: "trangosystems/version", value: version);
  }

  set_kb_item(name: "trangosystems/detected", value: TRUE);
  set_kb_item(name: "trangosystems/model", value: model);

  cpemod = tolower(str_replace(string: model, find: " ", replace: ""));
  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:trango:" + cpemod + ":");
  if (!cpe)
    cpe = "cpe:/a:trango:" + cpemod;

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "Trango Systems " + model, version: version, install: "/",
                                           cpe: cpe, concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
