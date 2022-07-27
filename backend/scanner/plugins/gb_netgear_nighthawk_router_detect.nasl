###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netgear_nighthawk_router_detect.nasl 4738 2016-12-12 06:31:41Z ckuerste $
#
# NETGEAR Nighthawk Routers Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.106464");
  script_version("$Revision: 4738 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-12 07:31:41 +0100 (Mon, 12 Dec 2016) $");
  script_tag(name:"creation_date", value:"2016-12-12 11:02:51 +0700 (Mon, 12 Dec 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("NETGEAR Nighthawk Routers Detection");

  script_tag(name:"summary", value:"Detection of NETGEAR Nighthawk Routers

  The script sends a connection request to the server and attempts to detect the presence of NETGEAR Nighthawk
Routers and to extract its firmware version");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 8443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 8443);

req = http_get(port: port, item: "/MNU_access_login_top.htm");
res = http_keepalive_send_recv(port: port, data: req);

if ('<img src="img/NewNetgeargenie.png"' >< res && "Firmware Version" >< res) {
  version = 'unknown';

  mod = eregmatch(pattern: 'description" content="(R[0-9]+)', string: res);
  if (isnull(mod[1]))
    exit(0);

  model = mod[1];
  set_kb_item(name: "netgear_nighthawk/model", value: model);
  set_kb_item(name: "netgear_nighthawk/detected", value: TRUE);

  vers = eregmatch(pattern: "Firmware Version</b><br>V([0-9._]+)", string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "netgear_nighthawk/fw_version", value: version);
  }

  cpe = build_cpe(value: version, exp: "^([0-9._]+)", base: "cpe:/a:netgear:" + tolower(model) + ":");
  if (!cpe)
    cpe = 'cpe:/a:netgear:' + tolower(model);

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "NETGEAR " + model, version: version, install: "/", cpe: cpe,
                                           concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
