###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_network_automation_detect.nasl 4652 2016-12-01 10:17:24Z ckuerste $
#
# HP Network Automation Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.106329");
  script_version("$Revision: 4652 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-01 11:17:24 +0100 (Thu, 01 Dec 2016) $");
  script_tag(name:"creation_date", value:"2016-12-01 11:00:37 +0700 (Thu, 01 Dec 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("HP Network Automation Detection");

  script_tag(name:"summary", value:"Detection of HP Network Automation

  The script sends a connection request to the server and attempts to detect the presence of HP Network Automation
and to extract its version");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 443);

res = http_get_cache(port: port, item: "/");

if ("<title>HP Network Automation" >< res && "HP Network Automation Log In Help" >< res) {
  version = 'unknown';

  vers = eregmatch(pattern: "HP Network Automation ([0-9.]+): Login", string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "hp/network_automation/version", value: version);
  }

  set_kb_item(name: "hp/network_automation/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:hp:network_automation:");
  if (!cpe)
    cpe = 'cpe:/a:hp:network_automation';

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "HP Network Automation", version: version, install: "/",
                                           cpe: cpe, concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
