###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_energy_management_detect.nasl 12251 2018-11-08 05:46:56Z ckuersteiner $
#
# Cisco Energy Management Suite Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.141665");
  script_version("$Revision: 12251 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-08 06:46:56 +0100 (Thu, 08 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-11-08 11:41:07 +0700 (Thu, 08 Nov 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco Energy Management Suite Detection");

  script_tag(name:"summary", value:"Detection of Cisco Energy Management Suite.

The script sends a connection request to the server and attempts to detect Cisco Energy Management Suite and to
extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.cisco.com/c/en_ca/products/switches/energy-management-technology/index.html");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 443);

res = http_get_cache(port: port, item: "/");

if ("<title>Cisco Energy Management</title>" >< res && "var JEM_FLAVOR" >< res) {
  version = "unknown";

  # var JEM_VERSION="5.2.0.47736";
  vers = eregmatch(pattern: 'JEM_VERSION="([0-9.]+)', string: res);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "cisco_energy_management/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:cisco:energy_management:");
  if (!cpe)
    cpe = 'cpe:/a:cisco:energy_management';

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Cisco Energy Management Suite", version: version, install: "/",
                                           cpe: cpe, concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
