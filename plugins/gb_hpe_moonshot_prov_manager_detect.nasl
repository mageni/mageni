###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hpe_moonshot_prov_manager_detect.nasl 12555 2018-11-28 10:30:02Z ckuersteiner $
#
# HPE Moonshot Provision Manager Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.141728");
  script_version("$Revision: 12555 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-28 11:30:02 +0100 (Wed, 28 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-11-28 15:05:29 +0700 (Wed, 28 Nov 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("HPE Moonshot Provision Manager Detection");

  script_tag(name:"summary", value:"Detection of HPE Moonshot Provision Manager.

The script sends a connection request to the server and attempts to detect HPE Moonshot Provision Manager.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.hpe.com");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 443);

res = http_get_cache(port: port, item: "/index.html");

if ("<title>Moonshot Provisioning</title>" >< res && "UserLoginPage()" >< res) {
  version = "unknown";

  set_kb_item(name: "ibm_moonshot_provision_manager/detected", value: TRUE);

  cpe = 'cpe:/a:hp:moonshot_provisioning_manager_appliance';

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "HPE Moonshot Privision Manager", version: version, install: "/",
                                           cpe: cpe),
              port: port);
  exit(0);
}

exit(0);
