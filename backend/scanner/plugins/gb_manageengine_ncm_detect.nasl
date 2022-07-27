###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manageengine_ncm_detect.nasl 10915 2018-08-10 15:50:57Z cfischer $
#
# ManageEngine Network Configuration Manager Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.140774");
  script_version("$Revision: 10915 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:50:57 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-02-15 15:59:46 +0700 (Thu, 15 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ManageEngine Network Configuration Manager Detection");

  script_tag(name:"summary", value:"Detection of ManageEngine Network Configuration Manager.

The script sends a connection request to the server and attempts to detect ManageEngine Network Configuration
Manager and to extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.manageengine.com/network-configuration-manager/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

res = http_get_cache(port: port, item: "/apiclient/ember/Login.jsp");

if ("Configuration Manager" >< res && "'info'>Network Configuration & Change Management Software" >< res) {
  version = "unknown";

  # Configuration Manager<span>v 12.0</span>
  # This is not that reliable since no build information available
  vers = eregmatch(pattern: "Configuration Manager<span>v ([0-9.]+)<", string: res);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "me_ncm/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:zohocorp:manageengine_network_configuration_manager:");
  if (!cpe)
    cpe = 'cpe:/a:zohocorp:manageengine_network_configuration_manager';

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "ManageEngine Network Configuration Manager", version: version,
                                           install: "/", cpe: cpe, concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
