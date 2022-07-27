###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_siemens_sinema_server_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Siemens SINEMA Server Detection
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106220");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-09-02 14:19:12 +0700 (Fri, 02 Sep 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Siemens SINEMA Server Detection");

  script_tag(name:"summary", value:"Detection of Siemens SINEMA Server

The script sends a connection request to the server and attempts to detect the presence of Siemens SINEMA Server
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

if ("<title>SINEMA Server" >< res && "sinema_DLS=") {
  version = "unknown";
  set_kb_item(name: "sinema_server/installed", value: TRUE);

  ver = eregmatch(pattern: "SINEMA Server V([0-9]+)", string: res);
  if (!isnull(ver[1])) {
    version = ver[1];
    set_kb_item(name: "sinema_server/version", value: version);
  }

  cpe = build_cpe(value: version, exp: "^([0-9]+)", base: "cpe:/a:siemens:sinema_server:");
  if (!cpe)
    cpe = 'cpe:/a:siemens:sinema_server';

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "Siemens SINEMA Server", version: version, install: "/",
                                           cpe: cpe, concluded: ver[0]),
              port: port);
  exit(0);
}

exit(0);
