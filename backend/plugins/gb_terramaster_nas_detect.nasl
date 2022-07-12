###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_terramaster_nas_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# TerraMaster NAS Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.106840");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-05-31 11:35:51 +0700 (Wed, 31 May 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("TerraMaster NAS Detection");

  script_tag(name:"summary", value:"Detection of TerraMaster NAS.

The script sends a connection request to the server and attempts to detect TerraMaster NAS.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 8181);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.terra-master.com/html/en/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 8181);

res = http_get_cache(port: port, item: "/");

if ("<title>TerraMaster" >< res && 'name="minuser"' >< res && 'name="dataError"' >< res) {
  version = "unknown";

  set_kb_item(name: "terramaster_nas/detected", value: TRUE);

  cpe = 'cpe:/a:noontec:terramaster';

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "TerraMaster NAS", version: version, install: "/", cpe: cpe),
              port: port);
  exit(0);
}

exit(0);
