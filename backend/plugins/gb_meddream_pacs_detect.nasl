###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_meddream_pacs_detect.nasl 11354 2018-09-12 10:03:30Z ckuersteiner $
#
# MedDream PACS Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.141472");
  script_version("$Revision: 11354 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-12 12:03:30 +0200 (Wed, 12 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-09-12 16:07:21 +0700 (Wed, 12 Sep 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("MedDream PACS Detection");

  script_tag(name:"summary", value:"Detection of MedDream PACS Server.

The script sends a connection request to the server and attempts to detect MedDream PACS Server.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.softneta.com/products/meddream-pacs-server/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

if (!can_host_php(port: port))
  exit(0);

res = http_get_cache(port: port, item: "/pacs/login.php");

if ("Not authorized to access this URL" >< res && "loginSplash" >< res) {
  version = "unknown";

  set_kb_item(name: "meddream_pacs/detected", value: TRUE);

  cpe = 'cpe:/a:softneta:meddreams_pacs';

  register_product(cpe: cpe, location: "/pacs", port: port);

  log_message(data: build_detection_report(app: "MedDream PACS", version: version, install: "/pacs", cpe: cpe),
              port: port);
  exit(0);
}

exit(0);
