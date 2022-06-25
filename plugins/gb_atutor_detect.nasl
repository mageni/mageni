###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_atutor_detect.nasl 13462 2019-02-05 09:37:54Z ckuersteiner $
#
# ATutor Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.141967");
  script_version("$Revision: 13462 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-05 10:37:54 +0100 (Tue, 05 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-02-05 15:18:21 +0700 (Tue, 05 Feb 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ATutor Detection");

  script_tag(name:"summary", value:"Detection of ATutor.

The script sends a connection request to the server and attempts to detect ATutor.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://atutor.github.io/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

if (!can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/ATutor", "/atutor", cgi_dirs(port: port))) {
  install = dir;

  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/login.php");

  if ("ATutor<" >< res && "ATutor.course.theme" >< res) {
    version = "unknown";

    set_kb_item(name: "atutor/detected", value: TRUE);

    cpe = "cpe:/a:atutor:atutor";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "ATutor", version: version, install: install, cpe: cpe),
                port: port);
  }
}

exit(0);
