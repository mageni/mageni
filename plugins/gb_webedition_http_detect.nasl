# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147973");
  script_version("2022-04-12T11:11:12+0000");
  script_tag(name:"last_modification", value:"2022-04-13 10:28:29 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-04-12 09:16:39 +0000 (Tue, 12 Apr 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("webEdition CMS Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of webEdition CMS.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.webedition.org/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/", "/webedition", "/webEdition", http_cgi_dirs(port: port))) {
  install = dir;

  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/index.php");
  if (!res || res !~ "^HTTP/1\.[01] 200")
    continue;

  if ('content="webEdition"' >< res || "<title>webEdition</title>" >< res) {
    version = "unknown";

    set_kb_item(name: "webedition/detected", value: TRUE);
    set_kb_item(name: "webedition/http/detected", value: TRUE);

    cpe = "cpe:/a:webedition:webedition_cms";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "webEdition CMS", version: version, install: install,
                                             cpe: cpe),
                port: port);
    exit(0);
  }
}

exit(0);
