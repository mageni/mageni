# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.145996");
  script_version("2021-05-21T07:42:49+0000");
  script_tag(name:"last_modification", value:"2021-05-21 10:13:40 +0000 (Fri, 21 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-21 05:17:42 +0000 (Fri, 21 May 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Apache Tapestry Framework Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Apache Tapestry Framework.");

  script_xref(name:"URL", value:"https://tapestry.apache.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

foreach dir (make_list_unique("/", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/");
  if (res =~ "^HTTP/1\.[01] 30[0-9]") {
    if (!loc = http_extract_location_from_redirect(port: port, data: res, current_dir: "/"))
      continue;
    else
      res = http_get_cache(port: port, item: loc);
  }

  if ('content="Apache Tapestry Framework' >< res) {
    version = "unknown";

    # <meta content="Apache Tapestry Framework (version 5.3.8)"
    vers = eregmatch(pattern: 'content="Apache Tapestry Framework \\(version ([0-9.]+)\\)"', string: res);
    if (!isnull(vers[1]))
      version = vers[1];

    set_kb_item(name: "apache/tapestry/detected", value: TRUE);
    set_kb_item(name: "apache/tapestry/http/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:apache:tapestry:");
    if (!cpe)
      cpe = "cpe:/a:apache:tapestry";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "Apache Tapestry Framework", version: version, cpe: cpe,
                                             install: install, concluded: vers[0]),
                port: port);
  }
}

exit(0);
