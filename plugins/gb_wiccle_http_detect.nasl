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
  script_oid("1.3.6.1.4.1.25623.1.0.146230");
  script_version("2021-07-06T11:53:06+0000");
  script_tag(name:"last_modification", value:"2021-07-06 11:53:06 +0000 (Tue, 06 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-06 09:48:08 +0000 (Tue, 06 Jul 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Wiccle Web Builder Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Wiccle Web Builder.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");
include("cpe.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/", "/wwb", "/iwiccle", http_cgi_dirs(port: port))) {
  install = dir;

  if (dir == "/")
    dir = "";

  res1 = http_get_cache(port: port, item: dir + "/index.php");
  url2 = dir + "/index.php?module=site&show=home";
  res2 = http_get_cache(port: port, item: url2);

  if ('title="Wiccle Site News' >< res1 || res1 =~ "Powered by[^>]+>Wiccle" ||
      "Powered by Wiccle - Wiccle Web Builder" >< res2 || ">Powered by Wiccle<" >< res2) {
    version = "unknown";

    set_kb_item(name: "wiccle/detected", value: TRUE);
    set_kb_item(name: "wiccle/http/detected", value: TRUE);

    # <h2>Welcome to Wiccle Web Builder 1.0!</h2>
    # nb: Only seen on older installations at res2.
    vers = eregmatch(pattern: ">Welcome to Wiccle Web Builder ([0-9.]+)", string: res2);
    if (!isnull(vers[1])) {
      version = vers[1];
      concUrl = http_report_vuln_url(port: port, url: url2, url_only: TRUE);
    }

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:wiccle:wiccle_web_builder:");
    if (!cpe)
      cpe = "cpe:/a:wiccle:wiccle_web_builder";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "Wiccle Web Builder", version: version, install: install,
                                             concluded: vers[0], concludedUrl: concUrl, cpe: cpe),
                port: port);
    exit(0);
  }
}

exit(0);