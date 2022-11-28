# Copyright (C) 2011 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103086");
  script_version("2022-11-25T10:01:30+0000");
  script_tag(name:"last_modification", value:"2022-11-25 10:01:30 +0000 (Fri, 25 Nov 2022)");
  script_tag(name:"creation_date", value:"2011-02-22 13:26:53 +0100 (Tue, 22 Feb 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Batavi Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Batavi.");

  script_xref(name:"URL", value:"http://www.batavi.org");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

foreach dir (make_list_unique("/", "/batavi", "/shop", http_cgi_dirs(port: port))) {
  install = dir;

  if (dir == "/")
    dir = "";

  url = dir + "/admin/index.php?login";

  res = http_get_cache(port: port, item: url);

  if (egrep(pattern: "Batavi Administration", string: res, icase: TRUE) || 'content="Batavi' >< res ||
      res =~ "X-Powered-By\s*:\s*Batavi e-commerce") {
    version = "unknown";

    # Powered By</span><span class="Batavi">Batavi 1.4.1<
    vers = eregmatch(string: res, pattern: "Powered By.*Batavi ([0-9.]+)<", icase: TRUE);
    if (isnull(vers[1]))
      # content="Batavi 1.4.1"
      vers = eregmatch(pattern: 'content="Batavi ([0-9.]+)"', string: res);

    if (!isnull(vers[1])) {
      version = vers[1];
      concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
    }

    set_kb_item(name: "batavi/detected", value: TRUE);
    set_kb_item(name: "batavi/http/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:batavi:batavi:");
    if (!cpe)
      cpe = "cpe:/a:batavi:batavi";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "Batavi", version: version, install: install, cpe: cpe,
                                             concluded: vers[0], concludedUrl: concUrl),
                port: port);
    exit(0);
  }
}

exit(0);
