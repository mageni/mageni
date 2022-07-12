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
  script_oid("1.3.6.1.4.1.25623.1.0.146181");
  script_version("2021-06-28T11:17:55+0000");
  script_tag(name:"last_modification", value:"2021-06-29 10:13:44 +0000 (Tue, 29 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-28 08:47:02 +0000 (Mon, 28 Jun 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Online Grades Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Online Grades.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://sourceforge.net/projects/onlinegrades/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/", "/grades", "/onlinegrades", http_cgi_dirs(port: port))) {
  install = dir;

  if (dir == "/")
    dir = "";

  url = dir + "/index.php";
  res = http_get_cache(port: port, item: url);
  if (!res || res !~ "HTTP/1\.[01] 200")
    continue;

  # <meta name="author" content="Online Grade Posting System -- http://www.onlinegrades.org" />
  # <meta name="keywords" content="Online Grades Version 3.2.5" />
  # <meta name="description" content="Online Grades for LCS - Online Grades" />
  # <a href="http://www.onlinegrades.org"><img src="http://www.liberty-patriots.org/grades/skins/lcs/images/og.png" width="94" height="50" border="0" alt="Powered by Online Grades"/></a>
  if (egrep(string: res, pattern: '" content="Online Grade(s Version|s for LCS| Posting System)', icase: FALSE) ||
      'alt="Powered by Online Grades"/>' >< res) {
    version = "unknown";

    # content="Online Grades Version 3.2.5"
    # Online Grades Version:
    # 3.2.5
    vers = eregmatch(pattern: "Online Grades Version(:)?\s*([0-9.]+)", string: res);
    if (!isnull(vers[2]))
      version = vers[2];

    set_kb_item(name: "online_grades/detected", value: TRUE);
    set_kb_item(name: "online_grades/http/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:onlinegrades:online_grades:");
    if (!cpe)
      cpe = "cpe:/a:onlinegrades:online_grades";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "Online Grades", version: version, install: install,
                                             cpe: cpe, concluded: vers[0]),
                port: port);
    exit(0);
  }
}

exit(0);
