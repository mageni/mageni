# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.106378");
  script_version("2021-10-19T05:42:00+0000");
  script_tag(name:"last_modification", value:"2021-10-19 10:35:24 +0000 (Tue, 19 Oct 2021)");
  script_tag(name:"creation_date", value:"2016-11-07 12:46:37 +0700 (Mon, 07 Nov 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Tuleap Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Tuleap.");

  script_xref(name:"URL", value:"https://www.tuleap.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

url = "/";
res = http_get_cache(port: port, item: url);

if ("<title>Welcome - Tuleap" >!< res || "/account/login.php" >!< res) {
  url = "/account/login.php";
  res = http_get_cache(port: port, item: url);

  if ("<title>Tuleap login" >!< res || "var tuleap = tuleap" >!< res)
    exit(0);
}

version = "unknown";
install = "/";
concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

vers = eregmatch(pattern: "</a> version (([0-9]+\.)+[0-9]+)", string: res);
if (isnull(vers[1])) {
  url = "/soap/index.php/";

  res = http_get_cache(port: port, item: url);
  # rel="noreferrer">Tuleap&trade;</a> version 8.18.99.78.</li>
  vers = eregmatch(pattern: ">Tuleap[^>]+> version (([0-9]+\.)+[0-9]+)", string: res);
}

if (!isnull(vers[1])) {
  version = vers[1];
  concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
}

set_kb_item(name: "tuleap/detected", value: TRUE);
set_kb_item(name: "tuleap/http/detected", value: TRUE);

cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:enalean:tuleap:");
if (!cpe)
  cpe = "cpe:/a:enalean:tuleap";

register_product(cpe: cpe, location: install, port: port, service: "www");

log_message(data: build_detection_report(app: "Tuleap", version: version, install: install, cpe: cpe,
                                         concluded: vers[0], concludedUrl: concUrl),
            port: port);
exit(0);
