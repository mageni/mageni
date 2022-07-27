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
  script_oid("1.3.6.1.4.1.25623.1.0.147358");
  script_version("2021-12-20T09:12:36+0000");
  script_tag(name:"last_modification", value:"2021-12-20 09:12:36 +0000 (Mon, 20 Dec 2021)");
  script_tag(name:"creation_date", value:"2021-12-20 06:40:20 +0000 (Mon, 20 Dec 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Apache JSPWiki Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Apache JSPWiki.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://jspwiki.apache.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

foreach dir (make_list_unique("/", "/JSPWiki", "/wiki", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/";
  res = http_get_cache(port: port, item: url);

  if ("JSPWiki" >< res && "PageIndex" >< res && res =~ '"wiki-?version"') {
    version = "unknown";

    # <div class="wikiversion"> JSPWiki v2.6.3 </div>
    # <div class="wiki-version">JSPWiki v2.11.0-M8</div>
    vers = eregmatch(pattern: '"wiki-?version">\\s*JSPWiki v([0-9A-Z.-]+)', string: res);
    if (!isnull(vers[1]))
      version = vers[1];

    set_kb_item(name: "apache/jspwiki/detected", value: TRUE);
    set_kb_item(name: "apache/jspwiki/http/detected", value: TRUE);

    concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

    cpe = build_cpe(value: tolower(version), exp: "^([0-9a-z.-]+)", base: "cpe:/a:apache:jspwiki:");
    if (!cpe)
      cpe = "cpe:/a:apache:jspwiki";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "Apache JSPWiki", version: version, install: install,
                                             cpe: cpe, concluded: vers[0], concludedUrl: concUrl),
                port: port);
    exit(0);
  }
}

exit(0);
