# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.141959");
  script_version("2022-08-16T10:48:20+0000");
  script_tag(name:"last_modification", value:"2022-08-16 10:48:20 +0000 (Tue, 16 Aug 2022)");
  script_tag(name:"creation_date", value:"2019-02-05 11:56:48 +0700 (Tue, 05 Feb 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Rundeck Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Rundeck.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.rundeck.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

url = "/user/login";

res = http_get_cache(port: port, item: url);
if (!res || res !~ "^HTTP/1\.[01] 200")
  exit(0);

detection_patterns = make_list(
  #    <title>
  #
  # Rundeck - Login</title>
  #
  # nb:
  # - Split over three lines, seen on 2.x/3.x/4.x
  # - It seems the login title is theme-able
  "Rundeck - Login</title>",
  #    <div class="copyright pull-left">
  #        &copy; Copyright 2022 <a href="http://rundeck.com">Rundeck, Inc.</a>
  #
  #        All rights reserved.
  #    </div>
  'Copyright [0-9]+ <a href="https?://([a-z]+\\.)?rundeck\\.(org|com)">Rundeck, Inc\\.</a>',
  # <img src="/static/images/rundeck-full-logo-black.png" alt="Rundeck" style="height: 20px; width: auto;"/>
  # <img src="/assets/logos/rundeck-logo-black-abcdefg" alt="Rundeck" style="width: 200px;"/>
  # <img src="/assets/static/img/rundeck-combination-abcdefg.svg" alt="Rundeck" style="width: 200px;" onload="SVGInject(this)"/>
  '^\\s*<img src="/(assets|static)/[^"]+" alt="Rundeck" style="[^>]+>',
  # See version examples below
  '^\\s*<a href="https?://([a-z]+\\.)?rundeck\\.(org|com)/.+utm_source=rundeckapp'
);

found = 0;
concluded = ""; # nb: To make openvas-nasl-lint happy...

foreach pattern (detection_patterns) {

  concl = egrep(string:res, pattern:pattern, icase:FALSE);
  if (concl) {

    found++;

    if (concluded)
      concluded += '\n';

    # nb: Minor formatting change for the reporting.
    concl = chomp(concl);
    concl = ereg_replace(string: concl, pattern: "^(\s+)", replace:"");
    concluded += "  " + concl;
  }
}

if (found > 0) {
  version = "unknown";

  # data-version-string="2.10.6-1"
  # data-version-string="2.11.1-1"
  vers = eregmatch(pattern: 'data-version-string="([0-9.-]+)"', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    concluded += '\n  ' + vers[0];
  } else {
    # <a href="http://rundeck.org/3.2.3?utm_source=rundeckapp&amp;utm_medium=3.2.3-20200221%20Linux%20java%201.8.0_181&amp;utm_campaign=helplink&amp;utm_content=user%2Flogin" class="help ">
    # <a href="https://docs.rundeck.com/4.4.0/manual/02-getting-help.html?utm_source=rundeckapp&amp;utm_medium=4.4.0-20220714%20Linux%20java%201.8.0_342&amp;utm_campaign=helplink&amp;utm_content=user%2Flogin" class="help " target="_blank">
    # <a href="http://rundeck.org/2.11.1?utm_source=rundeckapp&amp;utm_medium=2.11.1%20Linux%20java%201.8.0_171&amp;utm_campaign=helplink&amp;utm_content=user%2Flogin" class="help ">
    vers = eregmatch(pattern: '<a href="https?://([a-z]+\\.)?rundeck\\.(org|com)/([0-9.]{3,})(\\?|/)', string: res);
    if(!isnull(vers[3])) {
      version = vers[3];
      concluded += '\n  ' + vers[0];
    }
  }

  conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

  set_kb_item(name: "rundeck/detected", value: TRUE);
  set_kb_item(name: "rundeck/http/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.-]+)", base: "cpe:/a:rundeck:rundeck:");
  if (!cpe)
    cpe = "cpe:/a:rundeck:rundeck";

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Rundeck", version: version, install: "/", cpe: cpe,
                                           concluded: concluded, concludedUrl: conclUrl),
              port: port);
  exit(0);
}

exit(0);
