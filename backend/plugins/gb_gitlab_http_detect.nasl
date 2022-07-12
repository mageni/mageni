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
  script_oid("1.3.6.1.4.1.25623.1.0.147116");
  script_version("2021-11-09T09:38:50+0000");
  script_tag(name:"last_modification", value:"2021-11-09 09:38:50 +0000 (Tue, 09 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-08 06:33:54 +0000 (Mon, 08 Nov 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("GitLab Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of GitLab.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://about.gitlab.com/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

url = "/users/sign_in";

res = http_get_cache(port: port, item: url);
if (!res || res !~ "^HTTP/1\.[01] 200")
  exit(0);

detection_patterns = make_list(
  'content="GitLab"',
  ">About GitLab<",
  "gon\.gitlab_url",
  "<title>Sign in [^ ]+ GitLab</title>", # nb: The dot is U+00B7
  "https://about\.gitlab\.com/");

found = 0;
concluded = ""; # nb: To make openvas-nasl-lint happy...

foreach pattern (detection_patterns) {

  # nb: Don't use egrep() because it can't handle the U+00B7 mentioned above.
  concl = eregmatch(string: res, pattern: pattern, icase: FALSE);
  if (concl[0]) {

    found++;

    if (concluded)
      concluded += '\n';
    concluded += "  " + concl[0];
  }
}

if (found > 1) {
  version = "unknown";

  # content="GitLab Enterprise Edition"
  # content="GitLab Community Edition"
  ed = eregmatch(pattern: 'content="GitLab ([^ ]+ Edition)"', string: res);
  if (!isnull(ed[1])) {
    edition = ed[1];
    concluded += '\n  ' + ed[0];
  }

  set_kb_item(name: "gitlab/detected", value: TRUE);
  set_kb_item(name: "gitlab/http/detected", value: TRUE);

  concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

  os_register_and_report(os: "Linux/Unix", cpe: "cpe:/o:linux:kernel",
                         desc: "GitLab Detection (HTTP)", runs_key: "unixoide");

  cpe = "cpe:/a:gitlab:gitlab";

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "GitLab " + edition, version: version, install: "/",
                                           cpe: cpe, concluded: concluded, concludedUrl: concUrl),
              port: port);
  exit(0);
}

exit(0);