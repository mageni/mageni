# Copyright (C) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.902046");
  script_version("2021-10-08T12:48:53+0000");
  script_tag(name:"last_modification", value:"2021-10-11 11:42:12 +0000 (Mon, 11 Oct 2021)");
  script_tag(name:"creation_date", value:"2010-04-30 15:20:35 +0200 (Fri, 30 Apr 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Atlassian JIRA Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Atlassian JIRA.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.atlassian.com/software/jira");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default: 8080);

foreach dir (make_list_unique("/jira", http_cgi_dirs(port: port))) {

  install = dir;
  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/login.jsp");

  # Atlassian JIRA
  # or:
  # Atlassian Jira
  # so a case insensitive =~ is used here
  if(res =~ "Atlassian JIRA" && "/secure/Dashboard.jspa" >< res) {
    version = "unknown";
    vers = eregmatch(pattern: '<meta name="ajs-version-number" content="([0-9.]+)">', string:res);
    if (!isnull(vers[1])) {
      version = vers[1];
    } else {
      # <span id="footer-build-information" class="smallgreyfooter" >(v4.4.3#663-r165197)</span>
      # <span id="footer-build-information">(v8.9.0#809000-<span title='4ceb90abd8e813f4565a1705e597aeab0a82fc50'
      vers = eregmatch(pattern: '"footer-build-information"[^v]+v([0-9.]+)', string: res);
      if (!isnull(vers[1]))
        version = vers[1];
    }

    set_kb_item(name: "atlassian/jira/detected", value: TRUE);
    set_kb_item(name: "atlassian/jira/http/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:atlassian:jira:");
    if (!cpe)
      cpe = "cpe:/a:atlassian:jira";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "Atlassian JIRA", version: version, install: install,
                                             cpe: cpe, concluded: vers[0]),
                port: port);

    exit(0);
  }
}

exit(0);
