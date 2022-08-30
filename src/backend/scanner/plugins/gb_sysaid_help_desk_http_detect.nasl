# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.106004");
  script_version("2022-08-29T07:22:47+0000");
  script_tag(name:"last_modification", value:"2022-08-29 07:22:47 +0000 (Mon, 29 Aug 2022)");
  script_tag(name:"creation_date", value:"2015-06-11 10:02:43 +0700 (Thu, 11 Jun 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SysAid Help Desk Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of the SysAid Help Desk Software.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default: 8080);

foreach dir( make_list_unique( "/sysaid", http_cgi_dirs( port:port ) ) ) {
  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/Login.jsp";
  buf = http_get_cache(item: url, port: port);

  if (buf =~ "^HTTP/1\.[01] 200" && ("SysAid Help Desk" >< buf ||
                                 "Software del Servicio de asistencia de SysAid" >< buf ||
                                 'class="LookLikeLink"> by SysAid' >< buf)) {
    version = "unknown";

    url = dir + "/errorInSignUp.htm";
    req = http_get(port: port, item: url);
    buf = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

    vers = eregmatch(string: buf, pattern: "css/master\.css\?v([0-9.]+)", icase: TRUE);
    if (!isnull(vers[1])) {
      version = vers[1];
      concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
    }

    set_kb_item(name: "sysaid/detected", value: TRUE);
    set_kb_item(name: "sysaid/http/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:sysaid:sysaid:");
    if (!cpe)
      cpe = "cpe:/a:sysaid:sysaid";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "SysAid Help Desktop Software", version: version,
                                             install: install, cpe: cpe, concluded: vers[0], concludedUrl: concUrl),
                port: port);
  }
}

exit(0);
