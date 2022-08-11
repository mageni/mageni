# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.143516");
  script_version("2020-02-14T08:35:48+0000");
  script_tag(name:"last_modification", value:"2020-02-14 09:43:33 +0000 (Fri, 14 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-14 05:45:30 +0000 (Fri, 14 Feb 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Unraid OS Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of Unraid OS.

  The script sends a connection request to the server and attempts to detect Unraid OS and to extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://unraid.net/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

res = http_get_cache(port: port, item: "/login");

if (res =~ "unraid" && "/webGui/images/" >< res && ('placeholder="Username"' >< res || "unRAIDServer.plg" >< res)) {
  version = "unknown";

  url = "/Main";
  res = http_get_cache(port: port, item: url);

  # Version: 6.6.6&nbsp;<a href='#' title='View Release Notes'
  # Version<br/>Uptime</span> <span class="text-right">Tower &bullet; 192.168.20.54<br/>Media server<br/>6.5.2&nbsp;<a href='#' title='View Release Notes'
  vers = eregmatch(pattern: "Version.*([0-9]+\.[0-9]+\.[0-9]+)&nbsp;<a href='#' title='View Release Notes'", string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    concUrl = report_vuln_url(port: port, url: url, url_only: TRUE);
  }

  url = "/Settings";
  if (http_vuln_check(port: port, url: url, pattern: '"PanelText">Date and Time',
                      extra_check: '"PanelText">Disk Settings', check_header: TRUE)) {
    set_kb_item(name: "unraid/http/" + port + "/noauth", value: TRUE);
    set_kb_item(name: "unraid/http/" + port + "/noauth/checkedUrl", value: report_vuln_url(port: port, url: url, url_only: TRUE));
  }

  set_kb_item(name: "unraid/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/o:unraid:unraid:");
  if (!cpe)
    cpe = "cpe:/o:unraid:unraid";

  register_and_report_os(os: "Unraid OS", cpe: cpe, desc: "Unraid OS Detection (HTTP)", runs_key: "unixoide");

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Unraid", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0], concludedUrl: concUrl),
              port: port);
  exit(0);
}

exit(0);
